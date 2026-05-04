"""
Core DNS scanning functionality.

Author: Mojtaba Akhbari
"""

import asyncio
import os
import time
import uuid
import json
import signal
from collections import deque
from datetime import timedelta

try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

import dns.asyncresolver
import dns.exception


class ScanState:
    def __init__(self):
        self.start_time = time.perf_counter()
        self.total_ips = 0
        self.domain = ""
        self.scanned = 0
        self.success = 0
        self.timeouts = 0
        self.errors = 0
        self.fastest_ips = []
        self.logs = deque(maxlen=30)
        self.stop_event = asyncio.Event()
        self.results = []
        self.failed_results = []


def get_safe_concurrency(requested):
    if os.name == "posix":
        try:
            import resource

            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            needed = requested + 100
            if needed > hard:
                safe_limit = hard - 100
                return max(1, safe_limit)
            elif needed > soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (needed, hard))
        except Exception:
            pass
    return requested


async def dns_worker(queue, timeout, domain, port, record, tunnel, state):
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.port = port

    while not state.stop_event.is_set():
        try:
            ip = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue

        if ip is None:
            queue.task_done()
            break

        try:
            resolver.nameservers = [ip]
            test_domain = domain
            if tunnel:
                random_prefix = uuid.uuid4().hex[: random.randint(10, 27)]
                test_domain = f"{random_prefix}.{domain}"
            start_req = time.perf_counter()
            answer = await asyncio.wait_for(
                resolver.resolve(test_domain, record.upper(), raise_on_no_answer=False),
                timeout=timeout + 0.7,
            )
            rcode = answer.response.rcode()
            if rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL):
                latency = (time.perf_counter() - start_req) * 1000.0

                state.success += 1
                state.results.append({"ip": ip, "latency_ms": round(latency, 2)})
                state.logs.append(
                    f"[green]** Success: {ip}:{port} - {latency:.2f}ms[/green]"
                )

                state.fastest_ips.append((latency, ip))
                state.fastest_ips.sort(key=lambda x: x[0])
                state.fastest_ips = state.fastest_ips[:10]
            else:
                state.errors += 1
                err_msg = f"Unexpected RCODE: {rcode}"
                state.logs.append(
                    f"[bold red]-- {test_domain} | Error: {ip}:{port} - {err_msg}[/bold red]"
                )
                state.failed_results.append({"ip": ip, "error": err_msg})
        except (asyncio.TimeoutError, dns.exception.Timeout):
            state.timeouts += 1
            state.logs.append(
                f"[yellow]-- {test_domain} | Timeout: {ip}:{port}[/yellow]"
            )
            state.failed_results.append({"ip": ip, "error": "Timeout"})

        except Exception as e:
            err_msg = str(e) if str(e) else type(e).__name__
            if "SERVFAIL" in err_msg:
                latency = (time.perf_counter() - start_req) * 1000.0

                state.success += 1
                state.results.append({"ip": ip, "latency_ms": round(latency, 2)})
                state.logs.append(
                    f"[green]** Success: {ip}:{port} - {latency:.2f}ms[/green]"
                )

                state.fastest_ips.append((latency, ip))
                state.fastest_ips.sort(key=lambda x: x[0])
                state.fastest_ips = state.fastest_ips[:10]
            else:
                state.errors += 1
                state.logs.append(
                    f"[bold red]-- Error: {ip}:{port} - {err_msg}[/bold red]"
                )
                state.failed_results.append({"ip": ip, "error": err_msg})

        finally:
            state.scanned += 1
            queue.task_done()


class DNSScanner:
    def __init__(self):
        self.state = ScanState()

    async def scan(self, args):
        from .ip_generator import IPGenerator

        self.state.domain = args.domain
        args.concurrency = get_safe_concurrency(args.concurrency)
        queue = asyncio.Queue(maxsize=args.concurrency * 2)

        ip_generator = IPGenerator()
        producer_task = asyncio.create_task(
            ip_generator.generate_ips(args, queue, self.state.stop_event)
        )

        workers = [
            asyncio.create_task(
                dns_worker(
                    queue,
                    args.timeout,
                    args.domain,
                    args.port,
                    args.record,
                    args.tunnel,
                    self.state,
                )
            )
            for _ in range(args.concurrency)
        ]

        try:
            await producer_task
            await asyncio.gather(*workers)
        finally:
            self.state.stop_event.set()

        return self.state.results, self.state.failed_results

    def save_results(self, results, failed_results, args):
        if args.output and results:
            with open(args.output, "w") as f:
                for res in results:
                    f.write(f"{res['ip']}\n")

        if args.json and results:
            with open(args.json, "w") as f:
                json.dump(results, f, indent=4)

        if failed_results:
            import time

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            fails_file = f"fails_dns_resolver_{timestamp}.txt"
            with open(fails_file, "w") as f:
                for res in failed_results:
                    f.write(f"IP: {res['ip']} | Error: {res['error']}\n")

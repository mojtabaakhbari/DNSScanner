import asyncio
import argparse
import ipaddress
import random
import time
import sys
import json
import uuid
import os
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

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.console import Console

LEAKED_SUBNETS = [
    "78.157.32.0/19", "78.157.32.0/24", "78.157.34.0/24", "78.157.35.0/24",
    "78.157.36.0/24", "78.157.37.0/24", "78.157.38.0/24", "78.157.39.0/24",
    "78.157.40.0/24", "78.157.41.0/24", "78.157.42.0/24", "78.157.43.0/24",
    "78.157.44.0/24", "78.157.45.0/24", "78.157.46.0/24", "78.157.47.0/24",
    "78.157.48.0/24", "78.157.49.0/24", "78.157.50.0/24", "78.157.51.0/24",
    "78.157.52.0/24", "78.157.53.0/24", "78.157.54.0/23", "78.157.56.0/24",
    "78.157.57.0/24", "78.157.58.0/24", "78.157.59.0/24", "78.157.60.0/23",
    "78.157.62.0/24", "78.157.63.0/24", "95.38.45.0/24", "95.38.51.0/24",
    "95.38.54.0/23", "95.38.58.0/24", "95.38.61.0/24", "185.14.0.0/16",
    "185.136.133.0/24", "185.221.239.0/24", "185.221.0.0/16", "185.222.210.0/24",
    "87.248.159.0/24", "185.208.76.0/23", "185.208.76.0/24", "185.208.77.0/24",
    "2.188.0.0/16", "2.188.0.0/24", "2.188.1.0/24", "2.188.2.0/24", "2.188.3.0/24",
    "2.188.7.0/24", "2.188.8.0/24", "2.188.9.0/24", "2.188.12.0/24", "2.188.13.0/24",
    "2.188.14.0/24", "2.188.15.0/24", "2.188.17.0/24", "2.188.21.0/24",
    "2.188.22.0/24", "2.188.23.0/24", "2.188.26.0/23", "2.188.30.0/24",
    "2.188.76.0/24", "2.188.144.0/24", "2.188.179.0/24", "2.188.184.0/24",
    "2.188.185.0/24", "2.188.187.0/24", "2.189.0.0/16", "2.189.1.0/24",
    "2.189.3.0/24", "2.189.4.0/24", "2.189.44.0/24", "2.189.48.0/23",
    "2.189.50.0/23", "2.189.52.0/23", "2.189.69.0/24", "2.189.190.0/23",
    "78.38.0.0/16", "78.38.242.0/24", "78.39.0.0/16", "80.191.0.0/16",
    "80.191.81.0/24", "85.185.0.0/16", "85.185.45.0/24", "89.251.10.0/24",
    "104.167.26.0/23", "185.188.16.0/24", "195.146.37.0/24", "195.146.63.0/24",
    "217.218.0.0/16", "217.218.67.0/24", "217.218.104.0/24", "217.218.105.0/24",
    "217.219.0.0/16"
]

CUSTOM_FIRST_OCTETS = (
        [2, 5, 10, 12, 31, 37, 45, 46, 62, 77, 78, 79, 80, 81, 82, 83] +
        list(range(84, 96)) +
        list(range(102, 110)) +
        [128, 130, 134, 138, 146, 151, 157, 158, 159, 164, 168, 171, 
         176, 178, 185, 188, 192, 193, 194, 195, 212, 213, 217]
    )

CUSTOM_FIRST_AND_SECOND_OCTETS = [
    "2.188", "2.189", "78.38", "78.39", "78.157", "80.191", "85.185", "87.248",
    "89.251", "95.38", "104.167", "185.136", "185.188", "185.208", "185.221",
    "185.222", "195.146", "217.218", "217.219"
]

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

state = ScanState()

def get_heuristic_host_octet():
    """
    Biases the random generation of the last IP octet towards 
    numbers statistically more likely to host infrastructure/DNS.
    """
    roll = random.random()
    if roll < 0.25:
        return random.choice([1, 2, 5, 8, 9, 10, 53, 100, 253, 254])
    elif roll < 0.50:
        return random.randint(3, 30)
    elif roll < 0.60:
        return random.choice([64, 65, 128, 129, 192, 193])
    else:
        return random.randint(31, 252)

def get_heuristic_mid_octet():
    """
    Biases 2nd and 3rd octets towards common ISP subnet boundaries 
    and low-numbered VLANs, drastically reducing time wasted on unrouted space.
    """
    roll = random.random()
    if roll < 0.20:
        return random.choice([0, 8, 16, 32, 64, 128, 192, 224])
    elif roll < 0.35:
        return random.randint(1, 20)
    elif roll < 0.50:
        return random.choice([253, 254, 255])
    else:
        return random.randint(0, 255)

def get_safe_concurrency(requested):
    if os.name == 'posix':
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            needed = requested + 100
            if needed > hard:
                safe_limit = hard - 100
                state.logs.append(f"[yellow]Concurrency reduced to {safe_limit} to fit OS limits.[/yellow]")
                return max(1, safe_limit)
            elif needed > soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (needed, hard))
        except Exception:
            pass
    return requested

def is_public(ip_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.is_global and not ip.is_multicast and not ip.is_unspecified
    except:
        return False

def generate_random_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, (2**32) - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)

def generate_custom_octet_ip():
    """For --cf: 1st is STRICT. 2nd/3rd are smartly guessed. 4th targets infrastructure."""
    first = random.choice(CUSTOM_FIRST_OCTETS)
    second = get_heuristic_mid_octet()
    third = get_heuristic_mid_octet()
    fourth = get_heuristic_host_octet()
    return f"{first}.{second}.{third}.{fourth}"

def generate_lite_custom_ip():
    """For --cl: 1st & 2nd are STRICT. 3rd is smartly guessed. 4th targets infrastructure."""
    prefix = random.choice(CUSTOM_FIRST_AND_SECOND_OCTETS)
    third = get_heuristic_mid_octet()
    fourth = get_heuristic_host_octet()
    return f"{prefix}.{third}.{fourth}"

def get_networks_from_file(filename, nearby):
    networks = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if '/' in line:
                    networks.append(ipaddress.IPv4Network(line, strict=False))
                else:
                    ip = ipaddress.IPv4Address(line)
                    if nearby:
                        net = ipaddress.IPv4Network(f"{line}/24", strict=False)
                        networks.append(net)
                    else:
                        networks.append(ipaddress.IPv4Network(f"{line}/32", strict=False))
            except ValueError:
                pass
    return networks

async def dns_producer(queue, args):
    async def safe_put(item):
        while not state.stop_event.is_set():
            try:
                await asyncio.wait_for(queue.put(item), timeout=0.5)
                return True
            except asyncio.TimeoutError:
                continue
        return False

    try:
        if args.random:
            for _ in range(args.random):
                if not await safe_put(generate_random_public_ip()): break
                
        elif args.cf:
            for _ in range(args.cf):
                if not await safe_put(generate_custom_octet_ip()): break

        elif args.cl:
            for _ in range(args.cl):
                if not await safe_put(generate_lite_custom_ip()): break
                
        elif args.al or args.ls:
            networks = [ipaddress.IPv4Network(n, strict=False) for n in LEAKED_SUBNETS]
            if args.ls:
                for _ in range(args.ls):
                    net = random.choice(networks)
                    ip = ipaddress.IPv4Address(random.randint(int(net.network_address), int(net.broadcast_address)))
                    if not await safe_put(str(ip)): break
            else:
                for net in networks:
                    for ip in net:
                        if not await safe_put(str(ip)): break
                        
        elif args.file:
            networks = get_networks_from_file(args.file, args.nearby)
            for net in networks:
                for ip in net:
                    if not await safe_put(str(ip)): break
                    
    except Exception as e:
        state.logs.append(f"[red]Producer Error: {e}[/red]")
    finally:
        for _ in range(args.concurrency):
            if not await safe_put(None): break

async def dns_worker(queue, timeout, domain, port, record, tunnel):
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
            	random_prefix = uuid.uuid4().hex[:random.randint(10,27)] 
            	test_domain = f"{random_prefix}.{domain}"
            start_req = time.perf_counter()
            answer = await asyncio.wait_for(
                resolver.resolve(test_domain, record.upper(), raise_on_no_answer=False),
                timeout=timeout + 0.7
            )
            rcode = answer.response.rcode()
            if rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL):
                latency = (time.perf_counter() - start_req) * 1000.0
                
                state.success += 1
                state.results.append({"ip": ip, "latency_ms": round(latency, 2)})
                state.logs.append(f"[green]** Success: {ip}:{port} - {latency:.2f}ms[/green]")
                
                state.fastest_ips.append((latency, ip))
                state.fastest_ips.sort(key=lambda x: x[0])
                state.fastest_ips = state.fastest_ips[:10]
            else:
                state.errors += 1
                err_msg = f"Unexpected RCODE: {rcode}"
                state.logs.append(f"[bold red]-- {test_domain} | Error: {ip}:{port} - {err_msg}[/bold red]")
                state.failed_results.append({"ip": ip, "error": err_msg})
        except (asyncio.TimeoutError, dns.exception.Timeout):
            state.timeouts += 1
            state.logs.append(f"[yellow]-- {test_domain} | Timeout: {ip}:{port}[/yellow]")
            state.failed_results.append({"ip": ip, "error": "Timeout"})
            
        except Exception as e:
            err_msg = str(e) if str(e) else type(e).__name__
            if "SERVFAIL" in err_msg:
                latency = (time.perf_counter() - start_req) * 1000.0
                
                state.success += 1
                state.results.append({"ip": ip, "latency_ms": round(latency, 2)})
                state.logs.append(f"[green]** Success: {ip}:{port} - {latency:.2f}ms[/green]")
                
                state.fastest_ips.append((latency, ip))
                state.fastest_ips.sort(key=lambda x: x[0])
                state.fastest_ips = state.fastest_ips[:10]
            else:
                state.errors += 1
                state.logs.append(f"[bold red]-- Error: {ip}:{port} - {err_msg}[/bold red]")
                state.failed_results.append({"ip": ip, "error": err_msg})
            
        finally:
            state.scanned += 1
            queue.task_done()

def format_elapsed(seconds):
    td = timedelta(seconds=int(seconds))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days:02d}:{hours:02d}:{minutes:02d}:{seconds:02d}"

def generate_ui(args):
    layout = Layout(name="root")
    layout.split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2)
    )
    layout["left"].split_column(
        Layout(name="stats", ratio=3),
        Layout(name="fastest", ratio=3),
        Layout(name="settings", ratio=2)
    )

    elapsed = format_elapsed(time.perf_counter() - state.start_time)
    
    if state.total_ips > 0:
        percent = (state.scanned / state.total_ips) * 100.0
    else:
        percent = 0.0

    stats_text = (
        f"Elapsed Time: [cyan]{elapsed}[/cyan]\n"
        f"Domain: [yellow]{state.domain}[/yellow]\n"
        f"Target Total IPs: [magenta]{state.total_ips}[/magenta]\n"
        f"Total Scanned: [blue]{state.scanned}[/blue] ({percent:.2f}%)\n"
        f"Success: [green]{state.success}[/green]\n"
        f"Timeouts: [yellow]{state.timeouts}[/yellow]\n"
        f"Other Errors: [red]{state.errors}[/red]"
    )
    layout["left"]["stats"].update(Panel(stats_text, title="Statistics", border_style="blue"))

    fastest_text = "\n".join([f"{i+1:<2}. [green]{ip:<15}[/green] ({lat:.2f}ms)" for i, (lat, ip) in enumerate(state.fastest_ips)])
    if not fastest_text: 
        if state.stop_event.is_set() or state.scanned >= state.total_ips:
            fastest_text = "Not found"
        else:
            fastest_text = "No results yet..."
            
    layout["left"]["fastest"].update(Panel(fastest_text, title="Top 10 Fastest Responders", border_style="cyan"))

    settings_text = (
        f"Concurrency: {args.concurrency}\n"
        f"Timeout:     {args.timeout} seconds\n"
        f"Target:      {args.target_desc}\n"
        f"Record Type: {args.record.upper()}\n"
        f"Fake Tunnel: {args.tunnel}"
    )
    layout["left"]["settings"].update(Panel(settings_text, title="Settings", border_style="magenta"))

    logs_text = Text.from_markup("\n".join(state.logs))
    layout["right"].update(Panel(logs_text, title="Event Log (Live)", border_style="green"))

    return layout

async def ui_updater(args, live):
    while not state.stop_event.is_set():
        live.update(generate_ui(args))
        await asyncio.sleep(0.2)
    live.update(generate_ui(args))

async def main():
    parser = argparse.ArgumentParser(description="Advanced Asynchronous DNS Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-d", "--domain", type=str, default="google.com", help="Domain to query (A record)")
    parser.add_argument("-p", "--port", type=int, default=53, help="Target UDP port (default: 53)")
    parser.add_argument("--record", type=str, default="A", help="Record type for DNS (default: A)")
    
    group.add_argument('-r', '--random', dest='random', type=int, metavar='N', help='Scan N random public IPs')
    group.add_argument('--cf', '--custom-full', dest='cf', type=int, metavar='N', help='Scan N random IR IPs FULL using custom first octet list')
    group.add_argument('--cl', '--custom-lite', dest='cl', type=int, metavar='N', help='Scan N random IR IPs using Lite custom list (1st & 2nd octets)')
    group.add_argument('--ls', '--leaked-subnets', dest='ls', type=int, metavar='N', help='Scan N random IPs from leaked subnets')
    group.add_argument('--al', '--all-leaked', dest='al', action='store_true', help='Scan all IPs in the leaked subnets')
    group.add_argument('-f', '--file', dest='file', type=str, metavar='FILE', help='Read targets from a file (IPs or CIDRs)')
    
    parser.add_argument('--nearby', action='store_true', help='Convert single IPs in file to /24 subnets')
    parser.add_argument('--tunnel', action='store_true', help='Simulate Tunneling with Encryption')
    parser.add_argument('--concurrency', type=int, default=200, help='Number of concurrent scan tasks')
    parser.add_argument('--timeout', type=float, default=5.0, help='Query timeout in seconds')
    parser.add_argument('-o', "--output", type=str, default="working_dns.txt", metavar='FILE', help='Save successful IPs to a simple text file')
    parser.add_argument('--json', type=str, required=False, metavar='FILE', help='Save structured results to a JSON file')
    
    args = parser.parse_args()
    if args.domain is not None:
        state.domain = args.domain
    if args.random is not None: 
        state.total_ips = args.random
        args.target_desc = f"{args.random} random public IPs"
    elif args.cf is not None: 
        state.total_ips = args.cf
        args.target_desc = f"{args.cf} random Full IR IPs (1st octet list)"
    elif args.cl is not None: 
        state.total_ips = args.cl
        args.target_desc = f"{args.cl} random IR IPs (Lite custom)"
    elif args.ls is not None: 
        state.total_ips = args.ls
        args.target_desc = f"{args.ls} random IPs from leaked subnets"
    elif args.al: 
        state.total_ips = sum(ipaddress.IPv4Network(n, strict=False).num_addresses for n in LEAKED_SUBNETS)
        args.target_desc = "Scan all leaked subnets"
    elif args.file: 
        networks = get_networks_from_file(args.file, args.nearby)
        state.total_ips = sum(net.num_addresses for net in networks)
        args.target_desc = f"File ({args.file})" + (" + nearby /24" if args.nearby else "")
        
    args.concurrency = get_safe_concurrency(args.concurrency)
    queue = asyncio.Queue(maxsize=args.concurrency * 2)

    producer_task = asyncio.create_task(dns_producer(queue, args))
    workers = [
        asyncio.create_task(dns_worker(queue, args.timeout, args.domain, args.port, args.record, args.tunnel)) 
        for _ in range(args.concurrency)
    ]

    console = Console()
    try:
        with Live(generate_ui(args), refresh_per_second=5, console=console) as live:
            ui_task = asyncio.create_task(ui_updater(args, live))
            await producer_task
            await asyncio.gather(*workers)
            state.stop_event.set()
            await ui_task
            
    except asyncio.CancelledError:
        pass
    finally:
        state.stop_event.set()
        
    print("\n")
    console.print("[bold cyan]Scan Process Finished. Processing results...[/bold cyan]")
    
    if args.output and state.results:
        with open(args.output, 'w') as f:
            for res in state.results:
                f.write(f"{res['ip']}\n")
        console.print(f"[bold green]Saved {len(state.results)} successful IPs to {args.output}[/bold green]")
        
    if args.json and state.results:
        with open(args.json, 'w') as f:
            json.dump(state.results, f, indent=4)
        console.print(f"[bold green]Saved structured results to {args.json}[/bold green]")
    if state.failed_results:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        fails_file = f"fails_dns_resolver_{timestamp}.txt"
        with open(fails_file, 'w') as f:
            for res in state.failed_results:
                f.write(f"IP: {res['ip']} | Error: {res['error']}\n")
        console.print(f"[bold red]Saved {len(state.failed_results)} failed IPs to {fails_file}[/bold red]")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def shutdown_handler():
        state.logs.append("\n\n[bold red]Stop signal (Ctrl+C) received. Shutting down gracefully...[/bold red]\n\n")
        state.stop_event.set()

    if os.name == 'posix':
        loop.add_signal_handler(signal.SIGINT, shutdown_handler)
        loop.add_signal_handler(signal.SIGTERM, shutdown_handler)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        shutdown_handler()
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    finally:
        loop.close()


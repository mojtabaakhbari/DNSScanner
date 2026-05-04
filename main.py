#!/usr/bin/env python3
"""
Advanced Asynchronous DNS Scanner - Main Entry Point

Author: Mojtaba Akhbari
"""

import asyncio
import argparse
import signal
import os

from dns_scanner import DNSScanner, ScanState
from dns_scanner.ui import UIManager
from dns_scanner.utils import calculate_target_ips, setup_signal_handlers


async def main():
    parser = argparse.ArgumentParser(description="Advanced Asynchronous DNS Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        default="google.com",
        help="Domain to query (A record)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=53, help="Target UDP port (default: 53)"
    )
    parser.add_argument(
        "--record", type=str, default="A", help="Record type for DNS (default: A)"
    )

    group.add_argument(
        "-r",
        "--random",
        dest="random",
        type=int,
        metavar="N",
        help="Scan N random public IPs",
    )
    group.add_argument(
        "--cf",
        "--custom-full",
        dest="cf",
        type=int,
        metavar="N",
        help="Scan N random IR IPs FULL using custom first octet list",
    )
    group.add_argument(
        "--cl",
        "--custom-lite",
        dest="cl",
        type=int,
        metavar="N",
        help="Scan N random IR IPs using Lite custom list (1st & 2nd octets)",
    )
    group.add_argument(
        "--ls",
        "--leaked-subnets",
        dest="ls",
        type=int,
        metavar="N",
        help="Scan N random IPs from leaked subnets",
    )
    group.add_argument(
        "--al",
        "--all-leaked",
        dest="al",
        action="store_true",
        help="Scan all IPs in the leaked subnets",
    )
    group.add_argument(
        "-f",
        "--file",
        dest="file",
        type=str,
        metavar="FILE",
        help="Read targets from a file (IPs or CIDRs)",
    )

    parser.add_argument(
        "--nearby",
        action="store_true",
        help="Convert single IPs in file to /24 subnets",
    )
    parser.add_argument(
        "--tunnel", action="store_true", help="Simulate Tunneling with Encryption"
    )
    parser.add_argument(
        "--concurrency", type=int, default=200, help="Number of concurrent scan tasks"
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Query timeout in seconds"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="working_dns.txt",
        metavar="FILE",
        help="Save successful IPs to a simple text file",
    )
    parser.add_argument(
        "--json",
        type=str,
        required=False,
        metavar="FILE",
        help="Save structured results to a JSON file",
    )

    args = parser.parse_args()

    total_ips, target_desc = calculate_target_ips(args)
    args.target_desc = target_desc

    scanner = DNSScanner()
    scanner.state.total_ips = total_ips
    scanner.state.domain = args.domain

    ui = UIManager(scanner.state)

    loop = asyncio.get_event_loop()
    setup_signal_handlers(loop, scanner.state)

    try:

        async def run_scan():
            scan_task = asyncio.create_task(scanner.scan(args))
            ui_task = asyncio.create_task(ui.run_live_display(args))

            await scan_task
            scanner.state.stop_event.set()
            await ui_task

            results, failed_results = (
                scanner.state.results,
                scanner.state.failed_results,
            )
            scanner.save_results(results, failed_results, args)
            ui.print_final_results(results, failed_results, args)

        await run_scan()

    except asyncio.CancelledError:
        pass
    finally:
        scanner.state.stop_event.set()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    finally:
        loop.close()

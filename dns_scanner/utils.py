"""
Utility functions for DNS Scanner.

Author: Mojtaba Akhbari
"""

import ipaddress
import signal
from .config import LEAKED_SUBNETS


def calculate_target_ips(args):
    if args.random is not None:
        total_ips = args.random
        target_desc = f"{args.random} random public IPs"
    elif args.cf is not None:
        total_ips = args.cf
        target_desc = f"{args.cf} random Full IR IPs (1st octet list)"
    elif args.cl is not None:
        total_ips = args.cl
        target_desc = f"{args.cl} random IR IPs (Lite custom)"
    elif args.ls is not None:
        total_ips = args.ls
        target_desc = f"{args.ls} random IPs from leaked subnets"
    elif args.al:
        total_ips = sum(
            ipaddress.IPv4Network(n, strict=False).num_addresses for n in LEAKED_SUBNETS
        )
        target_desc = "Scan all leaked subnets"
    elif args.file:
        from .ip_generator import get_networks_from_file

        networks = get_networks_from_file(args.file, args.nearby)
        total_ips = sum(net.num_addresses for net in networks)
        target_desc = f"File ({args.file})" + (" + nearby /24" if args.nearby else "")
    else:
        total_ips = 0
        target_desc = "Unknown"

    return total_ips, target_desc


def setup_signal_handlers(loop, state):
    import os

    def shutdown_handler():
        state.logs.append(
            "\n\n[bold red]Stop signal (Ctrl+C) received. Shutting down gracefully...[/bold red]\n\n"
        )
        state.stop_event.set()

    if os.name == "posix":
        loop.add_signal_handler(signal.SIGINT, shutdown_handler)
        loop.add_signal_handler(signal.SIGTERM, shutdown_handler)

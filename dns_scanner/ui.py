"""
User interface components for DNS Scanner.

Author: Mojtaba Akhbari
"""

import asyncio
import time
from datetime import timedelta

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.console import Console


def format_elapsed(seconds):
    td = timedelta(seconds=int(seconds))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days:02d}:{hours:02d}:{minutes:02d}:{seconds:02d}"


class UIManager:
    def __init__(self, state):
        self.state = state
        self.console = Console()

    def generate_ui(self, args):
        layout = Layout(name="root")
        layout.split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=2))
        layout["left"].split_column(
            Layout(name="stats", ratio=3),
            Layout(name="fastest", ratio=3),
            Layout(name="settings", ratio=2),
        )

        elapsed = format_elapsed(time.perf_counter() - self.state.start_time)

        if self.state.total_ips > 0:
            percent = (self.state.scanned / self.state.total_ips) * 100.0
        else:
            percent = 0.0

        stats_text = (
            f"Elapsed Time: [cyan]{elapsed}[/cyan]\n"
            f"Domain: [yellow]{self.state.domain}[/yellow]\n"
            f"Target Total IPs: [magenta]{self.state.total_ips}[/magenta]\n"
            f"Total Scanned: [blue]{self.state.scanned}[/blue] ({percent:.2f}%)\n"
            f"Success: [green]{self.state.success}[/green]\n"
            f"Timeouts: [yellow]{self.state.timeouts}[/yellow]\n"
            f"Other Errors: [red]{self.state.errors}[/red]"
        )
        layout["left"]["stats"].update(
            Panel(stats_text, title="Statistics", border_style="blue")
        )

        fastest_text = "\n".join(
            [
                f"{i+1:<2}. [green]{ip:<15}[/green] ({lat:.2f}ms)"
                for i, (lat, ip) in enumerate(self.state.fastest_ips)
            ]
        )
        if not fastest_text:
            if (
                self.state.stop_event.is_set()
                or self.state.scanned >= self.state.total_ips
            ):
                fastest_text = "Not found"
            else:
                fastest_text = "No results yet..."

        layout["left"]["fastest"].update(
            Panel(fastest_text, title="Top 10 Fastest Responders", border_style="cyan")
        )

        settings_text = (
            f"Concurrency: {args.concurrency}\n"
            f"Timeout:     {args.timeout} seconds\n"
            f"Target:      {args.target_desc}\n"
            f"Record Type: {args.record.upper()}\n"
            f"Fake Tunnel: {args.tunnel}"
        )
        layout["left"]["settings"].update(
            Panel(settings_text, title="Settings", border_style="magenta")
        )

        logs_text = Text.from_markup("\n".join(self.state.logs))
        layout["right"].update(
            Panel(logs_text, title="Event Log (Live)", border_style="green")
        )

        return layout

    async def run_live_display(self, args):
        with Live(
            self.generate_ui(args), refresh_per_second=5, console=self.console
        ) as live:
            while not self.state.stop_event.is_set():
                live.update(self.generate_ui(args))
                await asyncio.sleep(0.2)
            live.update(self.generate_ui(args))

    def print_final_results(self, results, failed_results, args):
        print("\n")
        self.console.print(
            "[bold cyan]Scan Process Finished. Processing results...[/bold cyan]"
        )

        if args.output and results:
            self.console.print(
                f"[bold green]Saved {len(results)} successful IPs to {args.output}[/bold green]"
            )

        if args.json and results:
            self.console.print(
                f"[bold green]Saved structured results to {args.json}[/bold green]"
            )
        if failed_results:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            fails_file = f"fails_dns_resolver_{timestamp}.txt"
            self.console.print(
                f"[bold red]Saved {len(failed_results)} failed IPs to {fails_file}[/bold red]"
            )

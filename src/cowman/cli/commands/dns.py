"""Implementation of 'cowman dns' command."""

import time
from typing import Optional
import typer

from cowman.cli.ui.console import console, print_warning
from cowman.cli.ui.formatters import format_dns_table
from cowman.network.dns_sniffer import DnsMonitor
from cowman.security.engine import get_security_engine
from cowman.storage.database import init_db
from cowman.storage.repository import DnsLogRepository
from cowman.utils.platform import get_privilege_hint, is_admin

app = typer.Typer(help="Inspect and capture live DNS queries and anomalies.")


def run_dns(
    interface: Optional[str] = None,
    live: bool = False,
    limit: int = 50,
    anomalous_only: bool = False,
) -> None:
    """Execute DNS log retrieval or live sniffer."""
    init_db()

    if live:
        if not is_admin():
            print_warning("Running live packet capture without elevated privileges.")
            console.print(get_privilege_hint("DNS packet sniffing"))

        console.print("[bold cyan]Starting live DNS sniffer (Press Ctrl+C to stop)...[/bold cyan]")
        sniffer = DnsMonitor(interface=interface)
        engine = get_security_engine()
        sniffer.start()

        try:
            while True:
                time.sleep(1.0)
                events = sniffer.get_events()
                for ev in events:
                    engine.process_dns_event(ev)
                    flag = "[bold red]ANOMALOUS[/bold red]" if ev.is_anomalous else "[dim green]NORMAL[/dim green]"
                    console.print(
                        f"[dim]{ev.timestamp.strftime('%H:%M:%S')}[/dim] "
                        f"[cyan]{ev.query_type:<5}[/cyan] "
                        f"[bold white]{ev.query_name}[/bold white] "
                        f"from [dim cyan]{ev.source_ip}[/dim cyan] {flag}"
                    )
        except KeyboardInterrupt:
            sniffer.stop()
            console.print("\n[dim cyan]Live DNS sniffer terminated.[/dim cyan]")
    else:
        # Retrieve recent DNS query history from database
        queries = DnsLogRepository.get_logs(limit=limit, anomalous_only=anomalous_only)
        if not queries:
            console.print(
                "[yellow]No DNS records found in database. Run with '--live' to capture live packets, "
                "or run network discovery to generate activity.[/yellow]"
            )
            return
        console.print(format_dns_table(queries))


@app.callback(invoke_without_command=True)
def dns(
    live: bool = typer.Option(False, "--live", "-l", help="Start real-time packet capture on port 53"),
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum DNS records to display"),
    anomalous_only: bool = typer.Option(False, "--anomalous-only", "-a", help="Filter for only anomalous / high entropy queries"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Interface name for live sniffing"),
):
    """Monitor live or historical DNS query activity, detecting domain generation algorithms and tunneling."""
    run_dns(interface=interface, live=live, limit=limit, anomalous_only=anomalous_only)

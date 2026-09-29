"""Implementation of 'cowman discover' command."""

import asyncio
from typing import Optional
import typer
from rich.status import Status

from cowman.cli.ui.console import console
from cowman.cli.ui.formatters import format_devices_table
from cowman.core.models import Device
from cowman.network.scanner import NetworkScanner
from cowman.security.engine import get_security_engine
from cowman.storage.database import init_db
from cowman.storage.repository import DeviceRepository

app = typer.Typer(help="Discover and audit devices on authorized local subnets.")


def run_discover(interface: Optional[str] = None, target_cidr: Optional[str] = None) -> None:
    """Execute authorized network discovery and update inventory."""
    init_db()
    scanner = NetworkScanner(interface=interface, target_cidr=target_cidr)
    engine = get_security_engine()

    with console.status("[bold cyan]Scanning authorized network...[/bold cyan]", spinner="dots") as status:
        def _update_status(msg: str):
            status.update(f"[bold cyan]{msg}[/bold cyan]")

        devices = asyncio.run(scanner.discover(progress_callback=_update_status))

    if not devices:
        console.print("[yellow]No active devices found in the target subnet.[/yellow]")
        return

    console.print(format_devices_table(devices))
    console.print(f"[dim]Discovered [bold cyan]{len(devices)}[/bold cyan] active hosts on the authorized subnet.[/dim]")


@app.callback(invoke_without_command=True)
def discover(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Specific interface name to scan from"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Authorized CIDR subnet override (e.g., 192.168.1.0/24)"),
):
    """Discover active devices on the local authorized subnet, resolving hostnames and MAC vendors."""
    run_discover(interface=interface, target_cidr=target)

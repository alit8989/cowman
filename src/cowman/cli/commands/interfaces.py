"""Implementation of 'cowman interfaces' command."""

import typer
from cowman.cli.ui.console import console
from cowman.cli.ui.formatters import format_interfaces_table
from cowman.network.interfaces import get_all_interfaces
from cowman.storage.database import init_db

app = typer.Typer(help="List all physical and virtual network interfaces.")


def run_interfaces() -> None:
    """Execute interfaces inspection."""
    init_db()
    interfaces = get_all_interfaces()
    if not interfaces:
        console.print("[yellow]No network interfaces detected on the host system.[/yellow]")
        return
    console.print(format_interfaces_table(interfaces))


@app.callback(invoke_without_command=True)
def interfaces():
    """List all hardware and virtual network interfaces with operational statistics."""
    run_interfaces()

"""Implementation of 'cowman topology' command."""

from typing import Optional
import typer
from rich.panel import Panel

from cowman.cli.ui.console import console
from cowman.network.topology import TopologyGenerator
from cowman.storage.database import init_db
from cowman.storage.repository import DeviceRepository

app = typer.Typer(help="Render dynamically generated network topology.")


def run_topology(mode: str = "both") -> None:
    """Execute dynamic network topology reconstruction."""
    init_db()
    devices = DeviceRepository.get_all(status_filter="ONLINE")
    root = TopologyGenerator.build_topology(devices)

    if mode in ("ascii", "both"):
        ascii_diagram = TopologyGenerator.render_ascii_diagram(root)
        console.print(
            Panel(
                ascii_diagram,
                title="[bold cyan]Dynamic Network Infrastructure Topology[/bold cyan]",
                border_style="bright_blue",
                padding=(1, 2),
            )
        )

    if mode in ("tree", "both"):
        rich_tree = TopologyGenerator.render_rich_tree(root)
        console.print(rich_tree)


@app.callback(invoke_without_command=True)
def topology(
    mode: str = typer.Option("both", "--mode", "-m", help="Display mode: 'ascii', 'tree', or 'both'"),
):
    """Generate dynamic terminal-friendly topology layout from live and discovered network entities."""
    run_topology(mode=mode)

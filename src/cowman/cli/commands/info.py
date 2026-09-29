"""Implementation of 'cowman info' command."""

import typer
from cowman.cli.ui.banners import render_soc_header_panel
from cowman.cli.ui.console import console
from cowman.cli.ui.formatters import format_overview_panel
from cowman.network.interfaces import get_system_network_overview
from cowman.storage.database import init_db

app = typer.Typer(help="Display network host telemetry and configuration.")


def run_info() -> None:
    """Execute network host telemetry display."""
    init_db()
    overview = get_system_network_overview()
    console.print(format_overview_panel(overview))


@app.callback(invoke_without_command=True)
def info():
    """Display comprehensive system network overview, gateway, and DNS configuration."""
    run_info()

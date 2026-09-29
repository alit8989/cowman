"""Main Typer CLI application combining all COWMAN commands and interactive dashboard."""

import sys
from typing import Optional
import typer

from cowman import __app_name__, __version__
from cowman.cli.commands import (
    discover,
    dns,
    events,
    info,
    interfaces,
    monitor,
    ports,
    replay,
    report,
    topology,
)
from cowman.cli.ui.console import console
from cowman.cli.ui.dashboard import launch_dashboard
from cowman.core.config import load_config
from cowman.core.logger import setup_logger
from cowman.utils.platform import get_os_name

app = typer.Typer(
    name=__app_name__,
    help="COWMAN - Terminal SOC & Network Security Command Center.",
    no_args_is_help=False,
    add_completion=False,
)

# Register all primary commands directly
app.command(name="info", help="Display comprehensive system network overview, gateway, and DNS configuration.")(info.info)
app.command(name="interfaces", help="List all hardware and virtual network interfaces with operational statistics.")(interfaces.interfaces)
app.command(name="discover", help="Discover active devices on the local authorized subnet, resolving hostnames and MAC vendors.")(discover.discover)
app.command(name="ports", help="Scan and identify exposed TCP services on an explicitly specified authorized host.")(ports.ports)
app.command(name="monitor", help="Monitor real-time network interface bandwidth, packet rates, and active socket connections.")(monitor.monitor)
app.command(name="dns", help="Monitor live or historical DNS query activity, detecting domain generation algorithms and tunneling.")(dns.dns)
app.command(name="topology", help="Generate dynamic terminal-friendly topology layout from live and discovered network entities.")(topology.topology)
app.command(name="events", help="Inspect and filter recorded defensive events, service modifications, and anomalies.")(events.events)
app.command(name="replay", help="Replay historical network events, anomalies, and transitions chronologically.")(replay.replay)
app.command(name="report", help="Generate and export comprehensive security posture, host inventory, and anomaly reports.")(report.report)


def version_callback(value: bool):
    if value:
        os_info = get_os_name()
        console.print(
            f"[bold bright_cyan]{__app_name__.upper()}[/bold bright_cyan] "
            f"version [bold green]{__version__}[/bold green] "
            f"({os_info} | Python {sys.version.split()[0]})"
        )
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show COWMAN version and environment info.",
        callback=version_callback,
        is_eager=True,
    ),
    config_file: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to custom TOML configuration file.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose DEBUG logging.",
    ),
):
    """COWMAN: Terminal Network Security Operations Command Center."""
    cfg = load_config(config_file)
    log_level = "DEBUG" if verbose else cfg.general.log_level
    setup_logger(level_name=log_level)

    # If no subcommand was supplied, launch the interactive SOC dashboard!
    if ctx.invoked_subcommand is None:
        launch_dashboard()

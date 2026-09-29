"""Implementation of 'cowman monitor' real-time traffic command."""

import asyncio
import time
from typing import Optional
import typer
from rich.live import Live

from cowman.cli.ui.console import console
from cowman.cli.ui.formatters import format_traffic_panel
from cowman.network.monitor import TrafficMonitor
from cowman.security.engine import get_security_engine
from cowman.storage.database import init_db

app = typer.Typer(help="Stream real-time network traffic, bandwidth, and connection telemetry.")


def run_monitor(
    interface: Optional[str] = None,
    interval: float = 1.0,
    duration: Optional[float] = None,
) -> None:
    """Run real-time traffic monitoring loop using Rich Live."""
    init_db()
    monitor = TrafficMonitor(interface=interface, interval=interval)
    engine = get_security_engine()

    t_start = time.time()
    try:
        # Initial sample
        initial_snap = monitor.sample()
        with Live(format_traffic_panel(initial_snap), console=console, refresh_per_second=2) as live:
            while True:
                time.sleep(interval)
                snap = monitor.sample()
                engine.process_traffic_snapshot(snap)
                live.update(format_traffic_panel(snap))

                if duration and (time.time() - t_start) >= duration:
                    break
    except KeyboardInterrupt:
        console.print("\n[dim cyan]Traffic monitor stopped.[/dim cyan]")


@app.callback(invoke_without_command=True)
def monitor(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Interface name to bind/monitor"),
    interval: float = typer.Option(1.0, "--interval", help="Sampling interval in seconds"),
    duration: Optional[float] = typer.Option(None, "--duration", "-d", help="Exit after N seconds (default: continuous)"),
):
    """Monitor real-time network interface bandwidth, packet rates, and active socket connections."""
    run_monitor(interface=interface, interval=interval, duration=duration)

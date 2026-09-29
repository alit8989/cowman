"""Implementation of 'cowman replay' chronological event stream command."""

import time
from typing import Optional
import typer

from cowman.cli.ui.console import console, print_error
from cowman.security.severity import Severity
from cowman.storage.database import init_db
from cowman.storage.repository import SecurityEventRepository
from cowman.utils.time import format_timestamp, parse_datetime_flexible

app = typer.Typer(help="Replay recorded security and network events in chronological order.")


def run_replay(
    from_time_str: Optional[str] = None,
    to_time_str: Optional[str] = None,
    speed: float = 0.0,
    limit: int = 100,
) -> None:
    """Execute chronological event replay."""
    init_db()

    start_dt = None
    end_dt = None

    try:
        if from_time_str:
            start_dt = parse_datetime_flexible(from_time_str)
        if to_time_str:
            end_dt = parse_datetime_flexible(to_time_str)
    except ValueError as e:
        print_error(str(e))
        return

    # Query events (ordered descending in repository, so reverse to replay chronologically)
    events = SecurityEventRepository.get_events(
        start_time=start_dt,
        end_time=end_dt,
        limit=limit,
    )

    if not events:
        console.print("[yellow]No historical events found within the specified time window to replay.[/yellow]")
        return

    events.reverse()  # Chronological order: oldest to newest

    console.print(f"[bold cyan]─── COWMAN EVENT REPLAY ({len(events)} events) ───[/bold cyan]")
    if start_dt or end_dt:
        t_range = f"Window: {format_timestamp(start_dt)} → {format_timestamp(end_dt)}"
        console.print(f"[dim]{t_range}[/dim]\n")

    for idx, e in enumerate(events):
        time_str = e.timestamp.strftime("%H:%M:%S")
        type_str = e.category.upper()
        # Derive clean event action name
        rule_short = e.rule_id.split("-")[-1] if "-" in e.rule_id else e.rule_id

        # Target or subject info
        target_info = e.target_ip or e.source_ip or ""
        desc_summary = e.title

        line = (
            f"[bold bright_white]{time_str}[/bold bright_white]  "
            f"{e.severity.badge:<20} "
            f"[bold cyan]{type_str:<12}[/bold cyan] "
            f"[white]{desc_summary:<32}[/white] "
            f"[dim]{target_info}[/dim]"
        )

        console.print(line)

        if speed > 0 and idx < len(events) - 1:
            delay = min(max(1.0 / speed, 0.05), 2.0)
            time.sleep(delay)

    console.print("\n[dim cyan]✔ Replay completed.[/dim cyan]")


@app.callback(invoke_without_command=True)
def replay(
    from_time: Optional[str] = typer.Option(None, "--from", "-f", help="Replay starting timestamp (e.g., '1h', '24h', '09:00:00')"),
    to_time: Optional[str] = typer.Option(None, "--to", "-t", help="Replay ending timestamp"),
    speed: float = typer.Option(0.0, "--speed", "-s", help="Playback speed multiplier (0 = instantaneous, 1.0 = pacing delay)"),
    limit: int = typer.Option(100, "--limit", "-n", help="Maximum historical events to replay"),
):
    """Replay historical network events, anomalies, and transitions chronologically."""
    run_replay(from_time_str=from_time, to_time_str=to_time, speed=speed, limit=limit)

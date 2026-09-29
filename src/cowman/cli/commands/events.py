"""Implementation of 'cowman events' command."""

from datetime import datetime
from typing import Optional
import typer

from cowman.cli.ui.console import console, print_error
from cowman.cli.ui.formatters import format_events_table
from cowman.security.severity import Severity
from cowman.storage.database import init_db
from cowman.storage.repository import SecurityEventRepository
from cowman.utils.time import parse_datetime_flexible

app = typer.Typer(help="Query and filter security audit and anomaly event logs.")


def run_events(
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    host: Optional[str] = None,
    from_time_str: Optional[str] = None,
    to_time_str: Optional[str] = None,
    limit: int = 50,
) -> None:
    """Execute security event log query."""
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

    events = SecurityEventRepository.get_events(
        severity=severity,
        event_type=event_type,
        host=host,
        start_time=start_dt,
        end_time=end_dt,
        limit=limit,
    )

    if not events:
        console.print("[dim cyan]No security events found matching the specified query criteria.[/dim cyan]")
        return

    console.print(format_events_table(events))

    # Print severity breakdown
    crit = sum(1 for e in events if e.severity == Severity.CRITICAL)
    high = sum(1 for e in events if e.severity == Severity.HIGH)
    med = sum(1 for e in events if e.severity == Severity.MEDIUM)
    low = sum(1 for e in events if e.severity == Severity.LOW)
    info_cnt = sum(1 for e in events if e.severity == Severity.INFO)

    console.print(
        f"[dim]Showing {len(events)} events | "
        f"[bold white on red] CRITICAL: {crit} [/bold white on red] "
        f"[bold orange1] HIGH: {high} [/bold orange1] "
        f"[yellow] MED: {med} [/yellow] "
        f"[blue] LOW: {low} [/blue] "
        f"[cyan] INFO: {info_cnt} [/cyan][/dim]"
    )


@app.callback(invoke_without_command=True)
def events(
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL"),
    event_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by category or rule name (e.g. DNS, SERVICE, DISCOVERY)"),
    host: Optional[str] = typer.Option(None, "--host", "-H", help="Filter by source IP, target IP, or hostname"),
    from_time: Optional[str] = typer.Option(None, "--from", help="Start time filter (e.g. '1h', '24h', '2026-09-30 12:00')"),
    to_time: Optional[str] = typer.Option(None, "--to", help="End time filter"),
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum records to return"),
):
    """Inspect and filter recorded defensive events, service modifications, and anomalies."""
    run_events(
        severity=severity,
        event_type=event_type,
        host=host,
        from_time_str=from_time,
        to_time_str=to_time,
        limit=limit,
    )

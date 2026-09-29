"""Implementation of 'cowman ports <host>' command."""

import asyncio
from typing import List, Optional
import typer
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from cowman.cli.ui.console import console, print_error
from cowman.cli.ui.formatters import format_ports_table
from cowman.network.ports import PortAnalyzer
from cowman.security.engine import get_security_engine
from cowman.storage.database import init_db


def parse_port_list(port_spec: Optional[str]) -> Optional[List[int]]:
    """Parse port arguments like '80,443,8080' or '20-25' into a list of integers."""
    if not port_spec:
        return None

    ports: List[int] = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start_p, end_p = map(int, part.split("-"))
                ports.extend(range(max(1, start_p), min(65535, end_p) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)

    return sorted(list(set(ports))) if ports else None


def run_ports(
    target: str,
    port_spec: Optional[str] = None,
    timeout: Optional[float] = None,
    concurrency: Optional[int] = None,
) -> None:
    """Execute authorized port scan and service analysis."""
    init_db()
    parsed_ports = parse_port_list(port_spec)
    analyzer = PortAnalyzer(
        target_host=target,
        ports=parsed_ports,
        timeout=timeout,
        concurrency=concurrency,
    )
    engine = get_security_engine()

    console.print(f"[bold cyan]Initiating authorized service audit on target:[/bold cyan] [white]{target}[/white]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {len(analyzer.ports)} ports...", total=len(analyzer.ports))

        def _update_progress(completed: int, total: int):
            progress.update(task, completed=completed)

        try:
            report = asyncio.run(analyzer.scan(progress_callback=_update_progress))
            progress.update(task, completed=len(analyzer.ports))
        except Exception as e:
            print_error(f"Port audit failed: {e}", hint="Verify the target host is reachable and DNS resolves.")
            return

    # Check for security events (unexpected services)
    engine.process_port_scan(report)

    console.print(format_ports_table(report))
    console.print(
        f"[dim]Scanned {report.scanned_ports_count} ports in {report.scan_duration_seconds:.2f}s. "
        f"Found [bold green]{len(report.open_ports)}[/bold green] open service(s).[/dim]"
    )


def ports(
    host: str = typer.Argument(..., help="Authorized target hostname or IP address to inspect"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Specific ports or ranges to check (e.g. '80,443,8000-8080')"),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="TCP connection timeout per port in seconds"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-c", help="Concurrent probe socket limit"),
):
    """Scan and identify exposed TCP services on an explicitly specified authorized host."""
    run_ports(target=host, port_spec=ports, timeout=timeout, concurrency=concurrency)

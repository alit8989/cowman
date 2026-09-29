"""Implementation of 'cowman report' export command."""

from pathlib import Path
from typing import Optional
import typer
from rich.panel import Panel
from rich.syntax import Syntax

from cowman.cli.ui.console import console, print_error, print_success
from cowman.network.interfaces import get_system_network_overview
from cowman.storage.database import init_db
from cowman.storage.repository import (
    DeviceRepository,
    DnsLogRepository,
    PortRepository,
    SecurityEventRepository,
)
from cowman.utils.export import ReportExporter

app = typer.Typer(help="Export comprehensive network and security audit reports.")


def run_report(
    output_format: str = "markdown",
    output_path: Optional[str] = None,
    limit: int = 100,
) -> None:
    """Execute report compilation and export."""
    init_db()
    fmt = output_format.lower().strip()

    overview = get_system_network_overview()
    devices = DeviceRepository.get_all()
    events = SecurityEventRepository.get_events(limit=limit)
    dns_logs = DnsLogRepository.get_logs(limit=limit)

    # Collect ports for discovered devices
    all_ports = []
    for d in devices:
        ports = PortRepository.get_open_ports_for_host(d.ip)
        all_ports.extend(ports)

    report_content: str = ""

    if fmt == "json":
        data = ReportExporter.build_report_data(
            overview=overview,
            devices=devices,
            events=events,
            ports=all_ports,
            dns_logs=dns_logs,
        )
        report_content = ReportExporter.to_json(data)
    elif fmt == "csv":
        report_content = ReportExporter.to_csv(devices=devices, events=events)
    elif fmt in ("markdown", "md"):
        report_content = ReportExporter.to_markdown(
            overview=overview,
            devices=devices,
            events=events,
            ports=all_ports,
            dns_logs=dns_logs,
        )
    else:
        print_error(f"Unsupported report format '{output_format}'. Choose 'markdown', 'json', or 'csv'.")
        return

    if output_path:
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(report_content, encoding="utf-8")
        print_success(f"Audit report successfully written to [bold cyan]{out_file}[/bold cyan] ({len(report_content)} bytes)")
    else:
        # Display formatted report to terminal
        syntax_lexer = "json" if fmt == "json" else ("markdown" if fmt in ("markdown", "md") else "text")
        syntax_view = Syntax(report_content, syntax_lexer, theme="monokai", line_numbers=False)
        console.print(
            Panel(
                syntax_view,
                title=f"[bold cyan]COWMAN Audit Report ({fmt.upper()})[/bold cyan]",
                border_style="bright_blue",
            )
        )
        console.print(f"[dim]Tip: To save directly to disk, use --output filename.{fmt}[/dim]")


@app.callback(invoke_without_command=True)
def report(
    format_opt: str = typer.Option("markdown", "--format", "-f", help="Output format: 'markdown', 'json', or 'csv'"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save the generated report"),
    limit: int = typer.Option(100, "--limit", "-n", help="Maximum records included in report sections"),
):
    """Generate and export comprehensive security posture, host inventory, and anomaly reports."""
    run_report(output_format=format_opt, output_path=output, limit=limit)

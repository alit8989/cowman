"""Rich table and view formatters for network, ports, events, and metrics."""

from typing import List, Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cowman.core.models import (
    Device,
    DnsQueryEvent,
    NetworkInterface,
    PortInfo,
    PortScanReport,
    SecurityEvent,
    SystemNetworkOverview,
    TrafficSnapshot,
)
from cowman.utils.time import format_timestamp


def format_overview_panel(overview: SystemNetworkOverview) -> Panel:
    """Format high-level system network overview."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")

    table.add_row("Hostname:", f"[bold white]{overview.hostname}[/bold white]")
    table.add_row("Operating System:", overview.os_name)
    table.add_row("Primary Interface:", overview.active_interface or "None")
    table.add_row("Local IPv4:", f"[bold green]{overview.local_ip or 'N/A'}[/bold green]")
    table.add_row("Default Gateway:", overview.default_gateway or "N/A")
    dns_str = ", ".join(overview.dns_servers) if overview.dns_servers else "N/A"
    table.add_row("DNS Resolvers:", dns_str)
    table.add_row("Hardware MAC:", overview.mac_address or "N/A")
    table.add_row("Active Connections:", f"[bold yellow]{overview.active_connections_count}[/bold yellow]")
    table.add_row("Network IO Recv:", f"{overview.total_rx_mb:.2f} MB")
    table.add_row("Network IO Sent:", f"{overview.total_tx_mb:.2f} MB")

    return Panel(
        table,
        title="[bold bright_cyan]Network Host Telemetry[/bold bright_cyan]",
        border_style="bright_blue",
    )


def format_interfaces_table(interfaces: List[NetworkInterface]) -> Table:
    """Format network interfaces table."""
    table = Table(title="[bold cyan]Hardware & Virtual Interfaces[/bold cyan]", border_style="bright_blue")
    table.add_column("Interface", style="bold white")
    table.add_column("IPv4 Address", style="cyan")
    table.add_column("Netmask", style="dim white")
    table.add_column("MAC Address", style="dim cyan")
    table.add_column("Status", justify="center")
    table.add_column("Speed", justify="right", style="dim")
    table.add_column("MTU", justify="right", style="dim")
    table.add_column("RX (MB)", justify="right")
    table.add_column("TX (MB)", justify="right")

    for iface in interfaces:
        status_badge = "[bold green]UP[/bold green]" if iface.is_up else "[dim red]DOWN[/dim red]"
        speed_str = f"{iface.speed_mbps} Mbps" if iface.speed_mbps > 0 else "-"
        rx_mb = f"{iface.rx_bytes / (1024 * 1024):.1f}"
        tx_mb = f"{iface.tx_bytes / (1024 * 1024):.1f}"

        table.add_row(
            iface.name,
            iface.ip or "-",
            iface.netmask or "-",
            iface.mac or "-",
            status_badge,
            speed_str,
            str(iface.mtu),
            rx_mb,
            tx_mb,
        )
    return table


def format_devices_table(devices: List[Device]) -> Table:
    """Format discovered devices table matching specification."""
    table = Table(title="[bold cyan]Discovered Local Network Inventory[/bold cyan]", border_style="bright_blue")
    table.add_column("IP", style="bold cyan")
    table.add_column("HOSTNAME", style="bright_white")
    table.add_column("MAC", style="dim cyan")
    table.add_column("VENDOR", style="yellow")
    table.add_column("TYPE", style="dim white")
    table.add_column("STATUS", justify="center")
    table.add_column("LAST SEEN", style="dim")

    for d in devices:
        status_styled = "[bold green]ONLINE[/bold green]" if d.status == "ONLINE" else "[dim red]OFFLINE[/dim red]"
        table.add_row(
            d.ip,
            d.hostname or "-",
            d.mac,
            d.vendor or "Unknown",
            d.device_type,
            status_styled,
            format_timestamp(d.last_seen, include_date=False),
        )
    return table


def format_ports_table(report: PortScanReport) -> Table:
    """Format port scan report table."""
    table = Table(
        title=f"[bold cyan]Port & Service Analysis: {report.target_host} ({report.resolved_ip})[/bold cyan]",
        border_style="bright_blue",
    )
    table.add_column("PORT", style="bold cyan", justify="right")
    table.add_column("STATE", justify="center")
    table.add_column("SERVICE", style="bold white")
    table.add_column("LATENCY", justify="right", style="dim")
    table.add_column("BANNER / DETAILS", style="dim cyan")

    if not report.open_ports:
        table.add_row("-", "[yellow]NO OPEN PORTS FOUND[/yellow]", "-", "-", "-")
    else:
        for p in report.open_ports:
            state_str = f"[bold green]{p.state}[/bold green]" if p.state == "OPEN" else p.state
            lat_str = f"{p.latency_ms} ms" if p.latency_ms else "-"
            table.add_row(
                str(p.port),
                state_str,
                p.service,
                lat_str,
                p.banner or "-",
            )
    return table


def format_events_table(events: List[SecurityEvent]) -> Table:
    """Format security and audit events table."""
    table = Table(title="[bold cyan]Security & Audit Event Stream[/bold cyan]", border_style="bright_blue")
    table.add_column("TIME", style="dim white")
    table.add_column("SEV", justify="center")
    table.add_column("CATEGORY", style="cyan")
    table.add_column("TITLE", style="bold white")
    table.add_column("SOURCE", style="dim cyan")
    table.add_column("TARGET", style="dim cyan")
    table.add_column("DESCRIPTION")

    for e in events:
        table.add_row(
            format_timestamp(e.timestamp),
            e.severity.badge,
            e.category,
            e.title,
            e.source_ip or "-",
            e.target_ip or "-",
            e.description,
        )
    return table


def format_dns_table(queries: List[DnsQueryEvent]) -> Table:
    """Format captured DNS queries table."""
    table = Table(title="[bold cyan]Captured DNS Activity[/bold cyan]", border_style="bright_blue")
    table.add_column("TIME", style="dim white")
    table.add_column("TYPE", justify="center", style="bold cyan")
    table.add_column("QUERY DOMAIN", style="bright_white")
    table.add_column("SOURCE", style="dim cyan")
    table.add_column("DESTINATION", style="dim")
    table.add_column("ANOMALY FLAG", justify="center")
    table.add_column("REASON", style="yellow")

    for q in queries:
        flag = "[bold red]ANOMALOUS[/bold red]" if q.is_anomalous else "[dim green]NORMAL[/dim green]"
        table.add_row(
            format_timestamp(q.timestamp, include_date=False),
            q.query_type,
            q.query_name,
            q.source_ip,
            q.destination_ip,
            flag,
            q.anomaly_reason or "-",
        )
    return table


def format_traffic_panel(snapshot: TrafficSnapshot) -> Panel:
    """Format live traffic dashboard panel."""
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)

    # Metrics Card 1: Bandwidth
    rx_str = f"[bold cyan]{snapshot.rx_rate_kbs:,.1f} KB/s[/bold cyan]"
    tx_str = f"[bold green]{snapshot.tx_rate_kbs:,.1f} KB/s[/bold green]"
    rx_pkts = f"{snapshot.rx_packets_sec:,.0f} pkts/s"
    tx_pkts = f"{snapshot.tx_packets_sec:,.0f} pkts/s"

    card1 = (
        f"[bold white]Interface:[/bold white] [bright_cyan]{snapshot.interface}[/bright_cyan]\n"
        f"RX Bandwidth: {rx_str} [dim]({rx_pkts})[/dim]\n"
        f"TX Bandwidth: {tx_str} [dim]({tx_pkts})[/dim]"
    )

    # Metrics Card 2: Sockets & Protocol Distribution
    card2 = (
        f"Total Active Connections: [bold yellow]{snapshot.active_connections}[/bold yellow]\n"
        f"TCP Sockets: [cyan]{snapshot.tcp_count}[/cyan]  |  UDP Sockets: [magenta]{snapshot.udp_count}[/magenta]\n"
        f"Sample Time: [dim]{format_timestamp(snapshot.timestamp, include_date=False)}[/dim]"
    )

    grid.add_row(card1, card2)

    # Top Connections Table
    top_table = Table(box=None, expand=True, padding=(0, 1))
    top_table.add_column("Proto", style="dim", width=6)
    top_table.add_column("Local Address", style="cyan")
    top_table.add_column("Remote Address", style="bright_white")
    top_table.add_column("Status", style="yellow")
    top_table.add_column("Process", style="dim green")

    # Show first 8 connections
    for c in snapshot.connections[:8]:
        top_table.add_row(
            c.proto,
            c.local_address,
            c.remote_address,
            c.status,
            f"{c.process_name or 'N/A'} ({c.pid or '-'})",
        )

    layout_table = Table.grid(expand=True)
    layout_table.add_row(grid)
    layout_table.add_row(Text("\nActive Socket Connections:", style="bold white"))
    layout_table.add_row(top_table)

    return Panel(
        layout_table,
        title="[bold bright_cyan]Live Network Traffic Monitor (Press Ctrl+C to Exit)[/bold bright_cyan]",
        border_style="bright_blue",
    )

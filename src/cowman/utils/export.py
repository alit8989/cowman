"""Export utilities for generating JSON, CSV, and Markdown reports."""

import csv
import io
import json
from typing import Any, Dict, List, Optional
from cowman.core.models import Device, DnsQueryEvent, PortInfo, SecurityEvent, SystemNetworkOverview
from cowman.utils.time import format_timestamp


class ReportExporter:
    """Exports network and security data to JSON, CSV, and Markdown."""

    @staticmethod
    def build_report_data(
        overview: Optional[SystemNetworkOverview],
        devices: List[Device],
        events: List[SecurityEvent],
        ports: Optional[List[PortInfo]] = None,
        dns_logs: Optional[List[DnsQueryEvent]] = None,
    ) -> Dict[str, Any]:
        return {
            "metadata": {
                "generated_at": format_timestamp(None),
                "host": overview.hostname if overview else "Unknown",
                "os": overview.os_name if overview else "Unknown",
                "local_ip": overview.local_ip if overview else "Unknown",
                "default_gateway": overview.default_gateway if overview else "Unknown",
                "device_count": len(devices),
                "event_count": len(events),
            },
            "devices": [d.model_dump(mode="json") for d in devices],
            "security_events": [e.model_dump(mode="json") for e in events],
            "ports": [p.model_dump(mode="json") for p in (ports or [])],
            "dns_queries": [q.model_dump(mode="json") for q in (dns_logs or [])],
        }

    @classmethod
    def to_json(cls, data: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(data, indent=indent, default=str)

    @classmethod
    def to_csv(cls, devices: List[Device], events: List[SecurityEvent]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        # Devices Section
        writer.writerow(["# SECTION: DISCOVERED DEVICES"])
        writer.writerow(["IP", "MAC", "HOSTNAME", "VENDOR", "STATUS", "DEVICE_TYPE", "FIRST_SEEN", "LAST_SEEN"])
        for d in devices:
            writer.writerow([
                d.ip,
                d.mac,
                d.hostname or "N/A",
                d.vendor or "Unknown",
                d.status,
                d.device_type,
                format_timestamp(d.first_seen),
                format_timestamp(d.last_seen),
            ])

        writer.writerow([])
        # Events Section
        writer.writerow(["# SECTION: SECURITY EVENTS"])
        writer.writerow(["TIMESTAMP", "SEVERITY", "RULE_ID", "TITLE", "CATEGORY", "SOURCE_IP", "TARGET_IP", "DESCRIPTION"])
        for e in events:
            writer.writerow([
                format_timestamp(e.timestamp),
                e.severity.value,
                e.rule_id,
                e.title,
                e.category,
                e.source_ip or "N/A",
                e.target_ip or "N/A",
                e.description,
            ])

        return output.getvalue()

    @classmethod
    def to_markdown(
        cls,
        overview: Optional[SystemNetworkOverview],
        devices: List[Device],
        events: List[SecurityEvent],
        ports: Optional[List[PortInfo]] = None,
        dns_logs: Optional[List[DnsQueryEvent]] = None,
    ) -> str:
        lines: List[str] = []
        lines.append("# COWMAN Security & Network Audit Report")
        lines.append("")
        lines.append(f"**Generated:** {format_timestamp(None)}")
        if overview:
            lines.append(f"- **Host:** `{overview.hostname}`")
            lines.append(f"- **Operating System:** `{overview.os_name}`")
            lines.append(f"- **Primary IP:** `{overview.local_ip or 'N/A'}`")
            lines.append(f"- **Default Gateway:** `{overview.default_gateway or 'N/A'}`")
            lines.append(f"- **DNS Servers:** `{', '.join(overview.dns_servers) if overview.dns_servers else 'N/A'}`")
        lines.append("")

        # Executive Summary
        critical_count = sum(1 for e in events if e.severity.value == "CRITICAL")
        high_count = sum(1 for e in events if e.severity.value == "HIGH")
        med_count = sum(1 for e in events if e.severity.value == "MEDIUM")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Total Discovered Devices:** {len(devices)}")
        lines.append(f"- **Total Security Events:** {len(events)}")
        lines.append(f"- **Critical Anomalies:** {critical_count}")
        lines.append(f"- **High Severity Warnings:** {high_count}")
        lines.append(f"- **Medium Findings:** {med_count}")
        lines.append("")

        # Devices Table
        lines.append("## Discovered Network Inventory")
        lines.append("")
        lines.append("| IP Address | Hostname | MAC Address | Vendor | Type | Status | First Seen |")
        lines.append("|:---|:---|:---|:---|:---|:---|:---|")
        for d in devices:
            lines.append(
                f"| `{d.ip}` | {d.hostname or '*Unknown*'} | `{d.mac}` | {d.vendor or 'Unknown'} | {d.device_type} | **{d.status}** | {format_timestamp(d.first_seen)} |"
            )
        lines.append("")

        # Security Events Table
        lines.append("## Security & Anomaly Events")
        lines.append("")
        lines.append("| Timestamp | Severity | Rule ID | Title | Source IP | Target IP | Description |")
        lines.append("|:---|:---|:---|:---|:---|:---|:---|")
        for e in events:
            lines.append(
                f"| {format_timestamp(e.timestamp)} | **{e.severity.value}** | `{e.rule_id}` | {e.title} | `{e.source_ip or '-'}` | `{e.target_ip or '-'}` | {e.description} |"
            )
        lines.append("")

        if ports:
            lines.append("## Identified Ports & Services")
            lines.append("")
            lines.append("| Port | Protocol | State | Service | Banner / Details |")
            lines.append("|:---|:---|:---|:---|:---|")
            for p in ports:
                lines.append(f"| {p.port} | {p.protocol} | **{p.state}** | `{p.service}` | {p.banner or '-'} |")
            lines.append("")

        if dns_logs:
            lines.append("## Recent DNS Activity")
            lines.append("")
            lines.append("| Timestamp | Query Name | Type | Source | Anomalous | Reason |")
            lines.append("|:---|:---|:---|:---|:---|:---|")
            for q in dns_logs:
                flag = "⚠️ YES" if q.is_anomalous else "NO"
                lines.append(f"| {format_timestamp(q.timestamp)} | `{q.query_name}` | {q.query_type} | `{q.source_ip}` | {flag} | {q.anomaly_reason or '-'} |")
            lines.append("")

        return "\n".join(lines)

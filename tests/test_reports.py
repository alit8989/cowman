"""Tests for report generation (JSON, CSV, Markdown)."""

import json
import pytest
from cowman.core.models import (
    Device,
    DnsQueryEvent,
    PortInfo,
    SecurityEvent,
    SystemNetworkOverview,
)
from cowman.security.severity import Severity
from cowman.utils.export import ReportExporter


def test_report_exporter():
    overview = SystemNetworkOverview(
        hostname="test-host",
        os_name="Linux 6.5",
        local_ip="192.168.1.10",
        default_gateway="192.168.1.1",
        dns_servers=["1.1.1.1"],
    )
    devices = [
        Device(ip="192.168.1.1", mac="00:11:22:33:44:55", vendor="TP-Link", status="ONLINE"),
        Device(ip="192.168.1.10", mac="00:AA:BB:CC:DD:EE", vendor="Intel", status="ONLINE"),
    ]
    events = [
        SecurityEvent(
            rule_id="SEC-001",
            title="New Device",
            severity=Severity.INFO,
            category="DISCOVERY",
            description="New device found",
        )
    ]
    ports = [PortInfo(port=80, protocol="TCP", state="OPEN", service="HTTP")]

    # JSON test
    data = ReportExporter.build_report_data(overview, devices, events, ports=ports)
    json_str = ReportExporter.to_json(data)
    parsed = json.loads(json_str)
    assert parsed["metadata"]["host"] == "test-host"
    assert len(parsed["devices"]) == 2
    assert len(parsed["security_events"]) == 1

    # CSV test
    csv_str = ReportExporter.to_csv(devices, events)
    assert "192.168.1.1" in csv_str
    assert "SEC-001" in csv_str

    # Markdown test
    md_str = ReportExporter.to_markdown(overview, devices, events, ports=ports)
    assert "# COWMAN Security & Network Audit Report" in md_str
    assert "Executive Summary" in md_str
    assert "Discovered Network Inventory" in md_str
    assert "Security & Anomaly Events" in md_str

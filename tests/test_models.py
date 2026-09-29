"""Tests for core domain Pydantic data models."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from cowman.core.models import (
    ActiveConnectionInfo,
    Device,
    DnsQueryEvent,
    NetworkInterface,
    PortInfo,
    PortScanReport,
    SecurityEvent,
    SystemNetworkOverview,
    TrafficSnapshot,
    utc_now,
)
from cowman.security.severity import Severity


def test_device_model_defaults():
    dev = Device(ip="192.168.1.50")
    assert dev.ip == "192.168.1.50"
    assert dev.mac == "Unknown"
    assert dev.vendor == "Unknown"
    assert dev.status == "ONLINE"
    assert dev.device_type == "Unknown"
    assert dev.open_ports == []
    assert isinstance(dev.first_seen, datetime)
    assert isinstance(dev.last_seen, datetime)


def test_network_interface_model():
    iface = NetworkInterface(
        name="eth0",
        ip="10.0.0.5",
        netmask="255.255.255.0",
        mac="00:11:22:33:44:55",
        is_up=True,
        speed_mbps=1000,
        mtu=1500,
        rx_bytes=1048576,
        tx_bytes=524288,
    )
    assert iface.name == "eth0"
    assert iface.is_up is True
    assert iface.speed_mbps == 1000
    assert iface.rx_bytes == 1048576


def test_port_scan_report_model():
    report = PortScanReport(
        target_host="localhost",
        resolved_ip="127.0.0.1",
        scanned_ports_count=3,
        open_ports=[
            PortInfo(port=80, protocol="TCP", state="OPEN", service="HTTP", latency_ms=1.2),
            PortInfo(port=443, protocol="TCP", state="OPEN", service="HTTPS", latency_ms=1.5),
        ],
        scan_duration_seconds=0.45,
    )
    assert report.target_host == "localhost"
    assert len(report.open_ports) == 2
    assert report.open_ports[0].port == 80
    assert report.open_ports[1].service == "HTTPS"


def test_security_event_model():
    evt = SecurityEvent(
        rule_id="SEC-001",
        title="Test Event",
        severity=Severity.HIGH,
        category="SERVICE",
        target_ip="192.168.1.100",
        description="Suspicious port detected",
    )
    assert evt.rule_id == "SEC-001"
    assert evt.severity == Severity.HIGH
    assert evt.category == "SERVICE"
    assert evt.target_ip == "192.168.1.100"


def test_traffic_snapshot_model():
    snap = TrafficSnapshot(
        interface="eth0",
        rx_rate_kbs=500.5,
        tx_rate_kbs=120.2,
        active_connections=12,
        connections=[
            ActiveConnectionInfo(
                proto="TCP",
                local_address="127.0.0.1:8080",
                remote_address="127.0.0.1:54321",
                status="ESTABLISHED",
                process_name="python.exe",
            )
        ],
    )
    assert snap.interface == "eth0"
    assert snap.rx_rate_kbs == 500.5
    assert len(snap.connections) == 1
    assert snap.connections[0].process_name == "python.exe"


def test_dns_query_event_model():
    dns_ev = DnsQueryEvent(
        source_ip="192.168.1.20",
        destination_ip="1.1.1.1",
        query_name="example.com",
        query_type="AAAA",
        is_anomalous=False,
    )
    assert dns_ev.query_name == "example.com"
    assert dns_ev.query_type == "AAAA"
    assert dns_ev.is_anomalous is False

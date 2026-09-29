"""Tests for the Security Event Engine and defensive rules."""

import pytest
from cowman.core.models import (
    Device,
    DnsQueryEvent,
    PortInfo,
    PortScanReport,
    SecurityEvent,
    TrafficSnapshot,
    utc_now,
)
from cowman.security.engine import SecurityEventEngine
from cowman.security.rules import (
    DeviceStateChangeRule,
    DnsAnomalyRule,
    InterfaceStateRule,
    NetworkAnomalyRule,
    NewDeviceRule,
    UnexpectedServiceRule,
)
from cowman.security.severity import Severity


def test_new_device_rule():
    rule = NewDeviceRule()
    dev = Device(ip="192.168.1.75", mac="00:11:22:33:44:55", vendor="Apple", hostname="guest-phone")
    events = rule.evaluate({"is_new_device": True, "device": dev})
    assert len(events) == 1
    assert events[0].rule_id == "SEC-001-NEW-DEVICE"
    assert events[0].severity == Severity.INFO
    assert "192.168.1.75" in events[0].description


def test_device_state_change_rule():
    rule = DeviceStateChangeRule()
    dev = Device(ip="192.168.1.10", hostname="nas-server")
    events = rule.evaluate({"device": dev, "old_status": "ONLINE", "new_status": "OFFLINE"})
    assert len(events) == 1
    assert events[0].rule_id == "SEC-002-DEVICE-STATE"
    assert events[0].severity == Severity.LOW
    assert "Offline" in events[0].title


def test_unexpected_service_rule():
    rule = UnexpectedServiceRule()
    report = PortScanReport(
        target_host="router.local",
        resolved_ip="192.168.1.1",
        open_ports=[
            PortInfo(port=23, protocol="TCP", state="OPEN", service="Telnet", banner="BusyBox telnetd"),
            PortInfo(port=80, protocol="TCP", state="OPEN", service="HTTP"),
        ],
    )
    events = rule.evaluate({"port_scan_report": report})
    assert len(events) >= 1
    telnet_event = [e for e in events if "Telnet" in e.title][0]
    assert telnet_event.severity == Severity.HIGH
    assert "23" in telnet_event.description


def test_dns_anomaly_rule():
    rule = DnsAnomalyRule()
    dns_ev = DnsQueryEvent(
        source_ip="192.168.1.50",
        destination_ip="8.8.8.8",
        query_name="a90b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f.tunnel.exfil.org",
        is_anomalous=True,
        anomaly_reason="Excessive domain length - potential DNS tunnel",
    )
    events = rule.evaluate({"dns_event": dns_ev})
    assert len(events) == 1
    assert events[0].rule_id == "SEC-005-DNS-ANOMALY"
    assert events[0].severity in (Severity.MEDIUM, Severity.HIGH)


def test_network_traffic_anomaly_rule():
    rule = NetworkAnomalyRule()
    snap = TrafficSnapshot(
        interface="eth0",
        rx_rate_kbs=60000.0,  # ~58 MB/s (exceeds default 50 MB/s threshold)
        tx_rate_kbs=1000.0,
        active_connections=600,  # exceeds default 500 threshold
    )
    events = rule.evaluate({"traffic_snapshot": snap})
    assert len(events) == 2  # Bandwidth surge and Connection spike


def test_security_engine_lifecycle():
    engine = SecurityEventEngine()
    received_events = []

    def _listener(evt: SecurityEvent):
        received_events.append(evt)

    engine.subscribe(_listener)

    dev = Device(ip="10.0.0.99", mac="00:AA:BB:CC:DD:EE")
    fired = engine.process_device_discovery(dev, is_new=True)

    assert len(fired) >= 1
    assert len(received_events) >= 1
    assert received_events[0].target_ip == "10.0.0.99"

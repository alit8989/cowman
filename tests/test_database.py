"""Tests for SQLite persistence and database repositories."""

from datetime import datetime, timedelta, timezone
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
from cowman.security.severity import Severity
from cowman.storage.repository import (
    DeviceRepository,
    DnsLogRepository,
    PortRepository,
    SecurityEventRepository,
    TrafficLogRepository,
)


def test_device_repository_crud():
    now = utc_now()
    dev1 = Device(
        ip="192.168.1.10",
        mac="00:11:22:33:44:55",
        hostname="workstation",
        vendor="Intel",
        status="ONLINE",
        device_type="Laptop",
        first_seen=now,
        last_seen=now,
        open_ports=[22, 80],
    )

    # Save
    saved = DeviceRepository.save_or_update(dev1)
    assert saved.ip == "192.168.1.10"
    assert saved.vendor == "Intel"
    assert saved.open_ports == [22, 80]

    # Get by IP
    fetched = DeviceRepository.get_by_ip("192.168.1.10")
    assert fetched is not None
    assert fetched.hostname == "workstation"
    assert fetched.mac == "00:11:22:33:44:55"

    # Update
    dev1.hostname = "workstation-renamed"
    dev1.open_ports = [22, 80, 443]
    updated = DeviceRepository.save_or_update(dev1)
    assert updated.hostname == "workstation-renamed"
    assert 443 in updated.open_ports

    # Count
    assert DeviceRepository.count() == 1

    # Get all
    all_devs = DeviceRepository.get_all()
    assert len(all_devs) == 1


def test_security_event_repository():
    now = utc_now()
    ev1 = SecurityEvent(
        timestamp=now - timedelta(hours=2),
        rule_id="SEC-001",
        title="Event Old",
        severity=Severity.INFO,
        category="DISCOVERY",
        target_ip="10.0.0.1",
        description="First event",
    )
    ev2 = SecurityEvent(
        timestamp=now,
        rule_id="SEC-003",
        title="Event New",
        severity=Severity.CRITICAL,
        category="SERVICE",
        target_ip="10.0.0.2",
        description="Second event",
    )

    SecurityEventRepository.add(ev1)
    SecurityEventRepository.add(ev2)

    assert SecurityEventRepository.count() == 2
    assert SecurityEventRepository.count(severity="CRITICAL") == 1

    # Filter by severity
    crit_events = SecurityEventRepository.get_events(severity="CRITICAL")
    assert len(crit_events) == 1
    assert crit_events[0].title == "Event New"

    # Filter by time range
    recent_events = SecurityEventRepository.get_events(start_time=now - timedelta(minutes=30))
    assert len(recent_events) == 1
    assert recent_events[0].title == "Event New"


def test_port_repository():
    report = PortScanReport(
        target_host="web-server",
        resolved_ip="192.168.1.200",
        scanned_ports_count=2,
        open_ports=[
            PortInfo(port=80, protocol="TCP", state="OPEN", service="HTTP", banner="nginx/1.24"),
            PortInfo(port=443, protocol="TCP", state="OPEN", service="HTTPS"),
        ],
    )

    PortRepository.save_scan(report)
    open_ports = PortRepository.get_open_ports_for_host("192.168.1.200")
    assert len(open_ports) == 2
    assert open_ports[0].port == 80
    assert open_ports[0].banner == "nginx/1.24"


def test_dns_and_traffic_log_repositories():
    dns_ev = DnsQueryEvent(
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        query_name="suspicious-domain.xyz",
        query_type="A",
        is_anomalous=True,
        anomaly_reason="High entropy",
    )
    DnsLogRepository.log(dns_ev)

    logs = DnsLogRepository.get_logs(anomalous_only=True)
    assert len(logs) == 1
    assert logs[0].query_name == "suspicious-domain.xyz"

    snap = TrafficSnapshot(
        interface="eth0",
        rx_rate_kbs=100.0,
        tx_rate_kbs=50.0,
        active_connections=5,
    )
    TrafficLogRepository.log(snap)

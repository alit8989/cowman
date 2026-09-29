"""Seed realistic security events into SQLite database for testing and replay."""

from datetime import timedelta
from cowman.core.models import SecurityEvent, utc_now
from cowman.security.severity import Severity
from cowman.storage.database import init_db
from cowman.storage.repository import SecurityEventRepository


def seed():
    init_db()
    now = utc_now()
    events = [
        SecurityEvent(
            timestamp=now - timedelta(minutes=15),
            rule_id="SEC-001-NEW-DEVICE",
            title="New Network Device Detected",
            severity=Severity.INFO,
            category="DISCOVERY",
            target_ip="192.168.1.5",
            description="New device detected on local subnet: 192.168.1.5 [04:26:65:11:22:33] (Apple). Hostname: iphone.",
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=12),
            rule_id="SEC-005-DNS-ANOMALY",
            title="DNS Anomaly Observed",
            severity=Severity.MEDIUM,
            category="DNS",
            source_ip="192.168.1.20",
            target_ip="8.8.8.8",
            description="Potentially anomalous DNS query observed from 192.168.1.20: Query 'a8f93e2b109c4d9e018a.tunnel.internal' [Type A]. Reason: Excessive length.",
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=10),
            rule_id="SEC-002-DEVICE-STATE",
            title="Device Offline",
            severity=Severity.LOW,
            category="DISCOVERY",
            target_ip="192.168.1.15",
            description="Device state transition observed: 192.168.1.15 (Office-Printer) changed from ONLINE to OFFLINE.",
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=5),
            rule_id="SEC-002-DEVICE-STATE",
            title="Device Online",
            severity=Severity.LOW,
            category="DISCOVERY",
            target_ip="192.168.1.15",
            description="Device state transition observed: 192.168.1.15 (Office-Printer) changed from OFFLINE to ONLINE.",
        ),
        SecurityEvent(
            timestamp=now - timedelta(minutes=2),
            rule_id="SEC-003-UNEXPECTED-SERVICE",
            title="Unexpected Service (Telnet)",
            severity=Severity.HIGH,
            category="SERVICE",
            target_ip="192.168.1.50",
            description="Potentially unexpected service detected on 192.168.1.50: Port 23/TCP [Telnet] is OPEN. Banner: Cisco IOS Telnet Gateway",
        ),
    ]

    for e in events:
        SecurityEventRepository.add(e)
    print(f"Successfully seeded {len(events)} security events.")


if __name__ == "__main__":
    seed()

"""Modular rule-based security event detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from cowman.core.config import get_config
from cowman.core.models import (
    Device,
    DnsQueryEvent,
    NetworkInterface,
    PortInfo,
    PortScanReport,
    SecurityEvent,
    TrafficSnapshot,
    utc_now,
)
from cowman.security.severity import Severity


class BaseSecurityRule(ABC):
    """Abstract base class for all defensive security rules."""

    rule_id: str = "BASE_RULE"
    name: str = "Base Security Rule"
    category: str = "ANOMALY"
    default_severity: Severity = Severity.INFO

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        """Evaluate rule conditions against the provided event context."""
        pass


class NewDeviceRule(BaseSecurityRule):
    """Detects when an unrecognized MAC/IP device connects to the authorized network."""

    rule_id: str = "SEC-001-NEW-DEVICE"
    name: str = "New Device Discovered"
    category: str = "DISCOVERY"
    default_severity: Severity = Severity.INFO

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        is_new = context.get("is_new_device", False)
        device: Optional[Device] = context.get("device")

        if is_new and device:
            desc = (
                f"New device detected on local subnet: {device.ip} "
                f"[{device.mac}] ({device.vendor or 'Unknown Vendor'}). "
                f"Hostname: {device.hostname or 'N/A'}."
            )
            events.append(
                SecurityEvent(
                    timestamp=utc_now(),
                    rule_id=self.rule_id,
                    title="New Network Device Detected",
                    severity=self.default_severity,
                    category=self.category,
                    target_ip=device.ip,
                    description=desc,
                    details={
                        "ip": device.ip,
                        "mac": device.mac,
                        "vendor": device.vendor,
                        "hostname": device.hostname,
                    },
                )
            )
        return events


class DeviceStateChangeRule(BaseSecurityRule):
    """Detects when a known host transitions between online and offline states."""

    rule_id: str = "SEC-002-DEVICE-STATE"
    name: str = "Device Status Transition"
    category: str = "DISCOVERY"
    default_severity: Severity = Severity.LOW

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        old_status = context.get("old_status")
        new_status = context.get("new_status")
        device: Optional[Device] = context.get("device")

        if old_status and new_status and old_status != new_status and device:
            desc = (
                f"Device state transition observed: {device.ip} "
                f"({device.hostname or device.vendor or 'Host'}) changed from {old_status} to {new_status}."
            )
            events.append(
                SecurityEvent(
                    timestamp=utc_now(),
                    rule_id=self.rule_id,
                    title=f"Device {new_status.title()}",
                    severity=self.default_severity,
                    category=self.category,
                    target_ip=device.ip,
                    description=desc,
                    details={"ip": device.ip, "old_status": old_status, "new_status": new_status},
                )
            )
        return events


class UnexpectedServiceRule(BaseSecurityRule):
    """Detects unexpected, plaintext, or sensitive services exposed on local endpoints."""

    rule_id: str = "SEC-003-UNEXPECTED-SERVICE"
    name: str = "Unexpected Service Identified"
    category: str = "SERVICE"
    default_severity: Severity = Severity.MEDIUM

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        scan_report: Optional[PortScanReport] = context.get("port_scan_report")
        cfg = get_config()
        unexpected_ports = set(cfg.security.unexpected_ports)

        if scan_report:
            for p in scan_report.open_ports:
                if p.port in unexpected_ports:
                    sev = Severity.HIGH if p.port in (21, 23, 445) else Severity.MEDIUM
                    desc = (
                        f"Potentially unexpected service detected on {scan_report.target_host} ({scan_report.resolved_ip}): "
                        f"Port {p.port}/{p.protocol} ({p.service}) is OPEN."
                    )
                    if p.banner:
                        desc += f" Banner: {p.banner}"

                    events.append(
                        SecurityEvent(
                            timestamp=utc_now(),
                            rule_id=self.rule_id,
                            title=f"Unexpected Service ({p.service})",
                            severity=sev,
                            category=self.category,
                            target_ip=scan_report.resolved_ip,
                            description=desc,
                            details={
                                "port": p.port,
                                "protocol": p.protocol,
                                "service": p.service,
                                "banner": p.banner,
                            },
                        )
                    )
        return events


class InterfaceStateRule(BaseSecurityRule):
    """Detects physical or logical network interface status and address modifications."""

    rule_id: str = "SEC-004-INTERFACE-STATE"
    name: str = "Interface State Modification"
    category: str = "INTERFACE"
    default_severity: Severity = Severity.MEDIUM

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        iface_name = context.get("interface_name")
        change_type = context.get("change_type")
        details = context.get("change_details", "")

        if iface_name and change_type:
            events.append(
                SecurityEvent(
                    timestamp=utc_now(),
                    rule_id=self.rule_id,
                    title=f"Interface Change: {change_type}",
                    severity=self.default_severity,
                    category=self.category,
                    description=f"Network interface '{iface_name}' reported change: {details}",
                    details={"interface": iface_name, "change": change_type},
                )
            )
        return events


class DnsAnomalyRule(BaseSecurityRule):
    """Detects anomalous DNS requests such as potential DGA domains or DNS tunneling."""

    rule_id: str = "SEC-005-DNS-ANOMALY"
    name: str = "Anomalous DNS Query"
    category: str = "DNS"
    default_severity: Severity = Severity.MEDIUM

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        dns_event: Optional[DnsQueryEvent] = context.get("dns_event")

        if dns_event and dns_event.is_anomalous:
            sev = Severity.HIGH if "tunnel" in (dns_event.anomaly_reason or "").lower() else Severity.MEDIUM
            desc = (
                f"Potentially anomalous DNS query observed from {dns_event.source_ip}: "
                f"Query '{dns_event.query_name}' ({dns_event.query_type}). "
                f"Trigger reason: {dns_event.anomaly_reason}."
            )
            events.append(
                SecurityEvent(
                    timestamp=utc_now(),
                    rule_id=self.rule_id,
                    title="DNS Anomaly Observed",
                    severity=sev,
                    category=self.category,
                    source_ip=dns_event.source_ip,
                    target_ip=dns_event.destination_ip,
                    description=desc,
                    details={
                        "query_name": dns_event.query_name,
                        "query_type": dns_event.query_type,
                        "reason": dns_event.anomaly_reason,
                    },
                )
            )
        return events


class NetworkAnomalyRule(BaseSecurityRule):
    """Detects bandwidth saturation bursts and unusual socket connection counts."""

    rule_id: str = "SEC-006-NETWORK-ANOMALY"
    name: str = "Network Traffic Anomaly"
    category: str = "TRAFFIC"
    default_severity: Severity = Severity.MEDIUM

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        snap: Optional[TrafficSnapshot] = context.get("traffic_snapshot")
        cfg = get_config()

        if snap:
            # Check bandwidth spike
            rx_mb = snap.rx_rate_kbs / 1024.0
            tx_mb = snap.tx_rate_kbs / 1024.0
            total_mb = rx_mb + tx_mb

            if total_mb > cfg.security.bandwidth_spike_mb:
                desc = (
                    f"Unexpected traffic surge on interface {snap.interface}: "
                    f"Total throughput {total_mb:.1f} MB/s (RX: {rx_mb:.1f} MB/s, TX: {tx_mb:.1f} MB/s) "
                    f"exceeded threshold of {cfg.security.bandwidth_spike_mb:.1f} MB/s."
                )
                events.append(
                    SecurityEvent(
                        timestamp=utc_now(),
                        rule_id=self.rule_id,
                        title="Unusual Bandwidth Surge",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        description=desc,
                        details={"rx_mb": rx_mb, "tx_mb": tx_mb, "interface": snap.interface},
                    )
                )

            # Check abnormal connection count
            if snap.active_connections > cfg.security.connection_count_threshold:
                desc = (
                    f"Anomalous active connection volume detected: "
                    f"{snap.active_connections} concurrent sockets active on system "
                    f"(Threshold: {cfg.security.connection_count_threshold})."
                )
                events.append(
                    SecurityEvent(
                        timestamp=utc_now(),
                        rule_id="SEC-007-CONNECTION-SPIKE",
                        title="Abnormal Active Connection Count",
                        severity=Severity.HIGH,
                        category=self.category,
                        description=desc,
                        details={"active_connections": snap.active_connections},
                    )
                )

        return events

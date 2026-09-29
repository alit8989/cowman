"""Security Event Engine orchestrating rule evaluation, event generation, and persistence."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from cowman.core.logger import get_logger
from cowman.core.models import (
    Device,
    DnsQueryEvent,
    PortScanReport,
    SecurityEvent,
    TrafficSnapshot,
)
from cowman.security.rules import (
    BaseSecurityRule,
    DeviceStateChangeRule,
    DnsAnomalyRule,
    InterfaceStateRule,
    NetworkAnomalyRule,
    NewDeviceRule,
    UnexpectedServiceRule,
)
from cowman.storage.repository import SecurityEventRepository

logger = get_logger("security_engine")


class SecurityEventEngine:
    """Central engine managing defensive security detection rules."""

    def __init__(self):
        self.rules: List[BaseSecurityRule] = [
            NewDeviceRule(),
            DeviceStateChangeRule(),
            UnexpectedServiceRule(),
            InterfaceStateRule(),
            DnsAnomalyRule(),
            NetworkAnomalyRule(),
        ]
        self._listeners: List[Callable[[SecurityEvent], None]] = []

    def register_rule(self, rule: BaseSecurityRule) -> None:
        """Add a custom detection rule to the engine."""
        self.rules.append(rule)

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for newly triggered security events."""
        self._listeners.append(callback)

    def evaluate(self, context: Dict[str, Any]) -> List[SecurityEvent]:
        """Run all active rules against the telemetry context, saving events to DB."""
        new_events: List[SecurityEvent] = []

        for rule in self.rules:
            try:
                matched = rule.evaluate(context)
                for event in matched:
                    # Persist event to database
                    saved_event = SecurityEventRepository.add(event)
                    new_events.append(saved_event)
                    logger.info(f"[{event.severity.value}] {event.title}: {event.description}")
                    # Notify registered listeners
                    for listener in self._listeners:
                        try:
                            listener(saved_event)
                        except Exception as e:
                            logger.debug(f"Error in event listener: {e}")
            except Exception as e:
                logger.error(f"Rule evaluation failed for {rule.rule_id}: {e}")

        return new_events

    def process_device_discovery(self, device: Device, is_new: bool = False, old_status: Optional[str] = None) -> List[SecurityEvent]:
        """Convenience method to evaluate device discovery telemetry."""
        ctx = {
            "device": device,
            "is_new_device": is_new,
            "old_status": old_status,
            "new_status": device.status,
        }
        return self.evaluate(ctx)

    def process_port_scan(self, report: PortScanReport) -> List[SecurityEvent]:
        """Convenience method to evaluate port scan results."""
        return self.evaluate({"port_scan_report": report})

    def process_dns_event(self, dns_event: DnsQueryEvent) -> List[SecurityEvent]:
        """Convenience method to evaluate a DNS query event."""
        return self.evaluate({"dns_event": dns_event})

    def process_traffic_snapshot(self, snapshot: TrafficSnapshot) -> List[SecurityEvent]:
        """Convenience method to evaluate traffic telemetry."""
        return self.evaluate({"traffic_snapshot": snapshot})


_GLOBAL_ENGINE: Optional[SecurityEventEngine] = None


def get_security_engine() -> SecurityEventEngine:
    """Retrieve singleton instance of SecurityEventEngine."""
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = SecurityEventEngine()
    return _GLOBAL_ENGINE

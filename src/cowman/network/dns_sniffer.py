"""DNS query monitor and anomaly detector."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import math
import queue
import threading
from typing import Callable, Generator, List, Optional
import scapy.all as scapy

from cowman.core.config import get_config
from cowman.core.logger import get_logger
from cowman.core.models import DnsQueryEvent, utc_now
from cowman.storage.repository import DnsLogRepository
from cowman.utils.platform import get_privilege_hint, is_admin

logger = get_logger("dns")

DNS_QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for string randomness detection (DGA indicator)."""
    if not text:
        return 0.0
    text = text.lower()
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def inspect_dns_anomaly(query_name: str, config=None) -> tuple[bool, Optional[str]]:
    """Evaluate whether a DNS query matches known anomaly patterns."""
    cfg = config or get_config()
    clean_domain = query_name.rstrip(".")

    # High length check (indicative of DNS tunneling or data exfiltration)
    if len(clean_domain) > cfg.dns.domain_length_alert_threshold:
        return True, f"Excessive domain length ({len(clean_domain)} chars) - potential DNS tunnel"

    # Entropy check for base domain labels
    labels = clean_domain.split(".")
    for label in labels:
        if len(label) > 10:
            ent = calculate_entropy(label)
            if ent > cfg.dns.entropy_alert_threshold:
                return True, f"High Shannon entropy ({ent:.2f}) on label '{label}' - potential DGA"

    # Suspicious hex or base64 encoded subdomain
    if len(labels) > 0 and len(labels[0]) > 20:
        if all(c in "0123456789abcdef" for c in labels[0].lower()):
            return True, "Hex-encoded subdomain prefix - potential tunneling"

    return False, None


class DnsMonitor:
    """Captures and analyzes DNS network traffic."""

    def __init__(self, interface: Optional[str] = None):
        self.config = get_config()
        self.interface_name = interface or self.config.general.interface
        self._packet_queue: queue.Queue = queue.Queue(maxsize=self.config.dns.buffer_size)
        self._stop_event = threading.Event()
        self._sniffer_thread: Optional[threading.Thread] = None

    def _process_packet(self, pkt):
        try:
            if pkt.haslayer(scapy.DNS) and pkt.getlayer(scapy.DNS).qr == 0:  # qr == 0 is DNS Query
                dns_layer = pkt.getlayer(scapy.DNS)
                if dns_layer.qd is None:
                    return

                qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype_code = dns_layer.qd.qtype
                qtype_str = DNS_QTYPE_MAP.get(qtype_code, str(qtype_code))

                src_ip = "Unknown"
                dst_ip = "Unknown"

                if pkt.haslayer(scapy.IP):
                    src_ip = pkt[scapy.IP].src
                    dst_ip = pkt[scapy.IP].dst
                elif pkt.haslayer(scapy.IPv6):
                    src_ip = pkt[scapy.IPv6].src
                    dst_ip = pkt[scapy.IPv6].dst

                is_anomaly, reason = inspect_dns_anomaly(qname, self.config)

                event = DnsQueryEvent(
                    timestamp=utc_now(),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    query_name=qname,
                    query_type=qtype_str,
                    is_anomalous=is_anomaly,
                    anomaly_reason=reason,
                )

                # Persist to database
                DnsLogRepository.log(event)

                try:
                    self._packet_queue.put_nowait(event)
                except queue.Full:
                    try:
                        self._packet_queue.get_nowait()
                        self._packet_queue.put_nowait(event)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Error parsing DNS packet: {e}")

    def _sniff_worker(self):
        kwargs = {
            "filter": "udp port 53 or tcp port 53",
            "prn": self._process_packet,
            "store": 0,
            "stop_filter": lambda _: self._stop_event.is_set(),
        }
        if self.interface_name:
            kwargs["iface"] = self.interface_name

        try:
            scapy.sniff(**kwargs)
        except Exception as e:
            logger.warning(f"DNS sniffer stopped: {e}")

    def start(self) -> bool:
        """Start sniffer background thread. Returns False if unprivileged."""
        self._stop_event.clear()
        self._sniffer_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self._sniffer_thread.start()
        return True

    def stop(self):
        """Stop sniffer thread."""
        self._stop_event.set()
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=1.0)

    def get_events(self, timeout: float = 0.5) -> List[DnsQueryEvent]:
        """Drain buffered events from sniffer queue."""
        events: List[DnsQueryEvent] = []
        try:
            while not self._packet_queue.empty():
                events.append(self._packet_queue.get_nowait())
        except Exception:
            pass
        return events

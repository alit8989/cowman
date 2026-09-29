"""Core domain data models for COWMAN using Pydantic."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cowman.security.severity import Severity


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NetworkInterface(BaseModel):
    name: str
    ip: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    mac: Optional[str] = None
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 1500
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_packets: int = 0
    tx_packets: int = 0


class SystemNetworkOverview(BaseModel):
    hostname: str
    os_name: str
    local_ip: Optional[str] = None
    default_gateway: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    active_interface: Optional[str] = None
    mac_address: Optional[str] = None
    total_rx_mb: float = 0.0
    total_tx_mb: float = 0.0
    active_connections_count: int = 0


class Device(BaseModel):
    ip: str
    mac: str = "Unknown"
    hostname: Optional[str] = None
    vendor: Optional[str] = "Unknown"
    status: str = "ONLINE"  # "ONLINE", "OFFLINE"
    device_type: str = "Unknown"  # Router, Laptop, Phone, Server, IoT, Unknown
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    open_ports: List[int] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PortInfo(BaseModel):
    port: int
    protocol: str = "TCP"
    state: str = "OPEN"  # OPEN, CLOSED, FILTERED
    service: str = "Unknown"
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


class PortScanReport(BaseModel):
    target_host: str
    resolved_ip: str
    scanned_ports_count: int = 0
    open_ports: List[PortInfo] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=utc_now)


class ActiveConnectionInfo(BaseModel):
    proto: str = "TCP"
    local_address: str
    remote_address: str
    status: str = "ESTABLISHED"
    pid: Optional[int] = None
    process_name: Optional[str] = None


class TrafficSnapshot(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    interface: str
    rx_rate_kbs: float = 0.0
    tx_rate_kbs: float = 0.0
    rx_packets_sec: float = 0.0
    tx_packets_sec: float = 0.0
    active_connections: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    connections: List[ActiveConnectionInfo] = Field(default_factory=list)


class DnsQueryEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=utc_now)
    source_ip: str
    destination_ip: str
    query_name: str
    query_type: str = "A"
    response_code: Optional[str] = None
    latency_ms: Optional[float] = None
    is_anomalous: bool = False
    anomaly_reason: Optional[str] = None


class SecurityEvent(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=utc_now)
    rule_id: str
    title: str
    severity: Severity = Severity.INFO
    category: str = "ANOMALY"  # DISCOVERY, SERVICE, DNS, TRAFFIC, INTERFACE, ANOMALY
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class NetworkTopologyNode(BaseModel):
    id: str
    name: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    node_type: str  # WAN, ROUTER, SWITCH, HOST, SERVER, MOBILE, IOT
    vendor: Optional[str] = None
    status: str = "ONLINE"
    parent_id: Optional[str] = None
    children: List[NetworkTopologyNode] = Field(default_factory=list)

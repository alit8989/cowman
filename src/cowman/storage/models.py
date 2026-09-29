"""SQLAlchemy ORM models for SQLite persistence."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeviceModel(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), unique=True, nullable=False, index=True)
    mac = Column(String(32), nullable=False, index=True)
    hostname = Column(String(256), nullable=True)
    vendor = Column(String(256), nullable=True, default="Unknown")
    status = Column(String(32), nullable=False, default="ONLINE")
    device_type = Column(String(64), nullable=False, default="Unknown")
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    open_ports_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")

    @property
    def open_ports(self) -> List[int]:
        try:
            return json.loads(self.open_ports_json or "[]")
        except Exception:
            return []

    @open_ports.setter
    def open_ports(self, val: List[int]) -> None:
        self.open_ports_json = json.dumps(val or [])

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}

    @metadata_dict.setter
    def metadata_dict(self, val: Dict[str, Any]) -> None:
        self.metadata_json = json.dumps(val or {})


class PortScanModel(Base):
    __tablename__ = "port_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(256), nullable=False, index=True)
    ip = Column(String(64), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), default="TCP")
    state = Column(String(32), default="OPEN")
    service = Column(String(64), default="Unknown")
    banner = Column(Text, nullable=True)
    scanned_at = Column(DateTime, default=utc_now, nullable=False)


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    target_ip = Column(String(64), nullable=True, index=True)
    description = Column(Text, nullable=False)
    details_json = Column(Text, default="{}")

    @property
    def details(self) -> Dict[str, Any]:
        try:
            return json.loads(self.details_json or "{}")
        except Exception:
            return {}

    @details.setter
    def details(self, val: Dict[str, Any]) -> None:
        self.details_json = json.dumps(val or {})


class DnsLogModel(Base):
    __tablename__ = "dns_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    destination_ip = Column(String(64), nullable=False)
    query_name = Column(String(512), nullable=False, index=True)
    query_type = Column(String(16), default="A")
    response_code = Column(String(32), nullable=True)
    is_anomalous = Column(Boolean, default=False, index=True)
    anomaly_reason = Column(String(256), nullable=True)


class TrafficLogModel(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    interface = Column(String(64), nullable=False)
    rx_rate_kbs = Column(Float, default=0.0)
    tx_rate_kbs = Column(Float, default=0.0)
    rx_packets_sec = Column(Float, default=0.0)
    tx_packets_sec = Column(Float, default=0.0)
    active_connections = Column(Integer, default=0)

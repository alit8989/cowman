"""Repository layer for database operations across devices, events, DNS, and traffic."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from cowman.core.models import (
    ActiveConnectionInfo,
    Device,
    DnsQueryEvent,
    PortInfo,
    PortScanReport,
    SecurityEvent,
    TrafficSnapshot,
    utc_now,
)
from cowman.security.severity import Severity
from cowman.storage.database import get_db_session
from cowman.storage.models import (
    DeviceModel,
    DnsLogModel,
    PortScanModel,
    SecurityEventModel,
    TrafficLogModel,
)


class DeviceRepository:
    """Manages persistent device inventory."""

    @staticmethod
    def _model_to_domain(m: DeviceModel) -> Device:
        return Device(
            ip=m.ip,
            mac=m.mac,
            hostname=m.hostname,
            vendor=m.vendor,
            status=m.status,
            device_type=m.device_type,
            first_seen=m.first_seen if m.first_seen.tzinfo else m.first_seen.replace(tzinfo=timezone.utc),
            last_seen=m.last_seen if m.last_seen.tzinfo else m.last_seen.replace(tzinfo=timezone.utc),
            open_ports=m.open_ports,
            metadata=m.metadata_dict,
        )

    @classmethod
    def save_or_update(cls, device: Device, session: Optional[Session] = None) -> Device:
        """Upsert a discovered device."""
        def _execute(s: Session) -> Device:
            existing = s.query(DeviceModel).filter(DeviceModel.ip == device.ip).first()
            now = utc_now()
            if existing:
                if device.mac and device.mac != "Unknown":
                    existing.mac = device.mac
                if device.hostname:
                    existing.hostname = device.hostname
                if device.vendor and device.vendor != "Unknown":
                    existing.vendor = device.vendor
                if device.device_type and device.device_type != "Unknown":
                    existing.device_type = device.device_type
                existing.status = device.status
                existing.last_seen = now
                if device.open_ports:
                    merged_ports = sorted(list(set(existing.open_ports + device.open_ports)))
                    existing.open_ports = merged_ports
                meta = existing.metadata_dict
                meta.update(device.metadata)
                existing.metadata_dict = meta
                s.flush()
                return cls._model_to_domain(existing)
            else:
                new_model = DeviceModel(
                    ip=device.ip,
                    mac=device.mac or "Unknown",
                    hostname=device.hostname,
                    vendor=device.vendor or "Unknown",
                    status=device.status or "ONLINE",
                    device_type=device.device_type or "Unknown",
                    first_seen=device.first_seen or now,
                    last_seen=device.last_seen or now,
                    open_ports=device.open_ports or [],
                    metadata_dict=device.metadata or {},
                )
                s.add(new_model)
                s.flush()
                return cls._model_to_domain(new_model)

        if session:
            return _execute(session)
        with get_db_session() as s:
            return _execute(s)

    @classmethod
    def get_by_ip(cls, ip: str) -> Optional[Device]:
        with get_db_session() as s:
            m = s.query(DeviceModel).filter(DeviceModel.ip == ip).first()
            return cls._model_to_domain(m) if m else None

    @classmethod
    def get_by_mac(cls, mac: str) -> Optional[Device]:
        with get_db_session() as s:
            m = s.query(DeviceModel).filter(DeviceModel.mac == mac).first()
            return cls._model_to_domain(m) if m else None

    @classmethod
    def get_all(cls, status_filter: Optional[str] = None) -> List[Device]:
        with get_db_session() as s:
            query = s.query(DeviceModel)
            if status_filter:
                query = query.filter(DeviceModel.status == status_filter.upper())
            models = query.order_by(DeviceModel.ip).all()
            return [cls._model_to_domain(m) for m in models]

    @classmethod
    def count(cls) -> int:
        with get_db_session() as s:
            return s.query(DeviceModel).count()


class SecurityEventRepository:
    """Manages audit and security events."""

    @staticmethod
    def _model_to_domain(m: SecurityEventModel) -> SecurityEvent:
        ts = m.timestamp if m.timestamp.tzinfo else m.timestamp.replace(tzinfo=timezone.utc)
        return SecurityEvent(
            id=m.id,
            timestamp=ts,
            rule_id=m.rule_id,
            title=m.title,
            severity=Severity.from_string(m.severity),
            category=m.category,
            source_ip=m.source_ip,
            target_ip=m.target_ip,
            description=m.description,
            details=m.details,
        )

    @classmethod
    def add(cls, event: SecurityEvent, session: Optional[Session] = None) -> SecurityEvent:
        def _execute(s: Session) -> SecurityEvent:
            m = SecurityEventModel(
                timestamp=event.timestamp or utc_now(),
                rule_id=event.rule_id,
                title=event.title,
                severity=event.severity.value,
                category=event.category,
                source_ip=event.source_ip,
                target_ip=event.target_ip,
                description=event.description,
                details_json=json.dumps(event.details or {}),
            )
            s.add(m)
            s.flush()
            return cls._model_to_domain(m)

        if session:
            return _execute(session)
        with get_db_session() as s:
            return _execute(s)

    @classmethod
    def get_events(
        cls,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        host: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        with get_db_session() as s:
            q = s.query(SecurityEventModel)
            if severity:
                q = q.filter(SecurityEventModel.severity == severity.upper())
            if event_type:
                q = q.filter(
                    or_(
                        SecurityEventModel.rule_id.ilike(f"%{event_type}%"),
                        SecurityEventModel.category.ilike(f"%{event_type}%"),
                    )
                )
            if host:
                q = q.filter(
                    or_(
                        SecurityEventModel.source_ip == host,
                        SecurityEventModel.target_ip == host,
                        SecurityEventModel.description.ilike(f"%{host}%"),
                    )
                )
            if start_time:
                # Ensure naive UTC for SQLite comparison if tz-aware
                st = start_time.replace(tzinfo=None) if start_time.tzinfo else start_time
                q = q.filter(SecurityEventModel.timestamp >= st)
            if end_time:
                et = end_time.replace(tzinfo=None) if end_time.tzinfo else end_time
                q = q.filter(SecurityEventModel.timestamp <= et)

            q = q.order_by(desc(SecurityEventModel.timestamp)).limit(limit)
            return [cls._model_to_domain(m) for m in q.all()]

    @classmethod
    def count(cls, severity: Optional[str] = None) -> int:
        with get_db_session() as s:
            q = s.query(SecurityEventModel)
            if severity:
                q = q.filter(SecurityEventModel.severity == severity.upper())
            return q.count()


class PortRepository:
    """Manages port scan results."""

    @classmethod
    def save_scan(cls, report: PortScanReport) -> None:
        with get_db_session() as s:
            now = report.timestamp or utc_now()
            for p in report.open_ports:
                m = PortScanModel(
                    host=report.target_host,
                    ip=report.resolved_ip,
                    port=p.port,
                    protocol=p.protocol,
                    state=p.state,
                    service=p.service,
                    banner=p.banner,
                    scanned_at=now,
                )
                s.add(m)

    @classmethod
    def get_open_ports_for_host(cls, host: str) -> List[PortInfo]:
        with get_db_session() as s:
            records = (
                s.query(PortScanModel)
                .filter(or_(PortScanModel.host == host, PortScanModel.ip == host))
                .order_by(PortScanModel.port)
                .all()
            )
            # Deduplicate by port
            seen = {}
            for r in records:
                seen[r.port] = PortInfo(
                    port=r.port,
                    protocol=r.protocol,
                    state=r.state,
                    service=r.service,
                    banner=r.banner,
                )
            return list(seen.values())


class DnsLogRepository:
    """Manages captured DNS query records."""

    @classmethod
    def log(cls, query: DnsQueryEvent) -> DnsQueryEvent:
        with get_db_session() as s:
            m = DnsLogModel(
                timestamp=query.timestamp or utc_now(),
                source_ip=query.source_ip,
                destination_ip=query.destination_ip,
                query_name=query.query_name,
                query_type=query.query_type,
                response_code=query.response_code,
                is_anomalous=query.is_anomalous,
                anomaly_reason=query.anomaly_reason,
            )
            s.add(m)
            s.flush()
            query.id = m.id
            return query

    @classmethod
    def get_logs(cls, limit: int = 100, anomalous_only: bool = False) -> List[DnsQueryEvent]:
        with get_db_session() as s:
            q = s.query(DnsLogModel)
            if anomalous_only:
                q = q.filter(DnsLogModel.is_anomalous.is_(True))
            q = q.order_by(desc(DnsLogModel.timestamp)).limit(limit)
            results = []
            for m in q.all():
                ts = m.timestamp if m.timestamp.tzinfo else m.timestamp.replace(tzinfo=timezone.utc)
                results.append(
                    DnsQueryEvent(
                        id=m.id,
                        timestamp=ts,
                        source_ip=m.source_ip,
                        destination_ip=m.destination_ip,
                        query_name=m.query_name,
                        query_type=m.query_type,
                        response_code=m.response_code,
                        is_anomalous=m.is_anomalous,
                        anomaly_reason=m.anomaly_reason,
                    )
                )
            return results


class TrafficLogRepository:
    """Manages bandwidth and interface traffic samples."""

    @classmethod
    def log(cls, snap: TrafficSnapshot) -> None:
        with get_db_session() as s:
            m = TrafficLogModel(
                timestamp=snap.timestamp or utc_now(),
                interface=snap.interface,
                rx_rate_kbs=snap.rx_rate_kbs,
                tx_rate_kbs=snap.tx_rate_kbs,
                rx_packets_sec=snap.rx_packets_sec,
                tx_packets_sec=snap.tx_packets_sec,
                active_connections=snap.active_connections,
            )
            s.add(m)

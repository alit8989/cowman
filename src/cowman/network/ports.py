"""Authorized port and service detection engine."""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Callable, Dict, List, Optional, Tuple

from cowman.core.config import get_config
from cowman.core.logger import get_logger
from cowman.core.models import PortInfo, PortScanReport, utc_now
from cowman.storage.repository import DeviceRepository, PortRepository

logger = get_logger("ports")

COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9092: "Kafka",
    27017: "MongoDB",
}


async def grab_service_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
    """Safely and passively probe service banner without destructive payloads."""
    try:
        if port in (80, 8080, 8000, 8443):
            # Send standard benign HTTP HEAD request
            writer.write(b"HEAD / HTTP/1.0\r\nUser-Agent: COWMAN-Auditor/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=0.8)
            text = data.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            if text:
                return text.splitlines()[0][:60].strip()

        # For SSH, FTP, SMTP, banner is sent on connect
        data = await asyncio.wait_for(reader.read(256), timeout=0.8)
        text = data.decode("utf-8", errors="ignore").strip()
        if text:
            # Clean non-printable characters
            clean = " ".join(text.splitlines())[:80].strip()
            return clean
    except Exception:
        pass
    return None


async def probe_port(
    ip: str,
    port: int,
    timeout: float = 0.8,
) -> Optional[PortInfo]:
    """Probe an individual TCP port on the target host."""
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.perf_counter() - t0) * 1000.0

        banner = await grab_service_banner(reader, writer, port)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        service_name = COMMON_SERVICES.get(port, "Unknown")
        return PortInfo(
            port=port,
            protocol="TCP",
            state="OPEN",
            service=service_name,
            banner=banner,
            latency_ms=round(latency, 2),
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


class PortAnalyzer:
    """Orchestrates authorized port scans against a specified target host."""

    def __init__(
        self,
        target_host: str,
        ports: Optional[List[int]] = None,
        timeout: Optional[float] = None,
        concurrency: Optional[int] = None,
    ):
        self.config = get_config()
        self.target_host = target_host.strip()
        self.ports = ports or self.config.port_scan.default_ports
        self.timeout = timeout or self.config.port_scan.timeout
        self.concurrency = concurrency or self.config.port_scan.concurrency

    async def scan(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> PortScanReport:
        """Scan authorized target ports concurrently."""
        t_start = time.perf_counter()

        # Resolve target host to IP
        loop = asyncio.get_running_loop()
        try:
            resolved_ip = await loop.run_in_executor(None, socket.gethostbyname, self.target_host)
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve host '{self.target_host}': {e}")

        semaphore = asyncio.Semaphore(self.concurrency)
        total_ports = len(self.ports)
        completed = 0
        open_ports: List[PortInfo] = []

        async def _scan_worker(p: int):
            nonlocal completed
            async with semaphore:
                res = await probe_port(resolved_ip, p, timeout=self.timeout)
                completed += 1
                if progress_callback and completed % 5 == 0:
                    progress_callback(completed, total_ports)
                if res is not None:
                    open_ports.append(res)

        tasks = [_scan_worker(p) for p in self.ports]
        await asyncio.gather(*tasks)

        open_ports.sort(key=lambda x: x.port)
        duration = time.perf_counter() - t_start

        report = PortScanReport(
            target_host=self.target_host,
            resolved_ip=resolved_ip,
            scanned_ports_count=total_ports,
            open_ports=open_ports,
            scan_duration_seconds=round(duration, 3),
            timestamp=utc_now(),
        )

        # Save scan report to database
        PortRepository.save_scan(report)

        # Update device inventory if IP exists in DB
        device = DeviceRepository.get_by_ip(resolved_ip)
        if device:
            device.open_ports = [p.port for p in open_ports]
            DeviceRepository.save_or_update(device)

        return report

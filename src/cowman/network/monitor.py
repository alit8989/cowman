"""Real-time network traffic and connection monitoring engine."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time
from typing import AsyncGenerator, Dict, List, Optional
import psutil

from cowman.core.config import get_config
from cowman.core.logger import get_logger
from cowman.core.models import ActiveConnectionInfo, TrafficSnapshot, utc_now
from cowman.network.interfaces import get_primary_interface
from cowman.storage.repository import TrafficLogRepository

logger = get_logger("monitor")


def get_process_name(pid: Optional[int]) -> Optional[str]:
    """Retrieve process name from PID safely."""
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except Exception:
        return None


class TrafficMonitor:
    """Monitors live RX/TX rates, packet counts, protocol distribution, and active connections."""

    def __init__(self, interface: Optional[str] = None, interval: float = 1.0):
        self.config = get_config()
        self.interval = max(0.2, interval or self.config.monitor.interval)
        self.interface_name = interface or self.config.general.interface

        if not self.interface_name:
            primary = get_primary_interface()
            if primary:
                self.interface_name = primary.name

        self._last_time = time.perf_counter()
        self._last_counters = self._get_interface_io()

    def _get_interface_io(self):
        """Retrieve IO counters for target interface or aggregate if none specified."""
        pernic = psutil.net_io_counters(pernic=True)
        if self.interface_name and self.interface_name in pernic:
            return pernic[self.interface_name]
        return psutil.net_io_counters()

    def sample(self) -> TrafficSnapshot:
        """Sample network statistics and compute transfer rates over the elapsed interval."""
        now_perf = time.perf_counter()
        dt = max(now_perf - self._last_time, 0.001)
        current_io = self._get_interface_io()

        rx_bytes = current_io.bytes_recv - self._last_counters.bytes_recv
        tx_bytes = current_io.bytes_sent - self._last_counters.bytes_sent
        rx_pkts = current_io.packets_recv - self._last_counters.packets_recv
        tx_pkts = current_io.packets_sent - self._last_counters.packets_sent

        # Protect against counter resets / interface restarts
        if rx_bytes < 0:
            rx_bytes = 0
        if tx_bytes < 0:
            tx_bytes = 0
        if rx_pkts < 0:
            rx_pkts = 0
        if tx_pkts < 0:
            tx_pkts = 0

        rx_rate_kbs = round((rx_bytes / 1024.0) / dt, 2)
        tx_rate_kbs = round((tx_bytes / 1024.0) / dt, 2)
        rx_packets_sec = round(rx_pkts / dt, 1)
        tx_packets_sec = round(tx_pkts / dt, 1)

        self._last_time = now_perf
        self._last_counters = current_io

        # Collect active connections
        active_conns: List[ActiveConnectionInfo] = []
        tcp_count = 0
        udp_count = 0

        try:
            raw_conns = psutil.net_connections(kind="inet")
            for c in raw_conns:
                proto = "TCP" if c.type == psutil.SOCK_STREAM else "UDP"
                if proto == "TCP":
                    tcp_count += 1
                else:
                    udp_count += 1

                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                status = c.status if c.status else "NONE"
                pname = get_process_name(c.pid)

                active_conns.append(
                    ActiveConnectionInfo(
                        proto=proto,
                        local_address=laddr,
                        remote_address=raddr,
                        status=status,
                        pid=c.pid,
                        process_name=pname,
                    )
                )
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Access denied when reading system socket tables.")
        except Exception as e:
            logger.debug(f"Error inspecting network connections: {e}")

        snapshot = TrafficSnapshot(
            timestamp=utc_now(),
            interface=self.interface_name or "All",
            rx_rate_kbs=rx_rate_kbs,
            tx_rate_kbs=tx_rate_kbs,
            rx_packets_sec=rx_packets_sec,
            tx_packets_sec=tx_packets_sec,
            active_connections=len(active_conns),
            tcp_count=tcp_count,
            udp_count=udp_count,
            connections=active_conns,
        )

        return snapshot

    async def stream(self, max_samples: Optional[int] = None) -> AsyncGenerator[TrafficSnapshot, None]:
        """Asynchronously stream traffic snapshots at the configured interval."""
        count = 0
        while True:
            await asyncio.sleep(self.interval)
            snap = self.sample()
            TrafficLogRepository.log(snap)
            yield snap
            count += 1
            if max_samples is not None and count >= max_samples:
                break

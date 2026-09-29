"""Network interface enumeration, routing, and DNS configuration detection."""

from __future__ import annotations

import os
import platform
import socket
import subprocess
from typing import Dict, List, Optional, Tuple
import psutil

from cowman.core.models import NetworkInterface, SystemNetworkOverview
from cowman.utils.platform import is_windows, is_linux, is_macos


def get_default_gateway_and_interface() -> Tuple[Optional[str], Optional[str]]:
    """Determine default gateway IP and the associated network interface name."""
    # Method 1: Try Scapy routing table if available
    try:
        from scapy.all import conf
        # conf.route.route("8.8.8.8") returns (interface, output_ip, gateway_ip)
        res = conf.route.route("8.8.8.8")
        if res and len(res) >= 3:
            iface_name = res[0]
            gateway_ip = res[2]
            if gateway_ip and gateway_ip != "0.0.0.0":
                return gateway_ip, iface_name
    except Exception:
        pass

    # Method 2: System socket connection check to find local route
    chosen_iface = None
    local_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    if local_ip:
        # Match local_ip to interface
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    chosen_iface = name
                    break
            if chosen_iface:
                break

    # Method 3: OS command fallback for gateway
    gateway = None
    if is_windows():
        try:
            output = subprocess.check_output("netsh interface ip show config", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "Default Gateway" in line or "기본 게이트웨이" in line or "デフォルト ゲートウェイ" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        gw = parts[1].strip()
                        if gw and gw != "0.0.0.0":
                            gateway = gw
                            break
        except Exception:
            pass
    elif is_linux():
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[1] == "00000000":
                        # Destination is 0.0.0.0 (default)
                        gw_hex = fields[2]
                        gateway = socket.inet_ntoa(bytes.fromhex(gw_hex)[::-1])
                        if not chosen_iface:
                            chosen_iface = fields[0]
                        break
        except Exception:
            pass

    return gateway, chosen_iface


def get_dns_servers() -> List[str]:
    """Retrieve active system DNS servers."""
    servers: List[str] = []

    # Try Scapy conf nameservers
    try:
        from scapy.all import conf
        for ns in conf.nameservers:
            if ns and ns not in servers and ns != "0.0.0.0":
                servers.append(str(ns))
    except Exception:
        pass

    if servers:
        return servers

    if is_linux() or is_macos():
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] not in servers:
                            servers.append(parts[1])
        except Exception:
            pass
    elif is_windows():
        try:
            output = subprocess.check_output("ipconfig /all", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                if "DNS Servers" in line or "DNS 서버" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if ip and ip not in servers and not ip.startswith("fe80"):
                            servers.append(ip)
        except Exception:
            pass

    return servers


def get_all_interfaces() -> List[NetworkInterface]:
    """Retrieve full details of all system network interfaces."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)

    results: List[NetworkInterface] = []

    for name, addr_list in addrs.items():
        ip = None
        netmask = None
        broadcast = None
        mac = None

        for a in addr_list:
            # IPv4
            if a.family == socket.AF_INET:
                ip = a.address
                netmask = a.netmask
                broadcast = a.broadcast
            # MAC Address
            elif (
                (hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK)
                or (is_windows() and getattr(a, "family", None) == -1)
                or ("link" in str(getattr(a, "family", "")).lower())
            ):
                if a.address and len(a.address) in (12, 17):
                    mac = a.address

        st = stats.get(name)
        is_up = st.isup if st else False
        speed = st.speed if st else 0
        mtu = st.mtu if st else 1500

        io = io_counters.get(name)
        rx_b = io.bytes_recv if io else 0
        tx_b = io.bytes_sent if io else 0
        rx_p = io.packets_recv if io else 0
        tx_p = io.packets_sent if io else 0

        results.append(
            NetworkInterface(
                name=name,
                ip=ip,
                netmask=netmask,
                broadcast=broadcast,
                mac=mac,
                is_up=is_up,
                speed_mbps=speed,
                mtu=mtu,
                rx_bytes=rx_b,
                tx_bytes=tx_b,
                rx_packets=rx_p,
                tx_packets=tx_p,
            )
        )

    # Sort UP interfaces with IPs first
    results.sort(key=lambda x: (not x.is_up, x.ip is None, x.name))
    return results


def get_primary_interface() -> Optional[NetworkInterface]:
    """Get the primary active network interface connected to the network."""
    interfaces = get_all_interfaces()
    gateway, gw_iface = get_default_gateway_and_interface()

    # Try matching gw_iface
    if gw_iface:
        for iface in interfaces:
            if iface.name == gw_iface or (iface.ip and gw_iface == iface.ip):
                return iface

    # Otherwise find first UP interface with non-loopback IPv4
    for iface in interfaces:
        if iface.is_up and iface.ip and not iface.ip.startswith("127."):
            return iface

    return interfaces[0] if interfaces else None


def get_system_network_overview() -> SystemNetworkOverview:
    """Build unified system overview for CLI display and reports."""
    primary = get_primary_interface()
    gateway, _ = get_default_gateway_and_interface()
    dns = get_dns_servers()

    try:
        conns = len(psutil.net_connections(kind="inet"))
    except Exception:
        conns = 0

    io_tot = psutil.net_io_counters()

    return SystemNetworkOverview(
        hostname=socket.gethostname(),
        os_name=platform.platform(terse=True),
        local_ip=primary.ip if primary else None,
        default_gateway=gateway,
        dns_servers=dns,
        active_interface=primary.name if primary else None,
        mac_address=primary.mac if primary else None,
        total_rx_mb=round((io_tot.bytes_recv / (1024 * 1024)), 2) if io_tot else 0.0,
        total_tx_mb=round((io_tot.bytes_sent / (1024 * 1024)), 2) if io_tot else 0.0,
        active_connections_count=conns,
    )

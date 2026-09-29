"""Authorized local network device discovery engine."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import subprocess
from typing import Callable, Dict, List, Optional, Set, Tuple

from cowman.core.config import get_config
from cowman.core.logger import get_logger
from cowman.core.models import Device, utc_now
from cowman.network.interfaces import (
    get_all_interfaces,
    get_default_gateway_and_interface,
    get_primary_interface,
)
from cowman.network.oui import lookup_vendor, normalize_mac
from cowman.storage.repository import DeviceRepository
from cowman.utils.platform import is_windows

logger = get_logger("scanner")


def calculate_subnet(ip: str, netmask: Optional[str]) -> ipaddress.IPv4Network:
    """Calculate IPv4 network from IP and netmask, capped at /24 for safe local scanning."""
    if not netmask or netmask in ["0.0.0.0", "255.255.255.255"]:
        netmask = "255.255.255.0"
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        # Prevent accidentally scanning large /8 or /16 networks by bounding to /24
        if network.prefixlen < 24:
            ip_obj = ipaddress.IPv4Address(ip)
            c_block = f"{ip_obj.exploded.rsplit('.', 1)[0]}.0/24"
            return ipaddress.IPv4Network(c_block, strict=False)
        return network
    except Exception:
        ip_parts = ip.split(".")
        return ipaddress.IPv4Network(f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24", strict=False)


def parse_arp_table() -> Dict[str, str]:
    """Parse operating system ARP table into {ip: mac} dictionary."""
    arp_entries: Dict[str, str] = {}
    try:
        if is_windows():
            output = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
            # Lines like: 192.168.1.1   00-11-22-33-44-55   dynamic
            pattern = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F\-]{17})\s+([a-zA-Z]+)")
            for match in pattern.finditer(output):
                ip_str = match.group(1)
                mac_str = match.group(2).replace("-", ":")
                entry_type = match.group(3).lower()
                if not ip_str.endswith(".255") and not ip_str.startswith("224.") and entry_type != "invalid":
                    arp_entries[ip_str] = normalize_mac(mac_str)
        else:
            # Linux / macOS
            try:
                output = subprocess.check_output("arp -an", shell=True, text=True, stderr=subprocess.DEVNULL)
                pattern = re.compile(r"\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\)\s+at\s+([0-9a-fA-F:]{17})")
                for match in pattern.finditer(output):
                    ip_str = match.group(1)
                    mac_str = match.group(2)
                    arp_entries[ip_str] = normalize_mac(mac_str)
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Failed to read system ARP table: {e}")

    return arp_entries


async def resolve_hostname(ip: str) -> Optional[str]:
    """Asynchronously perform reverse DNS lookup for an IP address."""
    loop = asyncio.get_running_loop()
    try:
        name_info = await loop.run_in_executor(None, socket.getnameinfo, (ip, 0), socket.NI_NAMEREQD)
        host = name_info[0]
        if host and host != ip:
            return host
    except Exception:
        pass

    try:
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        if host and host != ip:
            return host
    except Exception:
        pass

    return None


async def probe_host_tcp(ip: str, port: int = 80, timeout: float = 0.3) -> bool:
    """Send a quick non-intrusive TCP connection check to trigger host ARP entry."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def sweep_subnet(network: ipaddress.IPv4Network, concurrency: int = 64) -> None:
    """Concurrently probe hosts on the subnet to update local ARP cache."""
    hosts = [str(h) for h in network.hosts()]
    semaphore = asyncio.Semaphore(concurrency)

    async def _worker(ip: str):
        async with semaphore:
            # Check common service ports
            for p in (80, 443, 22, 135, 445):
                if await probe_host_tcp(ip, port=p, timeout=0.2):
                    break

    await asyncio.gather(*[_worker(h) for h in hosts], return_exceptions=True)


def scan_scapy_arp(network_cidr: str, iface: Optional[str] = None, timeout: float = 1.5) -> Dict[str, str]:
    """Execute Scapy ARP broadcast ping if supported and permitted."""
    results: Dict[str, str] = {}
    try:
        from scapy.all import ARP, Ether, srp
        kwargs = {"timeout": timeout, "verbose": 0}
        if iface:
            kwargs["iface"] = iface

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr)
        ans, _ = srp(pkt, **kwargs)
        for _, rcv in ans:
            ip = rcv.psrc
            mac = normalize_mac(rcv.hwsrc)
            results[ip] = mac
    except Exception as e:
        logger.debug(f"Scapy ARP scan not possible or unprivileged: {e}")

    return results


def guess_device_type(vendor: Optional[str], hostname: Optional[str], is_gateway: bool) -> str:
    """Heuristically categorize device role."""
    if is_gateway:
        return "Router"

    text = f"{vendor or ''} {hostname or ''}".lower()

    if any(k in text for k in ["router", "gateway", "tp-link", "netgear", "ubiquiti", "asus", "linksys", "cisco"]):
        return "Router"
    if any(k in text for k in ["iphone", "android", "galaxy", "pixel", "mobile", "phone"]):
        return "Phone"
    if any(k in text for k in ["server", "synology", "qnap", "nas", "truenas", "ubuntu-server"]):
        return "Server"
    if any(k in text for k in ["esp8266", "esp32", "espressif", "raspberry", "hue", "sonos", "printer", "cam", "tv"]):
        return "IoT"
    if any(k in text for k in ["macbook", "laptop", "thinkpad", "dell", "hp", "intel", "desktop", "surface"]):
        return "Laptop"

    return "Unknown"


class NetworkScanner:
    """High-level discovery orchestrator for authorized local networks."""

    def __init__(self, interface: Optional[str] = None, target_cidr: Optional[str] = None):
        self.config = get_config()
        self.interface_name = interface or self.config.general.interface
        self.target_cidr = target_cidr or self.config.discovery.subnet_override

    async def discover(self, progress_callback: Optional[Callable[[str], None]] = None) -> List[Device]:
        """Perform comprehensive authorized network discovery."""
        if progress_callback:
            progress_callback("Detecting network topology and active interfaces...")

        primary = get_primary_interface()
        gateway_ip, gw_iface = get_default_gateway_and_interface()

        if self.interface_name:
            for iface in get_all_interfaces():
                if iface.name == self.interface_name and iface.ip:
                    primary = iface
                    break

        if not primary or not primary.ip:
            logger.warning("No active network interface with an IPv4 address detected.")
            return []

        # Determine target network
        if self.target_cidr:
            try:
                network = ipaddress.IPv4Network(self.target_cidr, strict=False)
            except Exception:
                network = calculate_subnet(primary.ip, primary.netmask)
        else:
            network = calculate_subnet(primary.ip, primary.netmask)

        cidr_str = str(network)
        if progress_callback:
            progress_callback(f"Scanning authorized subnet {cidr_str} via {primary.name}...")

        # Step 1: Scapy ARP scan (if permissions allow)
        discovered_map: Dict[str, str] = {}
        scapy_results = scan_scapy_arp(
            cidr_str,
            iface=self.interface_name or primary.name,
            timeout=self.config.discovery.timeout,
        )
        discovered_map.update(scapy_results)

        # Step 2: Concurrently probe hosts on the subnet to populate system ARP cache
        if progress_callback:
            progress_callback(f"Probing {network.num_addresses - 2} potential hosts on {cidr_str}...")
        await sweep_subnet(network, concurrency=self.config.discovery.max_workers)

        # Step 3: Harvest system ARP table
        arp_entries = parse_arp_table()
        for ip, mac in arp_entries.items():
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj in network:
                    discovered_map[ip] = mac
            except Exception:
                continue

        # Step 4: Ensure local host itself is represented
        if primary.ip and primary.ip not in discovered_map:
            discovered_map[primary.ip] = normalize_mac(primary.mac or "00:00:00:00:00:00")

        # Step 5: Ensure gateway is represented
        if gateway_ip:
            try:
                gw_obj = ipaddress.IPv4Address(gateway_ip)
                if gw_obj in network and gateway_ip not in discovered_map:
                    discovered_map[gateway_ip] = "Unknown"
            except Exception:
                pass

        # Step 6: Resolve hostnames, vendors, and types
        if progress_callback:
            progress_callback(f"Resolving hostnames and OUI vendors for {len(discovered_map)} devices...")

        devices: List[Device] = []
        now = utc_now()

        async def _enrich_device(ip: str, mac: str) -> Device:
            hostname = await resolve_hostname(ip)
            if not hostname and ip == primary.ip:
                hostname = socket.gethostname()
            elif not hostname and ip == gateway_ip:
                hostname = "gateway.router"

            vendor = lookup_vendor(mac)
            is_gw = (ip == gateway_ip)
            dtype = guess_device_type(vendor, hostname, is_gw)

            device = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                status="ONLINE",
                device_type=dtype,
                first_seen=now,
                last_seen=now,
            )

            # Check if newly discovered or status changed
            existing = DeviceRepository.get_by_ip(ip)
            is_new = (existing is None)
            old_status = existing.status if existing else None

            # Persist device to database
            saved = DeviceRepository.save_or_update(device)

            from cowman.security.engine import get_security_engine
            get_security_engine().process_device_discovery(saved, is_new=is_new, old_status=old_status)
            return saved

        enrich_tasks = [_enrich_device(ip, mac) for ip, mac in discovered_map.items()]
        devices = await asyncio.gather(*enrich_tasks)

        # Sort: Gateway first, then Local IP, then by IP numerically
        def _sort_key(d: Device):
            is_gw = 0 if d.ip == gateway_ip else 1
            is_local = 0 if d.ip == (primary.ip if primary else "") else 1
            try:
                num = int(ipaddress.IPv4Address(d.ip))
            except Exception:
                num = 0
            return (is_gw, is_local, num)

        devices.sort(key=_sort_key)
        return devices

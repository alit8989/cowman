"""Tests for local network device discovery."""

import ipaddress
import pytest

from cowman.network.scanner import (
    calculate_subnet,
    guess_device_type,
    NetworkScanner,
)


def test_calculate_subnet():
    sub1 = calculate_subnet("192.168.1.50", "255.255.255.0")
    assert str(sub1) == "192.168.1.0/24"

    # Subnet bounded at /24
    sub2 = calculate_subnet("10.0.5.20", "255.0.0.0")
    assert sub2.prefixlen == 24
    assert str(sub2) == "10.0.5.0/24"


def test_guess_device_type():
    assert guess_device_type("Cisco", "core-gw", is_gateway=True) == "Router"
    assert guess_device_type("Apple", "John's iPhone", is_gateway=False) == "Phone"
    assert guess_device_type("Synology", "diskstation", is_gateway=False) == "Server"
    assert guess_device_type("Espressif", "esp32-sensor", is_gateway=False) == "IoT"
    assert guess_device_type("Dell", "laptop-xps", is_gateway=False) == "Laptop"
    assert guess_device_type("Unknown", None, is_gateway=False) == "Unknown"


@pytest.mark.asyncio
async def test_network_scanner_mock(monkeypatch):
    from cowman.core.models import NetworkInterface

    # Mock primary interface
    primary_mock = NetworkInterface(
        name="eth0",
        ip="192.168.1.100",
        netmask="255.255.255.0",
        mac="00:11:22:33:44:55",
        is_up=True,
    )
    monkeypatch.setattr("cowman.network.scanner.get_primary_interface", lambda: primary_mock)
    monkeypatch.setattr("cowman.network.scanner.get_default_gateway_and_interface", lambda: ("192.168.1.1", "eth0"))
    monkeypatch.setattr("cowman.network.scanner.scan_scapy_arp", lambda cidr, iface=None, timeout=1.0: {})
    monkeypatch.setattr(
        "cowman.network.scanner.parse_arp_table",
        lambda: {"192.168.1.1": "00:09:5B:12:34:56", "192.168.1.50": "00:03:93:AA:BB:CC"},
    )

    async def mock_sweep(network, concurrency=64):
        pass

    monkeypatch.setattr("cowman.network.scanner.sweep_subnet", mock_sweep)

    scanner = NetworkScanner()
    devices = await scanner.discover()

    assert len(devices) >= 2
    ips = [d.ip for d in devices]
    assert "192.168.1.1" in ips
    assert "192.168.1.100" in ips

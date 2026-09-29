"""Tests for port analyzer and service detection."""

import asyncio
import pytest

from cowman.cli.commands.ports import parse_port_list
from cowman.network.ports import COMMON_SERVICES, PortAnalyzer, probe_port


def test_parse_port_list():
    assert parse_port_list("80,443") == [80, 443]
    assert parse_port_list("20-25") == [20, 21, 22, 23, 24, 25]
    assert parse_port_list("80, 8080, 80-82") == [80, 81, 82, 8080]
    assert parse_port_list(None) is None
    assert parse_port_list("invalid,xyz") is None


@pytest.mark.asyncio
async def test_port_analyzer_mock_scan(monkeypatch):
    from cowman.core.models import PortInfo

    # Mock probe_port to return simulated ports
    async def mock_probe_port(ip, port, timeout=0.8):
        if port in (80, 443):
            return PortInfo(
                port=port,
                protocol="TCP",
                state="OPEN",
                service=COMMON_SERVICES.get(port, "Unknown"),
                latency_ms=1.5,
            )
        return None

    monkeypatch.setattr("cowman.network.ports.probe_port", mock_probe_port)

    analyzer = PortAnalyzer(target_host="127.0.0.1", ports=[80, 443, 8080])
    report = await analyzer.scan()

    assert report.target_host == "127.0.0.1"
    assert report.scanned_ports_count == 3
    assert len(report.open_ports) == 2
    assert report.open_ports[0].port == 80
    assert report.open_ports[1].port == 443

"""Tests for network topology tree and diagram generation."""

import pytest
from cowman.core.models import Device
from cowman.network.topology import TopologyGenerator


def test_topology_generator():
    devices = [
        Device(ip="192.168.1.1", vendor="TP-Link", device_type="Router"),
        Device(ip="192.168.1.20", hostname="work-laptop", vendor="Dell", device_type="Laptop"),
        Device(ip="192.168.1.30", hostname="backup-nas", vendor="Synology", device_type="Server"),
    ]

    root = TopologyGenerator.build_topology(devices)
    assert root.id == "wan"
    assert len(root.children) == 1

    router = root.children[0]
    assert router.node_type == "ROUTER"
    assert len(router.children) >= 2

    # ASCII rendering
    ascii_out = TopologyGenerator.render_ascii_diagram(root)
    assert "INTERNET" in ascii_out
    assert "ROUTER" in ascii_out

    # Rich Tree rendering
    tree_out = TopologyGenerator.render_rich_tree(root)
    assert tree_out is not None

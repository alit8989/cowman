"""Tests for OUI MAC vendor lookup."""

import pytest
from cowman.network.oui import lookup_vendor, normalize_mac


def test_normalize_mac():
    assert normalize_mac("001122334455") == "00:11:22:33:44:55"
    assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert normalize_mac("00.11.22.33.44.55") == "00:11:22:33:44:55"


def test_lookup_vendor():
    # Apple
    assert lookup_vendor("00:03:93:11:22:33") == "Apple"
    assert lookup_vendor("04:26:65:AA:BB:CC") == "Apple"

    # Raspberry Pi
    assert lookup_vendor("B8:27:EB:12:34:56") == "Raspberry Pi"

    # Intel
    assert lookup_vendor("00:02:B3:01:02:03") == "Intel"

    # Espressif
    assert lookup_vendor("24:0A:C4:00:11:22") == "Espressif"

    # Cisco
    assert lookup_vendor("00:00:0C:12:34:56") == "Cisco"

    # Unknown
    assert lookup_vendor("00:00:00:00:00:00") == "Unknown"
    assert lookup_vendor("Unknown") == "Unknown"

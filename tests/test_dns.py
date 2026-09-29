"""Tests for DNS analysis, entropy calculations, and anomaly detection."""

import pytest
from cowman.core.config import CowmanConfig
from cowman.network.dns_sniffer import calculate_entropy, inspect_dns_anomaly


def test_calculate_entropy():
    # Low entropy (repetitive)
    ent_low = calculate_entropy("aaaaaaaaaa")
    assert ent_low == 0.0

    # Normal domain
    ent_normal = calculate_entropy("google")
    assert 1.5 <= ent_normal <= 3.0

    # High entropy (random generated string)
    ent_high = calculate_entropy("q8z9w4m1x7b2p5k3")
    assert ent_high >= 3.8


def test_inspect_dns_anomaly():
    cfg = CowmanConfig()

    # Normal domain
    is_anomaly, reason = inspect_dns_anomaly("api.github.com", config=cfg)
    assert is_anomaly is False
    assert reason is None

    # Excessively long domain (tunneling indicator)
    long_domain = "a" * 50 + ".example.com"
    is_anomaly, reason = inspect_dns_anomaly(long_domain, config=cfg)
    assert is_anomaly is True
    assert "length" in reason.lower()

    # DGA high entropy domain
    dga_domain = "x9z8q1m4w7k2p5v3b0c.malicious-site.cc"
    is_anomaly, reason = inspect_dns_anomaly(dga_domain, config=cfg)
    assert is_anomaly is True
    assert "entropy" in reason.lower()

"""Tests for security severity levels and formatting."""

import pytest
from cowman.security.severity import Severity


def test_severity_levels():
    assert Severity.INFO.level < Severity.LOW.level
    assert Severity.LOW.level < Severity.MEDIUM.level
    assert Severity.MEDIUM.level < Severity.HIGH.level
    assert Severity.HIGH.level < Severity.CRITICAL.level


def test_severity_from_string():
    assert Severity.from_string("INFO") == Severity.INFO
    assert Severity.from_string("critical") == Severity.CRITICAL
    assert Severity.from_string("medium") == Severity.MEDIUM
    assert Severity.from_string("unknown_string") == Severity.INFO


def test_severity_properties():
    for s in Severity:
        assert isinstance(s.color, str)
        assert isinstance(s.badge, str)
        assert isinstance(s.icon, str)
        assert len(s.badge) > 0

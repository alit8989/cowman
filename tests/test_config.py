"""Tests for configuration parsing and loading."""

from pathlib import Path
import tempfile
import pytest

from cowman.core.config import CowmanConfig, find_config_file, load_config


def test_default_config():
    cfg = CowmanConfig()
    assert cfg.general.interface == ""
    assert cfg.general.log_level == "INFO"
    assert cfg.discovery.timeout == 1.5
    assert cfg.port_scan.concurrency == 100
    assert 80 in cfg.port_scan.default_ports
    assert cfg.ui.theme == "dark_soc"
    assert cfg.resolved_database_path() is not None


def test_load_custom_config(tmp_path):
    config_file = tmp_path / "custom_config.toml"
    config_content = """
    [general]
    interface = "eth1"
    log_level = "DEBUG"

    [discovery]
    timeout = 2.5
    subnet_override = "10.0.0.0/24"

    [security]
    bandwidth_spike_mb = 100.0
    """
    config_file.write_text(config_content, encoding="utf-8")

    cfg = load_config(str(config_file))
    assert cfg.general.interface == "eth1"
    assert cfg.general.log_level == "DEBUG"
    assert cfg.discovery.timeout == 2.5
    assert cfg.discovery.subnet_override == "10.0.0.0/24"
    assert cfg.security.bandwidth_spike_mb == 100.0


def test_find_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        find_config_file("/non/existent/path/to/config.toml")

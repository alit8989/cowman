"""Tests for Typer CLI commands using CliRunner."""

import pytest
from typer.testing import CliRunner
from cowman.cli.app import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "COWMAN version" in result.stdout


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "COWMAN" in result.stdout
    assert "info" in result.stdout
    assert "interfaces" in result.stdout
    assert "discover" in result.stdout
    assert "ports" in result.stdout
    assert "monitor" in result.stdout
    assert "dns" in result.stdout
    assert "topology" in result.stdout
    assert "events" in result.stdout
    assert "replay" in result.stdout
    assert "report" in result.stdout


def test_cli_info():
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "Network Host Telemetry" in result.stdout


def test_cli_interfaces():
    result = runner.invoke(app, ["interfaces"])
    assert result.exit_code == 0
    assert "Hardware & Virtual Interfaces" in result.stdout


def test_cli_ports(monkeypatch):
    # Mock probe_port so test doesn't do real network call
    async def mock_probe(ip, port, timeout=0.8):
        return None

    monkeypatch.setattr("cowman.network.ports.probe_port", mock_probe)

    result = runner.invoke(app, ["ports", "127.0.0.1", "-p", "80,443"])
    assert result.exit_code == 0
    assert "Port & Service Analysis" in result.stdout


def test_cli_topology():
    result = runner.invoke(app, ["topology"])
    assert result.exit_code == 0
    assert "INTERNET" in result.stdout
    assert "ROUTER" in result.stdout


def test_cli_events():
    result = runner.invoke(app, ["events"])
    assert result.exit_code == 0


def test_cli_replay():
    result = runner.invoke(app, ["replay"])
    assert result.exit_code == 0


def test_cli_report(tmp_path):
    out_file = tmp_path / "test_report.md"
    result = runner.invoke(app, ["report", "--format", "markdown", "--output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    assert "# COWMAN Security & Network Audit Report" in out_file.read_text(encoding="utf-8")

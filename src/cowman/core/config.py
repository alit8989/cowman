"""Configuration management for COWMAN."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


class GeneralConfig(BaseModel):
    interface: str = Field(default="", description="Interface name to bind/monitor")
    database_path: str = Field(default="~/.cowman/cowman.db", description="Path to SQLite DB")
    log_level: str = Field(default="INFO", description="Logging level")


class DiscoveryConfig(BaseModel):
    timeout: float = Field(default=1.5, description="Probe timeout in seconds")
    retries: int = Field(default=2, description="ARP retry count")
    subnet_override: str = Field(default="", description="Optional subnet CIDR override")
    max_workers: int = Field(default=64, description="Max concurrent host checks")


class PortScanConfig(BaseModel):
    timeout: float = Field(default=0.8, description="Connection timeout in seconds")
    concurrency: int = Field(default=100, description="Max concurrent sockets")
    default_ports: List[int] = Field(
        default_factory=lambda: [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443
        ]
    )


class MonitorConfig(BaseModel):
    interval: float = Field(default=1.0, description="Monitor sampling interval in seconds")
    top_destinations_limit: int = Field(default=10, description="Max top destinations")


class DnsConfig(BaseModel):
    buffer_size: int = Field(default=256, description="Sniffer buffer limit")
    domain_length_alert_threshold: int = Field(default=45, description="Domain length alert cutoff")
    entropy_alert_threshold: float = Field(default=3.8, description="Shannon entropy alert cutoff")


class SecurityConfig(BaseModel):
    unexpected_ports: List[int] = Field(default_factory=lambda: [21, 23, 135, 139, 445, 5900])
    bandwidth_spike_mb: float = Field(default=50.0, description="Bandwidth spike cutoff in MB/s")
    connection_count_threshold: int = Field(default=500, description="Connection count cutoff")


class UiConfig(BaseModel):
    theme: str = Field(default="dark_soc", description="UI color theme")
    show_banner: bool = Field(default=True, description="Show ASCII banner")
    alert_bell: bool = Field(default=False, description="Beep on critical alerts")


class CowmanConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    port_scan: PortScanConfig = Field(default_factory=PortScanConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    ui: UiConfig = Field(default_factory=UiConfig)

    def resolved_database_path(self) -> Path:
        """Resolve database path with user home directory expansion."""
        raw_path = os.path.expanduser(self.general.database_path)
        path = Path(raw_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


_GLOBAL_CONFIG: Optional[CowmanConfig] = None


def find_config_file(custom_path: Optional[str] = None) -> Optional[Path]:
    """Search for configuration file in precedence order."""
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if p.exists() and p.is_file():
            return p
        raise FileNotFoundError(f"Specified configuration file not found: {custom_path}")

    env_path = os.environ.get("COWMAN_CONFIG")
    if env_path:
        p = Path(env_path).expanduser().resolve()
        if p.exists() and p.is_file():
            return p

    local_candidates = [
        Path.cwd() / "cowman.toml",
        Path.cwd() / "config.toml",
        Path.home() / ".cowman" / "config.toml",
        Path.home() / ".config" / "cowman" / "config.toml",
    ]

    for candidate in local_candidates:
        if candidate.exists() and candidate.is_file():
            return candidate

    return None


def load_config(config_path: Optional[str] = None) -> CowmanConfig:
    """Load configuration from file or return standard defaults."""
    global _GLOBAL_CONFIG

    file_to_load = find_config_file(config_path)
    if not file_to_load:
        _GLOBAL_CONFIG = CowmanConfig()
        return _GLOBAL_CONFIG

    try:
        with open(file_to_load, "rb") as f:
            data = tomllib.load(f)
        _GLOBAL_CONFIG = CowmanConfig(**data)
    except Exception as e:
        # Fall back to defaults on parsing error, logging warning
        _GLOBAL_CONFIG = CowmanConfig()

    return _GLOBAL_CONFIG


def get_config() -> CowmanConfig:
    """Get active global configuration or initialize with defaults."""
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = load_config()
    return _GLOBAL_CONFIG

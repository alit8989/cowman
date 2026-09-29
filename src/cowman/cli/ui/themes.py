"""Theme definitions and color palettes for COWMAN terminal UI."""

from typing import Dict
from rich.theme import Theme

# Dark SOC Palette: Neon Cyan, Matrix Green, Alert Amber, Crimson Red, Slate Grey
DARK_SOC_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "accent": "bold bright_cyan",
        "muted": "dim white",
        "panel.border": "bright_blue",
        "table.header": "bold cyan",
        "status.online": "bold green",
        "status.offline": "bold red",
        "badge.info": "cyan",
        "badge.low": "blue",
        "badge.medium": "yellow",
        "badge.high": "orange1",
        "badge.critical": "bold white on red",
    }
)

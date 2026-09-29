"""Terminal ASCII art banners and SOC status headers."""

from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cowman import __version__
from cowman.core.models import SystemNetworkOverview
from cowman.network.interfaces import get_system_network_overview

COWMAN_ASCII_LOGO = r"""
   ______ ____  _       ____  ___   _   __
  / ____// __ \| |     / /  |/  /  / | / /
 / /    / / / /| | /| / / /|_/ /  /  |/ / 
/ /___ / /_/ / | |/ |/ / /  / /  / /|  /  
\____/ \____/  |__/|__/_/  /_/  /_/ |_/   
       Terminal SOC & Security Command Center
"""


def render_ascii_logo() -> Text:
    """Return styled ASCII banner logo."""
    txt = Text(COWMAN_ASCII_LOGO, style="bold cyan")
    return txt


def render_soc_header_panel(overview: Optional[SystemNetworkOverview] = None) -> Panel:
    """Render the dark SOC-style command center header box."""
    if overview is None:
        overview = get_system_network_overview()

    iface_str = overview.active_interface or "Auto"
    ip_str = overview.local_ip or "Offline"
    gw_str = overview.default_gateway or "None"

    # Layout using internal table for exact alignment
    table = Table.grid(expand=True)
    table.add_column(justify="left", ratio=1)
    table.add_column(justify="right", ratio=1)

    table.add_row(
        f"[bold bright_white]COWMAN v{__version__}[/bold bright_white]",
        "[bold green]● SYSTEM ONLINE[/bold green]",
    )
    table.add_row(
        f"[dim white]Interface:[/dim white] [cyan]{iface_str}[/cyan]   [dim white]IP:[/dim white] [cyan]{ip_str}[/cyan]   [dim white]Gateway:[/dim white] [dim cyan]{gw_str}[/dim cyan]",
        f"[dim white]Host:[/dim white] [yellow]{overview.hostname}[/yellow]",
    )

    return Panel(
        table,
        border_style="bright_blue",
        padding=(0, 2),
    )

"""Central console instance and output helpers."""

import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cowman.cli.ui.themes import DARK_SOC_THEME

# Ensure UTF-8 output encoding across Windows / Linux / macOS
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Global console instance with dark SOC theme
console = Console(theme=DARK_SOC_THEME, highlight=False, soft_wrap=True)
error_console = Console(theme=DARK_SOC_THEME, stderr=True, highlight=False, soft_wrap=True)


def print_error(message: str, hint: Optional[str] = None) -> None:
    """Display a styled error message panel."""
    content = f"[bold red][!] ERROR:[/bold red] {message}"
    if hint:
        content += f"\n\n[dim cyan]HINT:[/dim cyan] {hint}"
    error_console.print(Panel(content, border_style="red", title="[bold red]Operation Failed[/bold red]"))


def print_warning(message: str) -> None:
    """Display a warning callout."""
    console.print(f"[yellow][!] WARNING:[/yellow] {message}")


def print_success(message: str) -> None:
    """Display a success notice."""
    console.print(f"[bold green][+][/bold green] {message}")


def print_info_panel(title: str, text: str) -> None:
    """Display informative panel."""
    console.print(Panel(text, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))

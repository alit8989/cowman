"""Interactive dark SOC-style terminal dashboard for COWMAN."""

import asyncio
import sys
from typing import Optional
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from cowman.cli.ui.banners import render_ascii_logo, render_soc_header_panel
from cowman.cli.ui.console import console
from cowman.network.interfaces import get_system_network_overview
from cowman.storage.database import init_db


def display_main_menu() -> None:
    """Print the interactive command selection menu."""
    menu_text = Text()
    options = [
        ("[1]", "Network Overview"),
        ("[2]", "Device Discovery"),
        ("[3]", "Port Analysis"),
        ("[4]", "Traffic Monitor"),
        ("[5]", "DNS Monitor"),
        ("[6]", "Security Events"),
        ("[7]", "Network Topology"),
        ("[8]", "Reports"),
        ("[9]", "Event Replay"),
        ("[0]", "Exit"),
    ]

    for key, desc in options:
        color = "red" if key == "[0]" else "bright_cyan"
        menu_text.append(f" {key}", style=f"bold {color}")
        menu_text.append(f" {desc}\n", style="white")

    console.print(menu_text)


def launch_dashboard(interactive: bool = True) -> None:
    """Launch the SOC command center dashboard loop."""
    init_db()

    # Deferred imports to avoid circular dependencies
    from cowman.cli.commands.discover import run_discover
    from cowman.cli.commands.dns import run_dns
    from cowman.cli.commands.events import run_events
    from cowman.cli.commands.info import run_info
    from cowman.cli.commands.monitor import run_monitor
    from cowman.cli.commands.ports import run_ports
    from cowman.cli.commands.replay import run_replay
    from cowman.cli.commands.report import run_report
    from cowman.cli.commands.topology import run_topology

    while True:
        try:
            overview = get_system_network_overview()
            console.print(render_soc_header_panel(overview))
            console.print()
            display_main_menu()

            if not interactive or not sys.stdin.isatty():
                # Non-interactive fallback (e.g. piped or test environments)
                break

            choice = Prompt.ask("[bold cyan]cowman[/bold cyan]", default="0").strip()

            if choice in ("0", "exit", "quit", "q"):
                console.print("[dim cyan]Shutting down COWMAN Command Center. System Offline.[/dim cyan]")
                break
            elif choice == "1":
                run_info()
            elif choice == "2":
                run_discover()
            elif choice == "3":
                target = Prompt.ask("[bold cyan]Target Host / IP to analyze[/bold cyan]", default="127.0.0.1")
                if target:
                    run_ports(target=target)
            elif choice == "4":
                console.print("[dim]Starting traffic monitor for 10 seconds (or press Ctrl+C)...[/dim]")
                run_monitor(duration=10.0)
            elif choice == "5":
                run_dns(limit=20)
            elif choice == "6":
                run_events(limit=25)
            elif choice == "7":
                run_topology()
            elif choice == "8":
                fmt = Prompt.ask("[bold cyan]Report format (markdown/json/csv)[/bold cyan]", default="markdown")
                run_report(output_format=fmt)
            elif choice == "9":
                run_replay()
            else:
                console.print(f"[yellow]Unknown option '{choice}'. Select a number from 0 to 9.[/yellow]")

            console.print()
            Prompt.ask("[dim]Press Enter to return to Command Center...[/dim]", default="")
            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim cyan]COWMAN Command Center terminated by user.[/dim cyan]")
            break
        except Exception as e:
            console.print(f"[bold red]Unexpected error in dashboard loop:[/bold red] {e}")
            break

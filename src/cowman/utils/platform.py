"""Cross-platform environment detection and privilege utilities."""

import os
import platform
import sys
from typing import Tuple


def get_os_name() -> str:
    """Return friendly operating system name."""
    system = platform.system().lower()
    if "windows" in system:
        return f"Windows {platform.release()}"
    elif "darwin" in system:
        return f"macOS {platform.mac_ver()[0]}"
    elif "linux" in system:
        return f"Linux ({platform.release()})"
    return platform.system()


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_admin() -> bool:
    """Check if the current process is running with administrative/root privileges."""
    try:
        if is_windows():
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_privilege_hint(feature_name: str = "Raw packet capture") -> str:
    """Return platform-specific elevation instructions when a feature needs higher privileges."""
    if is_windows():
        return (
            f"[yellow]{feature_name} requires elevated privileges or Npcap.[/yellow]\n"
            "• Run PowerShell or Terminal as [bold red]Administrator[/bold red].\n"
            "• Ensure [bold cyan]Npcap[/bold cyan] is installed with 'WinPcap API-compatible Mode' enabled (https://npcap.com)."
        )
    elif is_macos():
        return (
            f"[yellow]{feature_name} requires root privileges.[/yellow]\n"
            "• Run the command with [bold red]sudo[/bold red]: [bold cyan]sudo cowman ...[/bold cyan]"
        )
    else:
        return (
            f"[yellow]{feature_name} requires root privileges or CAP_NET_RAW capability.[/yellow]\n"
            "• Run with [bold red]sudo[/bold red]: [bold cyan]sudo cowman ...[/bold cyan]\n"
            "• Or grant raw socket capabilities: [bold cyan]sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)[/bold cyan]"
        )

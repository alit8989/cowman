"""Security severity classifications and terminal styling."""

from enum import Enum
from typing import Dict


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric level for sorting and comparison."""
        mapping = {
            Severity.INFO: 10,
            Severity.LOW: 20,
            Severity.MEDIUM: 30,
            Severity.HIGH: 40,
            Severity.CRITICAL: 50,
        }
        return mapping[self]

    @property
    def color(self) -> str:
        """Rich color tag for formatting."""
        mapping = {
            Severity.INFO: "cyan",
            Severity.LOW: "blue",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "orange1",
            Severity.CRITICAL: "bold red",
        }
        return mapping[self]

    @property
    def badge(self) -> str:
        """Styled terminal badge."""
        mapping = {
            Severity.INFO: "[cyan][INFO][/cyan]",
            Severity.LOW: "[blue][LOW][/blue]",
            Severity.MEDIUM: "[yellow][MEDIUM][/yellow]",
            Severity.HIGH: "[orange1][HIGH][/orange1]",
            Severity.CRITICAL: "[bold white on red][CRITICAL][/bold white on red]",
        }
        return mapping[self]

    @property
    def icon(self) -> str:
        """Status symbol icon."""
        mapping = {
            Severity.INFO: "ℹ",
            Severity.LOW: "●",
            Severity.MEDIUM: "▲",
            Severity.HIGH: "■",
            Severity.CRITICAL: "✖",
        }
        return mapping[self]

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        val_upper = val.strip().upper()
        for member in cls:
            if member.value == val_upper:
                return member
        return cls.INFO

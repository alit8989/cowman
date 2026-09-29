"""Datetime parsing and formatting utilities."""

from datetime import datetime, timedelta, timezone
import re
from typing import Optional


def parse_datetime_flexible(value: Optional[str]) -> Optional[datetime]:
    """Parse a date/time string, ISO timestamp, or relative time offset (e.g. '1h', '30m', '1d')."""
    if not value or not value.strip():
        return None

    val = value.strip().lower()
    now = datetime.now(timezone.utc)

    # Relative offset: e.g. "15m", "2h", "1d", "7d", "30s"
    rel_match = re.match(r"^(\d+)\s*(s|sec|m|min|h|hr|d|day|w|week)s?$", val)
    if rel_match:
        amount = int(rel_match.group(1))
        unit = rel_match.group(2)
        if unit.startswith("s"):
            return now - timedelta(seconds=amount)
        elif unit.startswith("m"):
            return now - timedelta(minutes=amount)
        elif unit.startswith("h"):
            return now - timedelta(hours=amount)
        elif unit.startswith("d"):
            return now - timedelta(days=amount)
        elif unit.startswith("w"):
            return now - timedelta(weeks=amount)

    if val == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif val == "yesterday":
        yesterday = now - timedelta(days=1)
        return yesterday.replace(hour=0, minute=0, second=0, microsecond=0)

    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%H:%M:%S",
        "%H:%M",
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            if fmt in ["%H:%M:%S", "%H:%M"]:
                # Combine with today's date
                parsed = now.replace(
                    hour=parsed.hour,
                    minute=parsed.minute,
                    second=parsed.second,
                    microsecond=0,
                )
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue

    raise ValueError(f"Unable to parse timestamp or relative time '{value}'. Examples: '1h', '30m', '2026-09-30 14:00'.")


def format_timestamp(dt: Optional[datetime] = None, include_date: bool = True) -> str:
    """Format datetime cleanly for terminal display. Defaults to current time if None."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    local_dt = dt.astimezone() if dt.tzinfo else dt
    if include_date:
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    return local_dt.strftime("%H:%M:%S")


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 1.0:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"

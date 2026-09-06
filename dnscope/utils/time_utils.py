"""Time helpers: UTC timestamps, ISO parsing and duration/interval parsing."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from dnscope.exceptions import ConfigurationError

#: Accepted interval suffixes mapped to seconds.
_UNITS = {
    "s": 1,
    "sec": 1,
    "secs": 1,
    "second": 1,
    "seconds": 1,
    "m": 60,
    "min": 60,
    "mins": 60,
    "minute": 60,
    "minutes": 60,
    "h": 3600,
    "hr": 3600,
    "hrs": 3600,
    "hour": 3600,
    "hours": 3600,
    "d": 86400,
    "day": 86400,
    "days": 86400,
    "w": 604800,
    "week": 604800,
    "weeks": 604800,
}

_INTERVAL_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$")


def now_utc() -> datetime:
    """Current UTC time as an aware ``datetime``."""
    return datetime.now(UTC)


def utc_iso(moment: datetime | None = None, *, seconds: bool = False) -> str:
    """ISO-8601 UTC timestamp (``Z`` suffix, microsecond precision)."""
    moment = moment or now_utc()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC)
    if seconds:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def utc_now_iso() -> str:
    """Shorthand for :func:`utc_iso` at the current moment."""
    return utc_iso(now_utc())


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (``Z`` or offset). Returns ``None`` if empty.

    Raises :class:`ConfigurationError` for malformed values so bad input fails
    loudly instead of silently becoming "no timestamp".
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = value.strip()
    if not text:
        return None
    normalized = text
    if normalized.endswith(("Z", "z")):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ConfigurationError(f"invalid timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_duration(value: str | int | float, *, default_unit: str = "s") -> float:
    """Parse ``90d``/``1h``/``30m``/``500ms``/``45`` into seconds.

    ``default_unit`` applies when no suffix is present, so numeric config
    values stay usable as seconds.
    """
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        raise ConfigurationError("duration must not be empty")
    text = str(value).strip().lower()
    if not text:
        raise ConfigurationError("duration must not be empty")
    match = _INTERVAL_RE.match(text)
    if not match:
        raise ConfigurationError(f"invalid duration: {value!r}")
    number = float(match.group(1))
    unit = match.group(2) or default_unit
    if unit == "ms":
        return number / 1000.0
    if unit not in _UNITS:
        raise ConfigurationError(f"unknown duration unit {unit!r} in {value!r}")
    return number * _UNITS[unit]


def parse_interval(value: str | int | float) -> int:
    """Parse a monitoring interval into whole seconds (minimum 1)."""
    return max(1, int(parse_duration(value)))


def format_duration(seconds: float | int | None, *, compact: bool = False) -> str:
    """Human readable duration, e.g. ``1h 5m`` or ``2.34s``."""
    if seconds is None:
        return "n/a"
    total = float(seconds)
    if total < 0:
        return f"-{format_duration(-total, compact=compact)}"
    if total < 1:
        return f"{total * 1000:.0f}ms"
    if compact or total < 60:
        return f"{total:.2f}s" if total < 10 else f"{total:.1f}s"
    days, remainder = divmod(int(total), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def format_elapsed(start: datetime, end: datetime | None = None) -> str:
    """Format the delta between two timestamps."""
    return format_duration(((end or now_utc()) - start).total_seconds())


def within(moment: datetime | None, window: timedelta) -> bool:
    """Return ``True`` when ``moment`` is newer than ``now - window``."""
    if moment is None:
        return False
    return moment >= now_utc() - window

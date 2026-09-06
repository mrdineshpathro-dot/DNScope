"""Identifier generation.

IDs are time-sortable and URL-safe so snapshots, jobs, findings and scans can
be referenced from CLI output, REST responses and reports interchangeably.
"""

from __future__ import annotations

import secrets
import time

_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def short_id(length: int = 8) -> str:
    """Return ``length`` random lowercase alphanumeric characters."""
    length = max(1, min(length, 64))
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def new_id(prefix: str = "", *, length: int = 10) -> str:
    """Return a time-sortable identifier, e.g. ``scan-m2x8k4b1qz``.

    The leading base36 timestamp keeps list ordering stable without requiring a
    database sequence, which matters for NDJSON streaming output.
    """
    stamp = _base36(int(time.time() * 1000))
    suffix = short_id(length)
    return f"{prefix}-{stamp}{suffix}" if prefix else f"{stamp}{suffix}"


def _base36(number: int) -> str:
    if number <= 0:
        return "0"
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 36)
        chars.append(_ALPHABET[remainder])
    return "".join(reversed(chars))


def fingerprint(*parts: object) -> str:
    """Stable short fingerprint for deduplication of alerts/findings."""
    from dnscope.utils.hashing import blake2b_hex

    joined = "\x1f".join(str(part) for part in parts)
    return blake2b_hex(joined, size=16)

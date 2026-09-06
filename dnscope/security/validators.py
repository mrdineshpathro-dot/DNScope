"""Input validation helpers used at every trust boundary.

Provider responses, imported JSON and user-supplied paths all pass through here
so a malformed or hostile payload degrades into an error record instead of a
crash (or, worse, silent corruption).
"""

from __future__ import annotations

import json
import re
from typing import Any

from dnscope.exceptions import ImportError_
from dnscope.utils.domains import valid_hostname

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

#: Maximum number of items accepted in a single provider/import list.
MAX_LIST_ITEMS = 100_000


def clamp_int(value: Any, minimum: int, maximum: int, *, default: int | None = None) -> int:
    """Coerce ``value`` to an int inside ``[minimum, maximum]``."""
    fallback = default if default is not None else minimum
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return fallback
    return max(minimum, min(maximum, number))


def clamp_float(value: Any, minimum: float, maximum: float, *, default: float | None = None) -> float:
    """Coerce ``value`` to a float inside ``[minimum, maximum]``."""
    fallback = default if default is not None else minimum
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if number != number:  # NaN
        return fallback
    return max(minimum, min(maximum, number))


def ensure_bounded(
    items: Any,
    *,
    maximum: int = MAX_LIST_ITEMS,
    name: str = "list",
    strict: bool = False,
) -> list[Any]:
    """Return ``items`` as a list truncated to ``maximum`` entries.

    Every caller here is normalizing an *untrusted* provider payload, so the
    default is to return an empty list for a value that is not a sequence: a
    malformed response must produce ``ok=False``, never an exception that
    escapes ``normalize()``. Pass ``strict=True`` to raise instead.
    """
    if items is None:
        return []
    if isinstance(items, (str, bytes)):
        if strict:
            raise ImportError_(f"{name} must be a list, got a string")
        return []
    try:
        sequence = list(items)
    except TypeError as exc:
        if strict:
            raise ImportError_(f"{name} is not iterable") from exc
        return []
    return sequence[:maximum]


def validate_identifier(value: Any, *, field: str = "identifier") -> str:
    """Validate an ID-like string (rule ids, workspace names, job ids...)."""
    text = str(value or "").strip()
    if not _IDENTIFIER_RE.match(text):
        raise ImportError_(f"invalid {field}: {value!r}")
    return text


def validate_hostname_input(value: Any, *, field: str = "hostname") -> str:
    """Validate and normalize a hostname supplied by an external source."""
    text = str(value or "").strip().strip(".").lower()
    if not text or not valid_hostname(text):
        raise ImportError_(f"invalid {field}: {value!r}")
    return text


def safe_json_loads(
    data: str | bytes,
    *,
    max_bytes: int = 5 * 1024 * 1024,
    context: str = "payload",
) -> Any:
    """Parse JSON with size and depth guards.

    Python's ``json`` module is not vulnerable to billion-laughs expansion, but
    deeply nested arrays can still exhaust the stack, so nesting is capped.
    """
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="replace")
    else:
        raw = bytes(data)
    if len(raw) > max_bytes:
        raise ImportError_(
            f"{context} exceeds the maximum size of {max_bytes} bytes",
            details={"size": len(raw)},
        )
    if not raw.strip():
        raise ImportError_(f"{context} is empty")
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportError_(f"{context} is not valid JSON: {exc}") from exc
    depth = _measure_depth(parsed)
    if depth > 64:
        raise ImportError_(f"{context} is nested too deeply ({depth} levels)")
    return parsed


def _measure_depth(value: Any, *, current: int = 0) -> int:
    """Compute the nesting depth of a parsed JSON value (iteratively)."""
    stack: list[tuple[Any, int]] = [(value, current)]
    deepest = current
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if level > 64:
            return level
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in item)
    return deepest


def coerce_str(value: Any, *, maximum: int = 4096, default: str = "") -> str:
    """Coerce any value to a bounded string."""
    if value is None:
        return default
    text = value if isinstance(value, str) else str(value)
    return text[:maximum]


def mapping_field(container: Any, key: str) -> dict[str, Any]:
    """Return ``container[key]`` when it is a mapping, otherwise ``{}``.

    Provider payloads are untrusted JSON, so every nested object has to be
    type-checked before use. Doing it through one helper keeps the narrowing
    visible to type checkers instead of relying on a repeated ``isinstance``
    call that they cannot relate to the later access.
    """
    value = container.get(key) if isinstance(container, dict) else None
    return dict(value) if isinstance(value, dict) else {}


def list_field(container: Any, key: str) -> list[Any]:
    """Return ``container[key]`` when it is a list, otherwise ``[]``."""
    value = container.get(key) if isinstance(container, dict) else None
    return list(value) if isinstance(value, (list, tuple)) else []


def coerce_str_list(value: Any, *, maximum: int = 1_000, item_length: int = 512) -> list[str]:
    """Coerce a value into a bounded list of bounded strings."""
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    else:
        items = ensure_bounded(value, maximum=maximum, name="string list")
    result: list[str] = []
    for item in items[:maximum]:
        text = coerce_str(item, maximum=item_length)
        if text:
            result.append(text)
    return result


def looks_like_html(text: str) -> bool:
    """``True`` when a payload that should be JSON is actually an HTML page."""
    head = text.lstrip()[:512].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


def truncate(text: str, maximum: int) -> str:
    """Truncate ``text`` with an explicit marker."""
    if len(text) <= maximum:
        return text
    return text[: max(0, maximum - 3)] + "..."


def require_keys(payload: Any, keys: tuple[str, ...], *, context: str = "object") -> dict[str, Any]:
    """Return ``payload`` as a mapping containing all ``keys``."""
    if not isinstance(payload, dict):
        raise ImportError_(f"{context} must be an object")
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ImportError_(f"{context} is missing required keys: {missing}")
    return payload

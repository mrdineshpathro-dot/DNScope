"""Filesystem helpers with path-traversal protection."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from dnscope.exceptions import SecurityPolicyViolation

#: Characters never allowed in a generated filename.
_UNSAFE = set('<>:"/\\|?*\0')


def safe_filename(name: str, *, max_length: int = 200) -> str:
    """Sanitize ``name`` into a safe single filename component.

    Strips directory separators, control characters and reserved names so a
    hostname like ``../../etc/passwd`` can never escape the output directory.
    """
    if not name:
        return "unnamed"
    cleaned = "".join("-" if (ch in _UNSAFE or ord(ch) < 32) else ch for ch in name.strip())
    cleaned = cleaned.strip(". -") or "unnamed"
    if cleaned.lower() in {"con", "prn", "aux", "nul", "com1", "lpt1"}:
        cleaned = f"_{cleaned}"
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def safe_path(base: str | Path, relative: str | Path) -> Path:
    """Resolve ``relative`` under ``base``, rejecting traversal attempts.

    Raises :class:`SecurityPolicyViolation` when the resolved path escapes the
    base directory (including via symlinks).
    """
    base_dir = Path(base).expanduser().resolve()
    candidate = (base_dir / str(relative)).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError as exc:
        raise SecurityPolicyViolation(
            f"path escapes base directory: {relative!r}",
            details={"base": str(base_dir), "resolved": str(candidate)},
        ) from exc
    return candidate


def ensure_dir(path: str | Path) -> Path:
    """Create a directory (and parents) if needed and return it."""
    directory = Path(path).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_atomic(path: str | Path, data: str | bytes, *, encoding: str = "utf-8") -> Path:
    """Write ``data`` to ``path`` atomically via a temporary file + rename."""
    target = Path(path).expanduser()
    ensure_dir(target.parent)
    mode = "wb" if isinstance(data, bytes) else "w"
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - replaced by os.replace
        mode=mode,
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
        encoding=None if isinstance(data, bytes) else encoding,
    )
    try:
        with handle as stream:
            stream.write(data)
        os.replace(handle.name, target)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:  # pragma: no cover - best effort cleanup
            pass
        raise
    return target


def read_text(path: str | Path, *, max_bytes: int = 20 * 1024 * 1024, encoding: str = "utf-8") -> str:
    """Read a text file with a hard size cap to avoid memory exhaustion."""
    target = Path(path).expanduser()
    size = target.stat().st_size
    if size > max_bytes:
        raise SecurityPolicyViolation(
            f"file exceeds maximum size of {max_bytes} bytes: {target}",
            details={"size": size, "max_bytes": max_bytes},
        )
    return target.read_text(encoding=encoding)


def human_size(num_bytes: int | float) -> str:
    """Human readable byte size."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024
    return f"{value:.1f}TB"  # pragma: no cover

"""Hashing utilities for report integrity, caching keys and config hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_hex(data: str | bytes) -> str:
    """SHA-256 hex digest of text or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, *, chunk_size: int = 1 << 16) -> str:
    """SHA-256 hex digest of a file, streamed to bound memory usage."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def blake2b_hex(data: str | bytes, *, size: int = 32) -> str:
    """BLAKE2b hex digest (faster than SHA-256 for cache keys)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.blake2b(data, digest_size=max(1, min(size, 64))).hexdigest()


def canonical_json(payload: Any) -> str:
    """Deterministic JSON serialization (sorted keys, no whitespace)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def payload_hash(payload: Any) -> str:
    """Hash of a canonicalized JSON payload."""
    return sha256_hex(canonical_json(payload))


def config_hash(config: Any) -> str:
    """Hash a configuration object for scan reproducibility records.

    Accepts a mapping, a Pydantic model or anything with a ``model_dump``
    method. Secrets are stripped before hashing so the hash is stable and safe
    to persist.
    """
    from dnscope.utils.redact import redact_mapping

    if hasattr(config, "model_dump"):
        data = config.model_dump(mode="json")  # type: ignore[attr-defined]
    elif isinstance(config, dict):
        data = config
    else:
        data = {"value": repr(config)}
    return payload_hash(redact_mapping(data))


def truncate_hash(value: str, length: int = 12) -> str:
    """Short prefix of a hash for compact display."""
    return value[: max(1, length)]

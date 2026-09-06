"""Secret redaction helpers.

Used by logging, report generation, ``config validate`` and the audit log so a
credential can never leak into an artifact DNScope writes.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

REDACTION_PLACEHOLDER = "[REDACTED]"

#: Substrings that make a mapping key look like a credential.
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "authorization",
    "auth",
    "webhook_url",
    "webhook",
    "private_key",
    "access_key",
)

#: Values that look like credentials regardless of key name.
_VALUE_PATTERNS = (
    # Bearer / basic auth headers
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/=]{8,}"),
    # Slack / Discord / Teams / Telegram webhook URLs
    re.compile(r"(?i)https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    re.compile(r"(?i)https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_-]+"),
    re.compile(r"(?i)https://[a-z0-9.-]*outlook\.office\.com/webhook/[A-Za-z0-9@/_-]+"),
    re.compile(r"(?i)https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+"),
    # AWS style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Generic long opaque tokens (32+ chars, no spaces)
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
)

#: Compiled patterns re-exported for the logging filter.
SECRET_PATTERNS = tuple(_VALUE_PATTERNS)

_HEXISH = re.compile(r"^[0-9a-fA-F]+$")


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when a config/mapping key names a credential."""
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def looks_like_secret(value: Any) -> bool:
    """Heuristic: does this scalar value look like a credential?"""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if len(stripped) < 16:
        return False
    if " " in stripped:
        return False
    if stripped.count(".") >= 2 and not _HEXISH.match(stripped):
        # Looks like a hostname or version string, not a token.
        return False
    for pattern in SECRET_PATTERNS:
        if pattern.fullmatch(stripped):
            return True
    return bool(_HEXISH.match(stripped)) and len(stripped) >= 32


def redact_text(text: str) -> str:
    """Replace credential-looking substrings in free text."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)
    return redacted


def redact_mapping(
    mapping: Mapping[str, Any],
    *,
    sensitive_keys: Iterable[str] = (),
    deep: bool = True,
) -> dict[str, Any]:
    """Return a copy of ``mapping`` with sensitive values replaced.

    Keys are matched case-insensitively against known credential names plus any
    extra ``sensitive_keys`` supplied by the caller.
    """
    extra = {k.lower() for k in sensitive_keys}
    redacted: dict[str, Any] = {}
    for key, value in mapping.items():
        lowered = key.lower()
        if lowered in extra or is_sensitive_key(key) or looks_like_secret(value):
            redacted[key] = REDACTION_PLACEHOLDER if value not in (None, "", []) else value
            continue
        if deep and isinstance(value, Mapping):
            redacted[key] = redact_mapping(value, sensitive_keys=extra, deep=True)
        elif deep and isinstance(value, (list, tuple)):
            redacted[key] = [
                redact_mapping(item, sensitive_keys=extra, deep=True)
                if isinstance(item, Mapping)
                else (REDACTION_PLACEHOLDER if looks_like_secret(item) else item)
                for item in value
            ]
        elif isinstance(value, str):
            redacted[key] = redact_text(value) if len(value) >= 16 else value
        else:
            redacted[key] = value
    return redacted


def mask_secret(value: str | None, *, visible: int = 4) -> str:
    """Mask a secret for display, e.g. ``abcd****`` (never the full value)."""
    if not value:
        return REDACTION_PLACEHOLDER
    if len(value) <= visible:
        return REDACTION_PLACEHOLDER
    return f"{value[:visible]}{'*' * 8}"

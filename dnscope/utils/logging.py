"""Logging configuration.

Logging is deliberately secret-safe: the :class:`SecretRedactor` filter runs on
every record so an API key accidentally interpolated into a log line is
replaced with ``[REDACTED]`` before it reaches a handler.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

from dnscope.utils.redact import REDACTION_PLACEHOLDER, SECRET_PATTERNS

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_CONFIGURED = False


class SecretRedactor(logging.Filter):
    """Scrub credential-looking substrings from every log record."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging API
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = message
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def setup_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    quiet: bool = False,
    log_file: str | None = None,
) -> None:
    """Configure the root ``dnscope`` logger.

    Safe to call repeatedly; handlers are only installed once and the level is
    adjusted on subsequent calls.
    """
    global _CONFIGURED

    level = logging.WARNING
    if verbose:
        level = logging.INFO
    if debug:
        level = logging.DEBUG
    if quiet:
        level = logging.ERROR

    logger = logging.getLogger("dnscope")
    logger.setLevel(level)
    logger.propagate = False

    if not _CONFIGURED:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
        handler.addFilter(SecretRedactor())
        logger.addHandler(handler)

        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
            file_handler.addFilter(SecretRedactor())
            logger.addHandler(file_handler)

        _CONFIGURED = True
    else:
        for handler in logger.handlers:
            handler.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger inside the ``dnscope`` namespace."""
    if not name.startswith("dnscope"):
        name = f"dnscope.{name}"
    return logging.getLogger(name)


def reset_logging_for_tests() -> None:
    """Remove all handlers (used by the test-suite only)."""
    global _CONFIGURED
    logger = logging.getLogger("dnscope")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    _CONFIGURED = False


def capture_debug_records(logger_name: str = "dnscope") -> list[logging.LogRecord]:
    """Attach an in-memory handler and return the list it fills (test helper)."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collector()
    handler.addFilter(SecretRedactor())
    handler.setLevel(logging.DEBUG)
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return records


def _silence_noisy_third_party() -> None:
    for name in ("httpx", "httpcore", "asyncio", "urllib3"):
        logging.getLogger(name).setLevel(
            os.environ.get("DNSCOPE_THIRD_PARTY_LOG_LEVEL", "WARNING")
        )


_silence_noisy_third_party()


def logger_debug_enabled(name: str) -> bool:
    """Return ``True`` when DEBUG logging is active (avoids costly formatting)."""
    return logging.getLogger(name).isEnabledFor(logging.DEBUG)


def log_payload(logger: logging.Logger, level: int, payload: Any) -> None:  # pragma: no cover
    """Log a structured payload if the level is enabled."""
    if logger.isEnabledFor(level):
        logger.log(level, payload)

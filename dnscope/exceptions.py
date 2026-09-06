"""DNScope exception hierarchy.

All errors raised by DNScope derive from :class:`DNScopeError` so callers can
catch the whole family without swallowing unrelated ``Exception`` types.
"""

from __future__ import annotations


class DNScopeError(Exception):
    """Base class for every error raised by DNScope."""

    #: Exit code the CLI maps this error to.
    exit_code = 3

    def __init__(self, message: str, *, details: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, object] = details or {}


class ConfigurationError(DNScopeError):
    """Invalid, missing or contradictory configuration."""

    exit_code = 2


class ScopeError(DNScopeError):
    """A target was rejected by the scope engine."""

    exit_code = 2


class TargetError(DNScopeError):
    """A target string could not be normalized."""

    exit_code = 2


class DNSError(DNScopeError):
    """A DNS operation failed."""

    exit_code = 3


class DNSTimeout(DNSError):
    """A DNS query timed out."""


class DNSResolutionError(DNSError):
    """A DNS query returned a terminal error response code."""

    def __init__(self, message: str, *, rcode: str = "", **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.rcode = rcode


class ProviderError(DNScopeError):
    """A provider call failed."""

    exit_code = 3

    def __init__(self, message: str, *, provider: str = "", **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.provider = provider


class ProviderNotConfigured(ProviderError):
    """A provider was requested but has no credentials configured."""

    exit_code = 2


class ProviderRateLimited(ProviderError):
    """A provider returned 429 or its circuit breaker is open."""


class ProviderTimeout(ProviderError):
    """A provider call exceeded its timeout."""


class ProviderResponseError(ProviderError):
    """A provider returned a malformed or oversized response."""


class SecurityPolicyViolation(DNScopeError):
    """An operation was blocked by a security guard (SSRF, path traversal...)."""

    exit_code = 2


class StorageError(DNScopeError):
    """A storage layer operation failed."""

    exit_code = 3


class MigrationError(StorageError):
    """A database migration failed."""


class PluginError(DNScopeError):
    """A plugin failed to load or was rejected by validation."""

    exit_code = 2


class RuleError(DNScopeError):
    """A rule definition is invalid."""

    exit_code = 2


class ReportError(DNScopeError):
    """Report generation failed."""

    exit_code = 3


class ImportError_(DNScopeError):
    """An imported payload was rejected."""

    exit_code = 2


class LimitsExceeded(DNScopeError):
    """A configured safety limit was reached."""

    exit_code = 1


class JobError(DNScopeError):
    """A background job failed."""

    exit_code = 3

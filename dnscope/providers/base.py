"""Provider abstraction: the contract every intelligence source implements."""

from __future__ import annotations

import abc
import time
from typing import TYPE_CHECKING, Any

from dnscope.exceptions import ProviderError, ProviderNotConfigured
from dnscope.models.common import Confidence, EvidenceQuality, SourceRecord
from dnscope.models.providers import (
    ProviderCapabilities,
    ProviderHealth,
    ProviderInfo,
    ProviderQueryResult,
    ProviderStatus,
)
from dnscope.utils.logging import get_logger

_log = get_logger("providers")


if TYPE_CHECKING:  # pragma: no cover - typing only
    from dnscope.providers.http import SafeHTTPClient


class ProviderContext:
    """Runtime context handed to every provider call.

    Carries the settings a provider needs without giving it access to the whole
    configuration object (least privilege) and without ever exposing secrets to
    logging.
    """

    __slots__ = (
        "allow_external",
        "api_key",
        "cache",
        "dns",
        "http",
        "offline",
        "privacy",
        "rate_budget",
        "settings",
        "target",
        "workspace",
    )

    def __init__(
        self,
        *,
        http: SafeHTTPClient | None = None,
        cache: Any = None,
        settings: Any = None,
        offline: bool = False,
        privacy: bool = False,
        workspace: str = "default",
        api_key: str = "",
        allow_external: bool = True,
        dns: Any = None,
        rate_budget: Any = None,
    ) -> None:
        self.http = http
        self.dns = dns
        self.rate_budget = rate_budget
        self.cache = cache
        self.settings = settings
        self.offline = offline
        self.privacy = privacy
        self.workspace = workspace
        self.api_key = api_key
        self.allow_external = allow_external

    @property
    def may_call_network(self) -> bool:
        """``False`` when offline mode or privacy mode forbids the request."""
        return self.allow_external and not self.offline


class Provider(abc.ABC):
    """Base class for all intelligence providers.

    Subclasses declare ``name``, ``category`` and ``capabilities``; the registry
    uses those to build the capability matrix and the router uses them to pick
    providers. ``query`` returns a :class:`ProviderQueryResult` in DNScope's
    canonical schema - provider-specific JSON never escapes ``normalize``.
    """

    #: Unique provider identifier (lowercase).
    name: str = ""
    #: Primary capability category.
    category: str = "enrichment"
    description: str = ""
    homepage: str = ""
    capabilities: ProviderCapabilities = ProviderCapabilities()
    #: Environment variables that provide credentials.
    env_vars: tuple[str, ...] = ()
    #: ``True`` when the provider cannot be used without credentials.
    requires_credentials: bool = False
    #: ``False`` for free/keyless sources.
    commercial: bool = True
    #: Documented rate limit (requests/minute, 0 = unknown).
    rate_limit_per_minute: float = 0.0
    #: Base URL (documented for transparency; never used for anything else).
    base_url: str = ""

    def __init__(self, *, api_key: str = "", settings: Any = None) -> None:
        self.api_key = api_key.strip() if api_key else ""
        self.settings = settings
        self.log = get_logger(f"providers.{self.name or 'base'}")

    # ------------------------------------------------------------- capability

    def info(self) -> ProviderInfo:
        """Static description used by ``dnscope providers``."""
        return ProviderInfo(
            name=self.name,
            category=self.category,
            description=self.description,
            homepage=self.homepage or self.base_url,
            env_vars=list(self.env_vars),
            requires_credentials=self.requires_credentials,
            capabilities=self.capabilities,
            rate_limit_per_minute=self.rate_limit_per_minute,
            commercial=self.commercial,
        )

    def supports(self, capability: str) -> bool:
        """Return whether this provider implements ``capability``."""
        return self.capabilities.supports(capability)

    # -------------------------------------------------------------- lifecycle

    def is_configured(self) -> bool:
        """``True`` when the provider has everything it needs to run."""
        if not self.requires_credentials:
            return True
        return bool(self.api_key)

    def health_check(self) -> ProviderHealth:
        """Cheap readiness check.

        The default implementation verifies configuration only - it does not
        spend API quota. Providers that can do better override this.
        """
        if not self.requires_credentials:
            return ProviderHealth(
                provider=self.name,
                ok=True,
                status=ProviderStatus.READY,
                message="keyless provider",
            )
        if self.is_configured():
            return ProviderHealth(
                provider=self.name,
                ok=True,
                status=ProviderStatus.READY,
                message="credentials configured",
            )
        missing = ", ".join(self.env_vars) or "credentials"
        return ProviderHealth(
            provider=self.name,
            ok=False,
            status=ProviderStatus.NOT_CONFIGURED,
            message=f"missing {missing}",
        )

    # ------------------------------------------------------------------- query

    @abc.abstractmethod
    def query(
        self, target: str, context: ProviderContext | None = None, **options: Any
    ) -> ProviderQueryResult:
        """Fetch data for ``target`` and return canonical observations."""

    @abc.abstractmethod
    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert a provider-specific payload into the canonical schema."""

    # ----------------------------------------------------------------- helpers

    def require_configured(self) -> None:
        """Raise :class:`ProviderNotConfigured` when credentials are missing."""
        if not self.is_configured():
            raise ProviderNotConfigured(
                f"provider {self.name} is not configured",
                provider=self.name,
                details={"env_vars": list(self.env_vars)},
            )

    def empty_result(self, target: str, *, error: str = "") -> ProviderQueryResult:
        """Build an empty result (used for failures and no-data responses)."""
        return ProviderQueryResult(
            provider=self.name,
            query=target,
            ok=not error,
            error=error,
            source=self.source_record(target),
        )

    def source_record(
        self, target: str, *, detail: str = "", confidence: Confidence = Confidence.MEDIUM
    ) -> SourceRecord:
        """Provenance record for observations produced by this provider."""
        return SourceRecord(
            provider=self.name,
            source=detail or self.base_url,
            confidence=confidence,
            quality=EvidenceQuality.OBSERVED,
        )

    def timed(self) -> _Timer:
        """Context manager measuring call latency for the budget engine."""
        return _Timer()

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        state = "configured" if self.is_configured() else "unconfigured"
        return f"<Provider {self.name} ({state})>"


class _Timer:
    """Small elapsed-time context manager."""

    __slots__ = ("_start", "elapsed_ms")

    def __init__(self) -> None:
        self.elapsed_ms = 0.0
        self._start = 0.0

    def __enter__(self) -> _Timer:
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed_ms = (time.monotonic() - self._start) * 1000.0


class DiscoveryProvider(Provider):
    """Provider whose primary job is hostname discovery."""

    category = "subdomains"

    def query(
        self, target: str, context: ProviderContext | None = None, **options: Any
    ) -> ProviderQueryResult:
        """Fetch and normalize subdomain observations for ``target``."""
        self.require_configured()
        ctx = context or ProviderContext()
        if not ctx.may_call_network:
            return self.empty_result(target, error="external calls disabled (offline/privacy mode)")
        raw = self.fetch(target, ctx, **options)
        return self.normalize(raw)

    @abc.abstractmethod
    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Perform the provider-specific request and return the raw payload."""


class ThreatProvider(Provider):
    """Provider that returns reputation/threat data for hosts and IPs."""

    category = "threat"

    def query(
        self, target: str, context: ProviderContext | None = None, **options: Any
    ) -> ProviderQueryResult:
        """Fetch and normalize threat observations for ``target``."""
        self.require_configured()
        ctx = context or ProviderContext()
        if not ctx.may_call_network:
            return self.empty_result(target, error="external calls disabled (offline/privacy mode)")
        raw = self.fetch(target, ctx, **options)
        return self.normalize(raw)

    @abc.abstractmethod
    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Perform the provider-specific request and return the raw payload."""


__all__ = [
    "DiscoveryProvider",
    "Provider",
    "ProviderContext",
    "ProviderError",
    "ThreatProvider",
]

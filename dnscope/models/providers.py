"""Provider models: capabilities, health, budgets and normalized results."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.utils.time_utils import utc_now_iso


class ProviderCategory:
    """Provider capability categories."""

    DNS = "dns"
    IP = "ip"
    CT = "ct"
    THREAT = "threat"
    HISTORY = "history"
    SUBDOMAINS = "subdomains"
    CERTIFICATES = "certificates"
    RDAP = "rdap"
    ASN = "asn"
    TLS = "tls"
    ENRICHMENT = "enrichment"

    ALL = (DNS, IP, CT, THREAT, HISTORY, SUBDOMAINS, CERTIFICATES, RDAP, ASN, TLS, ENRICHMENT)


class ProviderStatus:
    """Runtime provider states."""

    READY = "READY"
    NOT_CONFIGURED = "NOT CONFIGURED"
    DISABLED = "DISABLED"
    UNHEALTHY = "UNHEALTHY"
    RATE_LIMITED = "RATE LIMITED"
    UNKNOWN = "UNKNOWN"
    OFFLINE_MODE = "OFFLINE"

    ALL = (READY, NOT_CONFIGURED, DISABLED, UNHEALTHY, RATE_LIMITED, UNKNOWN, OFFLINE_MODE)


class ProviderCapabilities(SchemaVersioned):
    """What a provider can actually do.

    The capability matrix printed by ``dnscope providers`` is generated from
    these flags - nothing is asserted that the provider does not implement.
    """

    dns: bool = False
    ip: bool = False
    ct: bool = False
    threat: bool = False
    history: bool = False
    subdomains: bool = False
    certificates: bool = False
    rdap: bool = False
    asn: bool = False
    tls: bool = False
    enrichment: bool = False

    def supports(self, capability: str) -> bool:
        """Return whether ``capability`` (e.g. ``"ct"``) is supported."""
        return bool(getattr(self, capability.lower(), False))

    def matrix_row(self) -> dict[str, str]:
        """Row for the ``dnscope providers`` table."""
        return {
            "DNS": "yes" if self.dns else "-",
            "IP": "yes" if self.ip else "-",
            "CT": "yes" if self.ct else "-",
            "Threat": "yes" if self.threat else "-",
            "History": "yes" if self.history else "-",
            "Subdomains": "yes" if self.subdomains else "-",
        }

    def as_list(self) -> list[str]:
        """Sorted list of supported capability names."""
        return sorted(name for name in ProviderCategory.ALL if self.supports(name))


class ProviderHealth(SchemaVersioned):
    """Result of a provider health check."""

    provider: str
    ok: bool = False
    status: str = ProviderStatus.UNKNOWN
    message: str = ""
    latency_ms: float = 0.0
    checked_at: str = Field(default_factory=utc_now_iso)
    #: Only populated when the provider actually reports quota information.
    quota_limit: int | None = None
    quota_remaining: int | None = None
    quota_reset_at: str | None = None


class ProviderBudget(SchemaVersioned):
    """Per-provider usage tracking (the "budget engine")."""

    provider: str
    requests: int = 0
    successes: int = 0
    failures: int = 0
    rate_limited: int = 0
    timeouts: int = 0
    cache_hits: int = 0
    bytes_received: int = 0
    total_latency_ms: float = 0.0
    last_request_at: str | None = None
    last_error: str = ""
    #: ``True`` when the circuit breaker is currently open.
    circuit_open: bool = False
    circuit_opened_at: str | None = None

    def record_success(self, latency_ms: float = 0.0, *, size: int = 0) -> None:
        """Account for a successful request."""
        self.requests += 1
        self.successes += 1
        self.total_latency_ms += max(0.0, latency_ms)
        self.bytes_received += max(0, size)
        self.last_request_at = utc_now_iso()

    def record_failure(self, error: str = "", *, latency_ms: float = 0.0) -> None:
        """Account for a failed request."""
        self.requests += 1
        self.failures += 1
        self.total_latency_ms += max(0.0, latency_ms)
        self.last_error = error[:300]
        self.last_request_at = utc_now_iso()

    def record_rate_limited(self) -> None:
        """Account for a 429 response."""
        self.requests += 1
        self.rate_limited += 1
        self.failures += 1
        self.last_error = "HTTP 429 (rate limited)"
        self.last_request_at = utc_now_iso()

    def record_cache_hit(self) -> None:
        """Account for a served-from-cache response."""
        self.cache_hits += 1

    @property
    def average_latency_ms(self) -> float:
        """Mean latency across successful requests."""
        return self.total_latency_ms / self.successes if self.successes else 0.0

    @property
    def failure_rate(self) -> float:
        """Fraction of requests that failed."""
        return self.failures / self.requests if self.requests else 0.0

    @property
    def estimated_usage(self) -> int:
        """Requests actually sent to the provider (excludes cache hits)."""
        return self.requests


class ProviderInfo(SchemaVersioned):
    """Static + runtime description of a provider."""

    name: str
    category: str = ProviderCategory.ENRICHMENT
    description: str = ""
    homepage: str = ""
    #: Environment variables that provide credentials for this provider.
    env_vars: list[str] = Field(default_factory=list)
    requires_credentials: bool = False
    capabilities: ProviderCapabilities = Field(default_factory=ProviderCapabilities)
    #: Rate limits the provider documents (0 = unknown/unpublished).
    rate_limit_per_minute: float = 0.0
    #: ``False`` when the provider is free/keyless (e.g. crt.sh, RDAP).
    commercial: bool = False
    enabled: bool = True
    status: str = ProviderStatus.UNKNOWN
    #: Set when the provider was skipped for a policy reason.
    status_reason: str = ""
    health: ProviderHealth | None = None
    budget: ProviderBudget = Field(default_factory=lambda: ProviderBudget(provider=""))

    def __init__(self, **data: Any) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**data)
        if not self.budget.provider:
            self.budget.provider = self.name

    @property
    def needs_key(self) -> bool:
        """``True`` when credentials must be configured before use."""
        return self.requires_credentials

    def supports(self, capability: str) -> bool:
        return self.capabilities.supports(capability)


class ProviderQueryResult(SchemaVersioned):
    """Canonical result of any provider query.

    Providers must normalize their responses into this shape; the rest of
    DNScope never touches provider-specific JSON.
    """

    provider: str
    query: str
    ok: bool = True
    #: Canonical observation categories returned.
    hostnames: list[str] = Field(default_factory=list)
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    ip_records: list[dict[str, Any]] = Field(default_factory=list)
    threat_indicators: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)
    generic: list[dict[str, Any]] = Field(default_factory=list)
    source: SourceRecord = Field(default_factory=SourceRecord)
    confidence: Confidence = Confidence.MEDIUM
    quality: EvidenceQuality = EvidenceQuality.OBSERVED
    cached: bool = False
    request_count: int = 1
    latency_ms: float = 0.0
    error: str = ""
    #: Number of raw items received before normalization/dedup.
    raw_count: int = 0
    warnings: list[str] = Field(default_factory=list)

    @field_validator("provider", "query", mode="before")
    @classmethod
    def _str(cls, value: Any) -> Any:
        return str(value)

    @property
    def observation_count(self) -> int:
        """Total normalized observations returned."""
        return (
            len(self.hostnames)
            + len(self.certificates)
            + len(self.ip_records)
            + len(self.threat_indicators)
            + len(self.history)
            + len(self.generic)
        )

    def source_record(self) -> SourceRecord:
        """Provenance record for attribution in reports."""
        return self.source.model_copy()

    def merge(self, other: "ProviderQueryResult") -> "ProviderQueryResult":
        """Merge another result from the same provider (used for pagination)."""
        if self.provider != other.provider:
            raise ValueError("cannot merge results from different providers")
        self.hostnames = sorted({*self.hostnames, *other.hostnames})
        self.certificates.extend(other.certificates)
        self.ip_records.extend(other.ip_records)
        self.threat_indicators.extend(other.threat_indicators)
        self.history.extend(other.history)
        self.generic.extend(other.generic)
        self.request_count += other.request_count
        self.latency_ms += other.latency_ms
        self.raw_count += other.raw_count
        self.warnings.extend(other.warnings)
        return self

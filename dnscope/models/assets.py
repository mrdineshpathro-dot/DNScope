"""Asset models: the normalized inventory produced by correlation."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import (
    Confidence,
    EvidenceQuality,
    Observation,
    SchemaVersioned,
    ScopeStatus,
    SourceRecord,
)
from dnscope.utils.time_utils import parse_timestamp  # noqa: F401 - re-exported for subclasses


class AssetKind:
    """Node kinds in the DNScope asset graph."""

    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    ASN = "ASN"
    NS = "NS"
    MX = "MX"
    CNAME = "CNAME"
    CERTIFICATE = "CERTIFICATE"
    CA = "CA"
    CLOUD_PROVIDER = "CLOUD_PROVIDER"
    CDN = "CDN"
    WAF = "WAF"
    REGISTRAR = "REGISTRAR"
    THREAT_INDICATOR = "THREAT_INDICATOR"
    DNS_PROVIDER = "DNS_PROVIDER"
    TXT = "TXT"
    MAIL_PROVIDER = "MAIL_PROVIDER"

    ALL = (
        DOMAIN,
        SUBDOMAIN,
        IP,
        ASN,
        NS,
        MX,
        CNAME,
        CERTIFICATE,
        CA,
        CLOUD_PROVIDER,
        CDN,
        WAF,
        REGISTRAR,
        THREAT_INDICATOR,
        DNS_PROVIDER,
        TXT,
        MAIL_PROVIDER,
    )


class EdgeType:
    """Edge kinds in the DNScope asset graph."""

    RESOLVES_TO = "RESOLVES_TO"
    CNAME_TO = "CNAME_TO"
    USES_NS = "USES_NS"
    USES_MX = "USES_MX"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    ISSUED_TO = "ISSUED_TO"
    ISSUED_BY = "ISSUED_BY"
    HOSTED_BY = "HOSTED_BY"
    PROXIED_BY = "PROXIED_BY"
    REGISTERED_WITH = "REGISTERED_WITH"
    RELATED_TO = "RELATED_TO"
    OBSERVED_BY = "OBSERVED_BY"
    DELEGATED_TO = "DELEGATED_TO"
    PARENT_OF = "PARENT_OF"
    SHARES_IP = "SHARES_IP"
    PROTECTED_BY = "PROTECTED_BY"

    ALL = (
        RESOLVES_TO,
        CNAME_TO,
        USES_NS,
        USES_MX,
        BELONGS_TO_ASN,
        ISSUED_TO,
        ISSUED_BY,
        HOSTED_BY,
        PROXIED_BY,
        REGISTERED_WITH,
        RELATED_TO,
        OBSERVED_BY,
        DELEGATED_TO,
        PARENT_OF,
        SHARES_IP,
        PROTECTED_BY,
    )


class Asset(Observation):
    """Base asset. Every asset knows its kind, identity and provenance."""

    asset_id: str = ""
    kind: str = AssetKind.DOMAIN
    value: str
    label: str = ""
    confidence: Confidence = Confidence.UNKNOWN
    quality: EvidenceQuality = EvidenceQuality.OBSERVED
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    state: str = "UNKNOWN"
    attributes: dict[str, Any] = Field(default_factory=dict)
    sources: list[SourceRecord] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("value", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        return value if isinstance(value, str) else str(value)

    @property
    def identity(self) -> str:
        """Stable identity used for graph de-duplication."""
        return f"{self.kind}:{self.value.lower()}"

    def add_source(self, source: SourceRecord) -> None:
        """Attach provenance, keeping the list bounded and de-duplicated."""
        key = (source.provider, source.source)
        for existing in self.sources:
            if (existing.provider, existing.source) == key:
                existing.observed_at = max(existing.observed_at, source.observed_at)
                return
        self.sources.append(source)
        if len(self.sources) > 32:
            self.sources = self.sources[-32:]


class HostAsset(Asset):
    """A hostname asset (domain or subdomain) with its discovery context."""

    kind: str = AssetKind.SUBDOMAIN
    #: Discovery sources, e.g. ``["ct", "passive-dns"]``.
    discovery_sources: list[str] = Field(default_factory=list)
    #: ``RESOLVING``/``ACTIVE``/``NXDOMAIN``/... see the subdomain state machine.
    dns_state: str = "UNKNOWN"
    cname_target: str = ""
    resolved_ips: list[str] = Field(default_factory=list)
    ttl: int | None = None
    rcode: str = ""
    #: ``True`` when the name only has a CNAME and no A/AAAA answer.
    dangling_candidate: bool = False

    @property
    def is_active(self) -> bool:
        return self.dns_state == "ACTIVE"


class IPRecord(Asset):
    """An IP address observed for a target."""

    kind: str = AssetKind.IP
    ip: str
    version: int = 4
    ptr: list[str] = Field(default_factory=list)
    asn: str = ""
    organization: str = ""
    prefix: str = ""
    country: str = ""
    provider: str = ""
    is_cloud: bool = False
    is_cdn: bool = False
    hosted_domains: list[str] = Field(default_factory=list)

    @field_validator("ip", mode="before")
    @classmethod
    def _str(cls, value: Any) -> Any:
        return str(value)


class ASNRecord(Asset):
    """An autonomous system observed in the target's infrastructure."""

    kind: str = AssetKind.ASN
    asn: str
    organization: str = ""
    country: str = ""
    prefixes: list[str] = Field(default_factory=list)
    ip_count: int = 0
    domain_count: int = 0


class NameserverRecord(Asset):
    """An authoritative nameserver observed for a domain."""

    kind: str = AssetKind.NS
    nameserver: str
    provider: str = ""
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    asn: str = ""
    organization: str = ""
    response_time_ms: float | None = None
    available: bool = False
    ttl: int | None = None


class MailServerRecord(Asset):
    """An MX host observed for a domain."""

    kind: str = AssetKind.MX
    host: str
    preference: int = 10
    provider: str = ""
    resolves: bool = False


class CloudProvider(Asset):
    """A passive cloud/CDN/WAF identification with its evidence."""

    kind: str = AssetKind.CLOUD_PROVIDER
    provider: str
    category: str = "cloud"  # cloud | cdn | waf | dns | hosting
    evidence: list[str] = Field(default_factory=list)
    evidence_type: str = "cname"  # cname | asn | ip_range | tls | ptr | http
    confidence: Confidence = Confidence.MEDIUM
    quality: EvidenceQuality = EvidenceQuality.INFERRED
    match: str = ""

    def evidence_text(self) -> str:
        """Single-line evidence summary."""
        return "; ".join(self.evidence[:4]) or self.match


class CertificateAsset(Asset):
    """A certificate associated with the target's infrastructure."""

    kind: str = AssetKind.CERTIFICATE
    serial: str = ""
    fingerprint_sha256: str = ""
    issuer: str = ""
    common_name: str = ""
    subject_alternative_names: list[str] = Field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    #: Where the certificate observation came from: ``ct`` | ``tls`` | ``provider``.
    #: Named ``origin`` because ``Observation.source`` already holds the
    #: :class:`SourceRecord` provenance, and shadowing it with a string would
    #: break anything reading ``asset.source.provider``.
    origin: str = "ct"

    @property
    def identity(self) -> str:
        return f"CERTIFICATE:{self.fingerprint_sha256 or self.serial or self.common_name}".lower()


class AssetSearchHit(SchemaVersioned):
    """One match returned by ``dnscope assets search``."""

    query: str
    asset: Asset | None = None
    kind: str = ""
    value: str = ""
    score: float = 1.0
    matched_on: str = ""
    related: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class AssetSummary(SchemaVersioned):
    """Aggregated asset counts for ``dnscope assets`` and the dashboard."""

    domains: int = 0
    subdomains: int = 0
    ips: int = 0
    asns: int = 0
    certificates: int = 0
    nameservers: int = 0
    mail_servers: int = 0
    cloud_providers: int = 0
    cdns: int = 0
    total: int = 0
    in_scope: int = 0
    out_of_scope: int = 0

    def compute_total(self) -> int:
        """Recompute ``total`` from the individual counters."""
        self.total = (
            self.domains
            + self.subdomains
            + self.ips
            + self.asns
            + self.certificates
            + self.nameservers
            + self.mail_servers
        )
        return self.total

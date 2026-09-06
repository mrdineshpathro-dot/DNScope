"""Email-security models: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, MX and CAA."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import Confidence, Evidence, SchemaVersioned


class SPFRecord(SchemaVersioned):
    """Mechanically parsed SPF record.

    Expansion is always bounded: ``lookups_used``/``max_lookups`` make the RFC
    10-DNS-lookup limit observable instead of implicit, and ``cycle_detected``
    records when expansion stopped because an ``include`` loop was found.
    """

    domain: str
    record: str = ""
    found: bool = False
    version: str = ""
    mechanisms: list[dict[str, Any]] = Field(default_factory=list)
    modifiers: list[dict[str, Any]] = Field(default_factory=list)
    all_mechanism: str = ""  # +all | -all | ~all | ?all | "" when absent
    redirect: str = ""
    explanation: str = ""
    #: ``include``/``a``/``mx``/``ptr``/``exists`` targets in evaluation order.
    include_chain: list[str] = Field(default_factory=list)
    lookup_count: int = 0
    max_lookups: int = 10
    lookup_depth: int = 0
    max_depth: int = 5
    cycle_detected: bool = False
    truncated: bool = False
    #: Expanded IPv4/IPv6 senders, when expansion was permitted.
    authorized_networks: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None
    confidence: Confidence = Confidence.HIGH

    @field_validator("domain", "redirect", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    @property
    def lookup_budget_remaining(self) -> int:
        """Lookups left before the RFC 7208 limit would be exceeded."""
        return max(0, self.max_lookups - self.lookup_count)

    def mechanism_types(self) -> list[str]:
        """Distinct mechanism names present in the record."""
        seen: list[str] = []
        for mechanism in self.mechanisms:
            name = str(mechanism.get("type", "")).lower()
            if name and name not in seen:
                seen.append(name)
        return seen

    def has_mechanism(self, name: str) -> bool:
        """``True`` when the record contains ``name`` (case-insensitive)."""
        return name.lower() in self.mechanism_types()


class DMARCRecord(SchemaVersioned):
    """Parsed ``_dmarc`` TXT policy."""

    domain: str
    record: str = ""
    found: bool = False
    version: str = ""
    policy: str = ""  # p=
    subdomain_policy: str = ""  # sp=
    percentage: int | None = None  # pct=
    rua: list[str] = Field(default_factory=list)
    ruf: list[str] = Field(default_factory=list)
    adkim: str = ""  # r | s
    aspf: str = ""  # r | s
    fo: str = ""  # 0 | 1 | d | s
    ri: int | None = None  # reporting interval
    #: Organizational-domain record inherited by subdomains.
    inherited_from: str = ""
    issues: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None

    @field_validator("domain", "policy", "subdomain_policy", "adkim", "aspf", "fo", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    @property
    def effective_policy(self) -> str:
        """``sp`` when present, else ``p`` (what applies to subdomains)."""
        return self.subdomain_policy or self.policy

    @property
    def enforces(self) -> bool:
        """``True`` when the policy rejects or quarantines at 100%."""
        return self.policy in ("quarantine", "reject") and (self.percentage in (None, 100))

    def summary(self) -> str:
        """One-line configuration summary."""
        parts = [f"p={self.policy or 'n/a'}"]
        if self.subdomain_policy:
            parts.append(f"sp={self.subdomain_policy}")
        if self.percentage is not None and self.percentage != 100:
            parts.append(f"pct={self.percentage}")
        if self.rua:
            parts.append(f"rua={len(self.rua)}")
        if self.ruf:
            parts.append(f"ruf={len(self.ruf)}")
        return " ".join(parts)


class DKIMResult(SchemaVersioned):
    """Result of an explicitly requested DKIM selector lookup."""

    domain: str
    selector: str
    record: str = ""
    found: bool = False
    query_name: str = ""
    version: str = ""
    key_type: str = ""
    hash_algorithm: str = ""
    service: str = ""
    flags: str = ""
    key_size_bits: int | None = None
    revoked: bool = False
    issues: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None

    @field_validator("domain", "selector", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value


class CAARecordInfo(SchemaVersioned):
    """Parsed CAA record set."""

    domain: str
    records: list[str] = Field(default_factory=list)
    found: bool = False
    issue: list[str] = Field(default_factory=list)
    issuewild: list[str] = Field(default_factory=list)
    iodef: list[str] = Field(default_factory=list)
    critical_flags: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None

    @property
    def restricts_issuance(self) -> bool:
        """``True`` when the record set actually limits which CAs may issue.

        A CAA record containing only ``contactemail`` or ``iodef`` is *not* an
        issuance restriction, and treating it as one would hide a real gap.
        """
        return bool(self.issue or self.issuewild)

    def issuers(self) -> list[str]:
        """Distinct authorized issuers (issue + issuewild)."""
        return sorted(set(self.issue) | set(self.issuewild))


class MTASTSResult(SchemaVersioned):
    """MTA-STS (RFC 8461) discovery result.

    Only DNS-based indicators are collected (the ``_mta-sts`` TXT record and
    policy host resolution). Fetching the policy over HTTPS requires explicit
    authorization and is recorded separately.
    """

    domain: str
    found: bool = False
    record: str = ""
    version: str = ""
    policy_id: str = ""
    policy_host: str = ""
    policy_host_resolves: bool | None = None
    policy_fetched: bool = False
    policy_mode: str = ""
    policy_max_age: int | None = None
    policy_mx: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None


class TLSRPTResult(SchemaVersioned):
    """TLS-RPT (RFC 8460) ``_smtp._tls`` TXT discovery result."""

    domain: str
    found: bool = False
    record: str = ""
    version: str = ""
    rua: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None


class EmailSecurityReport(SchemaVersioned):
    """Aggregate mail-security posture for a domain."""

    domain: str
    spf: SPFRecord | None = None
    dmarc: DMARCRecord | None = None
    dkim: list[DKIMResult] = Field(default_factory=list)
    dkim_selectors_tested: list[str] = Field(default_factory=list)
    mta_sts: MTASTSResult | None = None
    tls_rpt: TLSRPTResult | None = None
    mx_hosts: list[str] = Field(default_factory=list)
    mx_providers: list[str] = Field(default_factory=list)
    caa: CAARecordInfo | None = None
    #: ``True`` when enough selectors were tested to comment on DKIM at all.
    dkim_conclusive: bool = False
    issues: list[str] = Field(default_factory=list)
    score: float | None = None

    def mechanisms_present(self) -> dict[str, bool]:
        """Which protections were observed."""
        return {
            "spf": bool(self.spf and self.spf.found),
            "dmarc": bool(self.dmarc and self.dmarc.found),
            "dkim": any(result.found for result in self.dkim),
            "mx": bool(self.mx_hosts),
            "caa": bool(self.caa and self.caa.found),
            "mta_sts": bool(self.mta_sts and self.mta_sts.found),
            "tls_rpt": bool(self.tls_rpt and self.tls_rpt.found),
        }
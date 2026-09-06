"""The evidence bundle a rule set is evaluated against.

Rules never reach for a resolver or an HTTP client. Everything they may inspect
is assembled here first, so a rule can only reason about data DNScope actually
collected - and a reader can see exactly which observations were available when a
finding was (or was not) produced.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from pydantic import BaseModel, Field

from dnscope.models.common import Confidence, Evidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.utils.domains import normalize_hostname, parent_domain, registered_domain
from dnscope.utils.time_utils import now_utc, utc_now_iso


class RuleHit(BaseModel):
    """A rule's conclusion about one subject, with its evidence.

    A logic predicate returns zero or more hits; the engine turns each into a
    :class:`dnscope.models.findings.Finding`. Severity and confidence may be
    overridden per hit (a wildcard-matched host is less certain than one confirmed
    by two resolvers), but a hit without evidence is rejected.
    """

    #: Hostname, IP or other subject the hit is about.
    target: str
    #: Where inside the subject the issue lives.
    location: dict[str, Any] = Field(default_factory=dict)
    #: At least one entry with a query or response is required.
    evidence: list[Evidence] = Field(default_factory=list)
    #: Machine-readable detail carried into the finding's context.
    context: dict[str, Any] = Field(default_factory=dict)
    #: Optional per-hit overrides.
    severity: str = ""
    confidence: str = ""
    #: ``True`` when the conclusion needs more evidence before being trusted.
    needs_verification: bool = False
    #: Overrides the rule's description when the hit has specifics to add.
    description: str = ""
    #: Overrides the rule's title.
    title: str = ""

    @property
    def has_evidence(self) -> bool:
        """``True`` when at least one evidence entry carries content."""
        return any(item.query or item.response for item in self.evidence)

    def evidence_text(self) -> str:
        """Concatenated evidence summaries."""
        return "; ".join(item.summary() for item in self.evidence if item.query or item.response)


class ScanContext(SchemaVersioned):
    """Everything a rule set may inspect for one scan.

    Fields are optional by design: an offline run has no intelligence data, a
    ``dnscope dnssec`` run has no email report. Rules must therefore check what
    they were given, and the engine records which sections were absent so a
    missing finding is never mistaken for a clean result.
    """

    model_config = SchemaVersioned.model_config

    target: str
    workspace: str = "default"
    #: Apex answers, keyed by record type.
    dns: dict[str, Any] = Field(default_factory=dict)
    #: Answers for every hostname in scope, keyed by hostname.
    answers: dict[str, Any] = Field(default_factory=dict)
    #: Subdomain discovery result (may be ``None`` when discovery was skipped).
    discovery: Any = None
    #: Email security report (SPF/DMARC/DKIM/MTA-STS/TLS-RPT/MX/CAA).
    email: Any = None
    #: DNSSEC analysis for the apex zone.
    dnssec: Any = None
    #: Health/reliability/security scores.
    health: Any = None
    #: Intelligence report (registration, IP, ASN, certificates, threat).
    intelligence: Any = None
    #: Dangling-DNS indicators.
    takeover: list[Any] = Field(default_factory=list)
    #: Cloud/CDN/WAF/DNS-provider fingerprint matches.
    cloud: list[Any] = Field(default_factory=list)
    #: Built knowledge graph.
    graph: Any = None
    #: Correlation groups (shared infrastructure).
    correlations: list[Any] = Field(default_factory=list)
    #: Pre-computed observations from the intelligence layer.
    observations: list[dict[str, Any]] = Field(default_factory=list)
    #: Names of sections that were not collected, with the reason.
    unavailable: dict[str, str] = Field(default_factory=dict)
    #: Run flags that constrain what rules may conclude.
    offline: bool = False
    privacy: bool = False
    #: ``True`` when DNS answers came from a validating resolver.
    resolver_validating: bool = False
    #: Wildcard addresses detected for the zone (used to discount artifacts).
    wildcard_addresses: list[str] = Field(default_factory=list)
    #: Scan metadata reproduced in every finding's context.
    resolver: str = ""
    transport: str = ""
    profile: str = ""
    started_at: str = Field(default_factory=utc_now_iso)

    # ------------------------------------------------------------------ helpers

    @property
    def domain(self) -> str:
        """Registrable domain of the target."""
        return registered_domain(self.target) or self.target

    def rdata(self, rtype: str, hostname: str | None = None) -> list[str]:
        """Rdata values for ``rtype`` at the apex or one hostname."""
        if hostname is None:
            values = self.dns.get(rtype.upper())
            return list(values or [])
        answer = self.answers.get(normalize_hostname(hostname))
        if answer is None:
            return []
        return list(answer.values(rtype))

    def records(self, rtype: str, hostname: str | None = None) -> list[Any]:
        """Normalized records for ``rtype``."""
        if hostname is None:
            return list(self.dns.get(f"{rtype.upper()}_RECORDS") or [])
        answer = self.answers.get(normalize_hostname(hostname))
        if answer is None:
            return []
        query = answer.by_type(rtype)
        return list(query.records) if query else []

    def status(self, rtype: str, hostname: str | None = None) -> str:
        """Response status for a query (``""`` when it was never made)."""
        if hostname is None:
            return str(self.dns.get(f"{rtype.upper()}_STATUS") or "")
        answer = self.answers.get(normalize_hostname(hostname))
        if answer is None:
            return ""
        query = answer.by_type(rtype)
        return query.status if query else ""

    def has_records(self, rtype: str, hostname: str | None = None) -> bool:
        """``True`` when the query succeeded and returned records."""
        return bool(self.records(rtype, hostname))

    def subdomains(self, *, active_only: bool = False) -> list[Any]:
        """Discovered subdomains (empty when discovery did not run)."""
        if self.discovery is None:
            return []
        hosts = list(getattr(self.discovery, "hosts", []) or [])
        if active_only:
            hosts = [host for host in hosts if getattr(host, "is_active", False)]
        return hosts

    def in_scope_hosts(self) -> list[str]:
        """Every in-scope hostname known to this scan."""
        hosts = {self.target}
        hosts.update(
            normalize_hostname(getattr(host, "hostname", ""))
            for host in self.subdomains()
            if not getattr(host, "out_of_scope", False)
        )
        hosts.update(normalize_hostname(name) for name in self.answers)
        return sorted(item for item in hosts if item)

    def is_wildcard_artifact(self, hostname: str) -> bool:
        """``True`` when the host's addresses match the zone wildcard."""
        if not self.wildcard_addresses:
            return False
        addresses = set(self.rdata("A", hostname)) | set(self.rdata("AAAA", hostname))
        return bool(addresses) and addresses == set(self.wildcard_addresses)

    def evidence(
        self,
        query: str,
        response: str = "",
        *,
        record_type: str = "",
        provider: str = "dns",
        source: str = "",
        quality: str = EvidenceQuality.OBSERVED.value,
        confidence: str = Confidence.HIGH.value,
        raw: dict[str, Any] | None = None,
    ) -> Evidence:
        """Build an :class:`Evidence` entry with full provenance."""
        return Evidence(
            query=query,
            response=response,
            record_type=record_type,
            observed_at=now_utc(),
            source=SourceRecord(
                provider=provider,
                source=source or self.resolver or provider,
                observed_at=utc_now_iso(),
                confidence=Confidence.coerce(confidence),
                quality=EvidenceQuality.coerce(quality),
            ),
            raw=raw or {},
        )

    def describe_availability(self) -> dict[str, Any]:
        """Which sections were present, for the report's methodology block."""
        present = {
            name: getattr(self, name) is not None
            for name in ("discovery", "email", "dnssec", "health", "intelligence", "graph")
        }
        return {
            "present": {key: value for key, value in present.items() if value},
            "absent": dict(self.unavailable),
            "offline": self.offline,
            "privacy": self.privacy,
            "resolver_validating": self.resolver_validating,
        }


def build_context(
    target: str,
    *,
    workspace: str = "default",
    dns: dict[str, Any] | None = None,
    answers: dict[str, Any] | None = None,
    discovery: Any = None,
    email: Any = None,
    dnssec: Any = None,
    health: Any = None,
    intelligence: Any = None,
    takeover: Sequence[Any] = (),
    cloud: Sequence[Any] = (),
    graph: Any = None,
    correlations: Sequence[Any] = (),
    offline: bool = False,
    privacy: bool = False,
    resolver: str = "",
    transport: str = "",
    profile: str = "",
    unavailable: dict[str, str] | None = None,
) -> ScanContext:
    """Assemble a :class:`ScanContext` from analyzer output.

    Intelligence observations are folded in here so rules see one flat list of
    evidence-backed observations regardless of which engine produced them.
    """
    context = ScanContext(
        target=normalize_hostname(target),
        workspace=workspace,
        dns=dict(dns or {}),
        answers=dict(answers or {}),
        discovery=discovery,
        email=email,
        dnssec=dnssec,
        health=health,
        intelligence=intelligence,
        takeover=list(takeover),
        cloud=list(cloud),
        graph=graph,
        correlations=list(correlations),
        offline=offline,
        privacy=privacy,
        resolver=resolver,
        transport=transport,
        profile=profile,
        unavailable=dict(unavailable or {}),
    )
    if intelligence is not None and hasattr(intelligence, "observations"):
        context.observations.extend(intelligence.observations())
    if dnssec is not None:
        context.resolver_validating = bool(getattr(dnssec, "resolver_validating", False))
    if discovery is not None:
        wildcard = getattr(discovery, "wildcard", None)
        if isinstance(wildcard, dict):
            context.wildcard_addresses = [str(item) for item in wildcard.get("addresses", [])]
    return context


__all__ = ["RuleHit", "ScanContext", "build_context"]

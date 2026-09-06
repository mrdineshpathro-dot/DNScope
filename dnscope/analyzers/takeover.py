"""Dangling-DNS (subdomain takeover) indicator engine.

SAFETY MODEL
------------
DNScope only *observes*. This module never:

* claims, registers or provisions an external resource
* authenticates to any provider
* modifies DNS records
* sends exploit payloads or takeover attempts

A result of ``POSSIBLE_DANGLING_DNS`` means: "this CNAME points at a
third-party service, and the service's endpoint did not resolve / returned the
provider's documented 'not found' signature". That is a *cleanup* signal for the
asset owner, not a claim that takeover is possible or was performed.
"""

from __future__ import annotations

from typing import Any, Iterable

from pydantic import BaseModel, Field

from dnscope.analyzers.cloud import FingerprintStore
from dnscope.dns.engine import DNSEngine
from dnscope.models.common import Confidence, Evidence, SchemaVersioned, SourceRecord
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.time_utils import utc_now_iso

#: The only state this engine ever emits.
POSSIBLE_DANGLING_DNS = "POSSIBLE_DANGLING_DNS"
#: State when nothing suspicious was observed.
NOT_DANGLING = "NOT_DANGLING"
#: State when the CNAME target resolves but looks unclaimed by other signals.
UNKNOWN = "UNKNOWN"


class TakeoverIndicator(BaseModel):
    """A possible dangling-DNS observation."""

    hostname: str
    state: str = UNKNOWN
    provider: str = ""
    service: str = ""
    cname_target: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: str = Confidence.LOW.value
    recommendation: str = ""
    observed_at: str = Field(default_factory=utc_now_iso)
    #: What we actually saw at the CNAME target.
    target_status: str = ""
    #: ``True`` when the CNAME target did not resolve at all.
    target_unresolvable: bool = False
    #: ``True`` when HTTP inspection (explicitly enabled) matched a signature.
    http_signature_matched: bool = False
    needs_verification: bool = True
    #: Whether scope allowed us to look at this host.
    in_scope: bool = True

    @property
    def is_dangling(self) -> bool:
        """``True`` when the indicator is a dangling-DNS candidate."""
        return self.state == POSSIBLE_DANGLING_DNS

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return {
            "hostname": self.hostname,
            "state": self.state,
            "provider": self.provider,
            "service": self.service,
            "cname_target": self.cname_target,
            "target_status": self.target_status,
            "target_unresolvable": self.target_unresolvable,
            "http_signature_matched": self.http_signature_matched,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "observed_at": self.observed_at,
            "needs_verification": self.needs_verification,
            "in_scope": self.in_scope,
        }

    def evidence_record(self) -> Evidence:
        """Evidence object for the finding model."""
        return Evidence(
            query=f"CNAME {self.hostname}; A {self.cname_target}",
            response=f"{self.target_status}; provider={self.provider or 'unknown'}",
            record_type="CNAME",
            source=SourceRecord(
                provider="dnscope.takeover",
                source="fingerprints/takeover.yaml",
                confidence=Confidence.coerce(self.confidence),
            ),
        )

    def summary(self) -> str:
        """One-line summary for terminal output."""
        if not self.is_dangling:
            return f"{self.hostname}: {self.state}"
        return (
            f"{self.hostname} -> {self.cname_target} "
            f"[{self.provider or 'unknown provider'}] {self.confidence} confidence"
        )


class TakeoverAnalyzer:
    """Passive dangling-DNS detection."""

    def __init__(
        self,
        engine: DNSEngine | None,
        *,
        store: FingerprintStore | None = None,
        http_metadata: dict[str, str] | None = None,
        enabled: bool = True,
    ) -> None:
        self.engine = engine
        self.store = store or FingerprintStore()
        #: Optional HTTP metadata supplied by an explicitly enabled inspection.
        self.http_metadata = http_metadata or {}
        self.enabled = enabled

    # ------------------------------------------------------------------ public

    def analyze(self, hostname: str, cname_target: str | None = None) -> TakeoverIndicator:
        """Analyze one hostname for dangling-DNS indicators."""
        indicator = TakeoverIndicator(hostname=normalize_hostname(hostname))
        if not self.enabled:
            indicator.state = UNKNOWN
            indicator.evidence.append("takeover analysis disabled")
            return indicator

        target = normalize_hostname(cname_target or "")
        if not target:
            target = self._find_cname(indicator.hostname)
        if not target:
            indicator.state = NOT_DANGLING
            indicator.evidence.append("no CNAME record observed")
            return indicator

        indicator.cname_target = target
        definition = self._match_provider(target)
        if definition is None:
            indicator.state = NOT_DANGLING
            indicator.evidence.append(f"CNAME target {target} does not match a known service fingerprint")
            return indicator

        indicator.provider = str(definition.get("provider", ""))
        indicator.service = str(definition.get("service", ""))

        status = self._resolve_target(target)
        indicator.target_status = status["status"]
        indicator.target_unresolvable = bool(status["unresolvable"])
        indicator.evidence.append(f"CNAME {indicator.hostname} -> {target}")
        indicator.evidence.append(
            f"A {target} -> {status['detail']}" if status["detail"] else f"A {target} -> {status['status']}"
        )

        signature = self._match_http_signature(definition)
        if signature:
            indicator.http_signature_matched = True
            indicator.evidence.append(f"HTTP response matched provider signature: {signature!r}")

        requires_nxdomain = bool(definition.get("requires_nxdomain", True))
        if indicator.target_unresolvable and (not requires_nxdomain or status["status"] == "NXDOMAIN"):
            indicator.state = POSSIBLE_DANGLING_DNS
            indicator.confidence = _combine_confidence(definition.get("confidence"), "high")
            indicator.evidence.append("CNAME target does not resolve (NXDOMAIN)")
        elif indicator.http_signature_matched:
            indicator.state = POSSIBLE_DANGLING_DNS
            indicator.confidence = _combine_confidence(definition.get("confidence"), "high")
        elif status["status"] in ("NOERROR",):
            indicator.state = NOT_DANGLING
            indicator.confidence = Confidence.MEDIUM.value
            indicator.evidence.append("CNAME target resolves, so no dangling indicator is raised")
        else:
            indicator.state = UNKNOWN
            indicator.confidence = Confidence.LOW.value
            indicator.evidence.append(
                f"CNAME target returned {status['status']}; insufficient evidence to conclude"
            )

        # Remediation advice is attached only to an actual indicator: showing
        # "remove the CNAME" next to a NOT_DANGLING result reads as a finding
        # that does not exist.
        if indicator.state == POSSIBLE_DANGLING_DNS:
            indicator.recommendation = str(definition.get("recommendation", "")).strip()
        return indicator

    def analyze_many(self, hostnames: Iterable[str]) -> list[TakeoverIndicator]:
        """Analyze several hostnames, returning only notable results and states."""
        return [self.analyze(host) for host in hostnames]

    # ---------------------------------------------------------------- internals

    def _find_cname(self, hostname: str) -> str:
        """Look up the CNAME target for ``hostname``."""
        if self.engine is None:
            return ""
        result = self.engine.query(hostname, "CNAME")
        if not result.ok:
            return ""
        for record in result.records:
            target = str((record.parsed or {}).get("target", ""))
            if target:
                return target
        return result.cname_chain[-1] if result.cname_chain else ""

    def _resolve_target(self, target: str) -> dict[str, Any]:
        """Resolve the CNAME target and describe the outcome."""
        if self.engine is None:
            return {"status": "UNKNOWN", "unresolvable": False, "detail": ""}
        a_result = self.engine.query(target, "A")
        if a_result.nxdomain:
            return {"status": "NXDOMAIN", "unresolvable": True, "detail": "no such name"}
        if a_result.ok and a_result.answer_count:
            return {
                "status": "NOERROR",
                "unresolvable": False,
                "detail": ", ".join(sorted(a_result.rdata_set())[:4]),
            }
        if a_result.ok and a_result.cname_chain:
            return {
                "status": "NOERROR",
                "unresolvable": False,
                "detail": f"chained to {a_result.cname_chain[-1]}",
            }
        return {
            "status": a_result.status,
            "unresolvable": False,
            "detail": a_result.error or "no answer",
        }

    def _match_provider(self, target: str) -> dict[str, Any] | None:
        """Find the fingerprint definition matching ``target``."""
        normalized = normalize_hostname(target)
        for definition in self.store.indicators():
            for pattern in definition.get("cname_patterns") or []:
                needle = str(pattern).lower()
                if needle.startswith(".") and (
                    normalized.endswith(needle) or normalized == needle[1:]
                ):
                    return definition
                if not needle.startswith(".") and needle in normalized:
                    return definition
        return None

    def _match_http_signature(self, definition: dict[str, Any]) -> str:
        """Match the provider's documented 'not found' signature, if we have HTTP data."""
        if not self.http_metadata:
            return ""
        body = str(self.http_metadata.get("body", "")).lower()
        title = str(self.http_metadata.get("title", "")).lower()
        haystack = f"{body} {title}"
        for signature in definition.get("http_signatures") or []:
            text = str(signature).lower()
            if text and text in haystack:
                return str(signature)
        return ""


def _combine_confidence(fingerprint_confidence: Any, evidence_confidence: str) -> str:
    """Combine fingerprint confidence with observed-evidence confidence."""
    ranking = {"high": 3, "medium": 2, "low": 1}
    base = str(fingerprint_confidence or "low").lower()
    observed = evidence_confidence.lower()
    # A "low" fingerprint backed by an NXDOMAIN is still only medium: the
    # service could simply be temporarily misconfigured.
    if ranking.get(base, 1) >= 3 and ranking.get(observed, 1) >= 3:
        return Confidence.HIGH.value
    if ranking.get(base, 1) >= 2:
        return Confidence.MEDIUM.value
    return Confidence.LOW.value


__all__ = [
    "NOT_DANGLING",
    "POSSIBLE_DANGLING_DNS",
    "UNKNOWN",
    "TakeoverAnalyzer",
    "TakeoverIndicator",
]

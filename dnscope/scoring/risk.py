"""Risk engine.

Turns findings, health scores and asset counts into a single explainable risk
score plus an attack-surface summary. The engine never invents risk: it weights
findings that already carry evidence, and reports the arithmetic it used.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from pydantic import Field

from dnscope.models.common import Confidence, SchemaVersioned, Severity
from dnscope.models.findings import Finding

#: Weight applied to each severity level when computing the risk score.
SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL.value: 10.0,
    Severity.HIGH.value: 5.0,
    Severity.MEDIUM.value: 2.0,
    Severity.LOW.value: 0.5,
    Severity.INFO.value: 0.0,
}

#: Confidence multiplier - a low-confidence finding counts for less.
CONFIDENCE_WEIGHTS: dict[str, float] = {
    Confidence.HIGH.value: 1.0,
    Confidence.MEDIUM.value: 0.6,
    Confidence.LOW.value: 0.25,
    Confidence.UNKNOWN.value: 0.1,
}


class RiskScore(SchemaVersioned):
    """Aggregate risk for one target."""

    target: str
    score: float = 0.0
    level: str = "LOW"
    max_possible: float = 100.0
    findings: int = 0
    weighted_findings: float = 0.0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    #: Contribution of each finding to the score (explainability).
    contributions: list[dict[str, Any]] = Field(default_factory=list)
    confidence: str = Confidence.MEDIUM.value
    notes: list[str] = Field(default_factory=list)

    @property
    def normalized(self) -> float:
        """Score clamped to 0-100."""
        return max(0.0, min(100.0, self.score))

    def summary(self) -> str:
        """One-line summary."""
        return f"{self.target}: risk {self.normalized:.1f}/100 ({self.level}) from {self.findings} finding(s)"


class AttackSurfaceSummary(SchemaVersioned):
    """What the scan actually saw, in counts."""

    target: str
    domains: int = 0
    subdomains: int = 0
    active_subdomains: int = 0
    inactive_subdomains: int = 0
    dangling_candidates: int = 0
    ips: int = 0
    asns: int = 0
    nameservers: int = 0
    mail_servers: int = 0
    certificates: int = 0
    expiring_certificates: int = 0
    expired_certificates: int = 0
    cloud_providers: list[str] = Field(default_factory=list)
    cdns: list[str] = Field(default_factory=list)
    dns_providers: list[str] = Field(default_factory=list)
    external_dependencies: int = 0
    out_of_scope_assets: int = 0
    #: Distinct registrable domains touched by CNAME/MX/NS records.
    third_party_domains: list[str] = Field(default_factory=list)

    def summary(self) -> str:
        """One-line summary for terminal output."""
        return (
            f"{self.target}: {self.subdomains} subdomain(s) "
            f"({self.active_subdomains} active), {self.ips} IP(s), {self.asns} ASN(s), "
            f"{self.certificates} certificate(s), {self.dangling_candidates} dangling candidate(s)"
        )


class RiskEngine:
    """Computes :class:`RiskScore` and :class:`AttackSurfaceSummary`."""

    def __init__(
        self,
        *,
        severity_weights: dict[str, float] | None = None,
        confidence_weights: dict[str, float] | None = None,
        saturation: float = 60.0,
    ) -> None:
        self.severity_weights = severity_weights or dict(SEVERITY_WEIGHTS)
        self.confidence_weights = confidence_weights or dict(CONFIDENCE_WEIGHTS)
        #: Weighted points at which the score saturates at 100.
        self.saturation = max(1.0, saturation)

    # ------------------------------------------------------------------- risk

    def score(self, target: str, findings: Iterable[Finding]) -> RiskScore:
        """Compute the weighted risk score for ``target``."""
        active = [finding for finding in findings if finding.is_active]
        result = RiskScore(target=target, findings=len(active))
        result.by_severity = dict(Counter(finding.severity.value for finding in active))
        result.by_category = dict(Counter(finding.category or "general" for finding in active))

        total = 0.0
        for finding in active:
            weight = self.severity_weights.get(finding.severity.value, 0.0)
            confidence = self.confidence_weights.get(finding.confidence.value, 0.1)
            contribution = weight * confidence
            total += contribution
            result.contributions.append(
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule.rule_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "contribution": round(contribution, 2),
                }
            )
        result.contributions.sort(key=lambda item: -item["contribution"])
        result.weighted_findings = round(total, 2)
        result.score = round(min(100.0, total / self.saturation * 100.0), 1)
        result.level = self._level(result)
        result.confidence = self._confidence(active)
        if not active:
            result.notes.append("no active findings; score reflects the absence of detected issues only")
        return result

    def _level(self, result: RiskScore) -> str:
        """Map a score to a risk level."""
        score = result.normalized
        if score >= 70:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "MINIMAL"

    def _confidence(self, findings: list[Finding]) -> str:
        """Overall confidence in the score (driven by finding confidence)."""
        if not findings:
            return Confidence.LOW.value
        high = sum(1 for finding in findings if finding.confidence is Confidence.HIGH)
        if high / len(findings) >= 0.6:
            return Confidence.HIGH.value
        if high / len(findings) >= 0.3:
            return Confidence.MEDIUM.value
        return Confidence.LOW.value

    # --------------------------------------------------------- attack surface

    def attack_surface(self, target: str, assets: dict[str, Any]) -> AttackSurfaceSummary:
        """Build the attack-surface summary from asset counts."""
        subdomains = assets.get("subdomains") or []
        certificates = assets.get("certificates") or []
        summary = AttackSurfaceSummary(
            target=target,
            domains=int(assets.get("domain_count") or (1 if target else 0)),
            subdomains=len(subdomains),
            active_subdomains=sum(1 for item in subdomains if _is_active(item)),
            inactive_subdomains=sum(1 for item in subdomains if not _is_active(item)),
            dangling_candidates=sum(1 for item in subdomains if _is_dangling(item)),
            ips=len(set(assets.get("ips") or [])),
            asns=len(set(assets.get("asns") or [])),
            nameservers=len(set(assets.get("nameservers") or [])),
            mail_servers=len(set(assets.get("mail_servers") or [])),
            certificates=len(certificates),
            expiring_certificates=sum(1 for cert in certificates if _expiring_soon(cert)),
            expired_certificates=sum(1 for cert in certificates if _expired(cert)),
            cloud_providers=sorted(set(assets.get("cloud_providers") or [])),
            cdns=sorted(set(assets.get("cdns") or [])),
            dns_providers=sorted(set(assets.get("dns_providers") or [])),
            third_party_domains=sorted(set(assets.get("third_party_domains") or [])),
            out_of_scope_assets=int(assets.get("out_of_scope_count") or 0),
        )
        summary.external_dependencies = (
            len(summary.cloud_providers) + len(summary.cdns) + len(summary.third_party_domains)
        )
        return summary

    # ------------------------------------------------------------ aggregation

    def top_risks(self, findings: Iterable[Finding], limit: int = 5) -> list[dict[str, Any]]:
        """Highest-impact findings for the executive summary."""
        ranked = sorted(
            (finding for finding in findings if finding.is_active),
            key=lambda finding: (
                -finding.severity.rank,
                -self.confidence_weights.get(finding.confidence.value, 0.0),
                finding.finding_id,
            ),
        )
        return [
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "target": finding.target,
                "evidence": finding.evidence_text(),
                "recommendation": finding.recommendation,
            }
            for finding in ranked[:limit]
        ]

    def recommendations(self, findings: Iterable[Finding], limit: int = 10) -> list[dict[str, str]]:
        """Deduplicated remediation guidance, worst findings first."""
        seen: set[str] = set()
        rows: list[dict[str, str]] = []
        for finding in sorted(
            (f for f in findings if f.is_active and f.recommendation),
            key=lambda item: -item.severity.rank,
        ):
            key = finding.recommendation.lower()
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "severity": finding.severity.value,
                    "finding": finding.title,
                    "recommendation": finding.recommendation,
                    "rule_id": finding.rule.rule_id,
                }
            )
            if len(rows) >= limit:
                break
        return rows

    def posture(self, risk: RiskScore, health: dict[str, Any] | None = None) -> dict[str, Any]:
        """Security-posture block used by the executive report.

        ``health`` may be a :class:`DNSHealthReport.to_dict()` payload (nested
        breakdowns) or a flat ``{"health": 81.0, ...}`` mapping; both are
        reduced to plain numbers here so report consumers get one shape.
        """
        scores = health or {}
        return {
            "risk_score": risk.normalized,
            "risk_level": risk.level,
            "findings": risk.findings,
            "by_severity": risk.by_severity,
            "dns_health": _score_value(scores.get("health")),
            "dns_reliability": _score_value(scores.get("reliability")),
            "dns_security": _score_value(scores.get("security")),
            "dns_grade": _grade_value(scores.get("health")),
            "overall_dns_score": _score_value(scores.get("overall")),
            "confidence": risk.confidence,
            "notes": risk.notes,
        }


def _score_value(value: Any) -> float | None:
    """Reduce a score cell to a number (breakdown dicts carry ``score``)."""
    if isinstance(value, dict):
        raw = value.get("score")
    else:
        raw = value
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _grade_value(value: Any) -> str:
    """Extract a letter grade when the caller supplied a breakdown dict."""
    if isinstance(value, dict):
        return str(value.get("grade") or "")
    return ""


def _is_active(subdomain: Any) -> bool:
    """``True`` when a subdomain record shows it currently resolves."""
    if isinstance(subdomain, dict):
        state = str(subdomain.get("state") or subdomain.get("dns_state") or "").upper()
        if state:
            return state in ("ACTIVE", "RESOLVING", "CNAME_ONLY")
        return bool(subdomain.get("ips") or subdomain.get("resolved_ips"))
    return bool(getattr(subdomain, "is_active", False))


def _is_dangling(subdomain: Any) -> bool:
    """``True`` when the subdomain is flagged as a dangling candidate."""
    if isinstance(subdomain, dict):
        state = str(subdomain.get("state") or subdomain.get("dns_state") or "").upper()
        return state == "POSSIBLE_DANGLING" or bool(subdomain.get("dangling_candidate"))
    return bool(getattr(subdomain, "dangling_candidate", False))


def _expiring_soon(certificate: Any, days: int = 30) -> bool:
    """``True`` when a certificate expires within ``days``."""
    remaining = _days_remaining(certificate)
    return remaining is not None and 0 <= remaining < days


def _expired(certificate: Any) -> bool:
    """``True`` when a certificate has already expired."""
    remaining = _days_remaining(certificate)
    return remaining is not None and remaining < 0


def _days_remaining(certificate: Any) -> float | None:
    """Days until expiry from a certificate model or mapping."""
    if hasattr(certificate, "days_until_expiry"):
        return certificate.days_until_expiry()
    if isinstance(certificate, dict):
        from dnscope.utils.time_utils import now_utc, parse_timestamp

        moment = parse_timestamp(str(certificate.get("not_after") or ""))
        if moment is None:
            return None
        return (moment - now_utc()).total_seconds() / 86400.0
    return None


__all__ = ["AttackSurfaceSummary", "RiskEngine", "RiskScore"]

"""DNS health, reliability and security-configuration scoring.

Scores are *explainable*: every point deducted is attached to a named check with
the observation that produced it, so a report can always answer "why is this
domain scored 74?".

Three scores are produced, because they answer different questions:

``health``
    Is the zone's DNS correctly and completely configured?
``reliability``
    Will resolution keep working (redundancy, TTLs, consistency)?
``security``
    Which DNS-level protections are in place (DNSSEC, CAA, mail authentication)?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from pydantic import BaseModel, Field

from dnscope.models.common import Confidence, SchemaVersioned, Severity
from dnscope.models.dns import DNSAnswer, NameserverProfile

#: Outcome of a single scored check.
CHECK_PASS = "PASS"
CHECK_WARN = "WARN"
CHECK_FAIL = "FAIL"
CHECK_UNKNOWN = "UNKNOWN"


@dataclass
class ScoreCheck:
    """One explainable scoring input."""

    name: str
    category: str
    status: str
    weight: float
    detail: str = ""
    evidence: str = ""
    severity: str = Severity.INFO.value

    @property
    def earned(self) -> float:
        """Points earned by this check (0..weight)."""
        if self.status == CHECK_PASS:
            return self.weight
        if self.status == CHECK_WARN:
            return self.weight * 0.5
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready representation."""
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "weight": round(self.weight, 2),
            "earned": round(self.earned, 2),
            "detail": self.detail,
            "evidence": self.evidence,
            "severity": self.severity,
        }


class ScoreBreakdown(SchemaVersioned):
    """A score plus the checks that produced it."""

    name: str
    score: float = 0.0
    maximum: float = 100.0
    checks: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    confidence: str = Confidence.MEDIUM.value

    @property
    def grade(self) -> str:
        """Letter grade derived from the percentage score."""
        if self.score >= 90:
            return "A"
        if self.score >= 80:
            return "B"
        if self.score >= 70:
            return "C"
        if self.score >= 60:
            return "D"
        return "F"

    @property
    def rating(self) -> str:
        """Human rating derived from the percentage score."""
        if self.score >= 90:
            return "excellent"
        if self.score >= 80:
            return "good"
        if self.score >= 70:
            return "fair"
        if self.score >= 60:
            return "weak"
        return "poor"

    def failures(self) -> list[dict[str, Any]]:
        """Checks that did not pass, worst first."""
        order = {CHECK_FAIL: 0, CHECK_WARN: 1, CHECK_UNKNOWN: 2, CHECK_PASS: 3}
        return sorted(
            (check for check in self.checks if check["status"] != CHECK_PASS),
            key=lambda check: (order.get(check["status"], 9), -check["weight"]),
        )

    def explanation(self) -> str:
        """Multi-line explanation for terminal and markdown reports."""
        lines = [f"{self.name}: {self.score:.1f}/{self.maximum:.0f} ({self.grade} - {self.rating})"]
        for check in self.checks:
            lines.append(
                f"  [{check['status']:7}] {check['name']:32} "
                f"{check['earned']:.1f}/{check['weight']:.1f}  {check['detail']}"
            )
        if self.summary:
            lines.append(f"  summary: {self.summary}")
        return "\n".join(lines)


class _Scorer:
    """Accumulates weighted checks and produces a 0-100 breakdown."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.checks: list[ScoreCheck] = []

    def add(
        self,
        name: str,
        category: str,
        status: str,
        weight: float,
        *,
        detail: str = "",
        evidence: str = "",
        severity: str = Severity.INFO.value,
    ) -> ScoreCheck:
        """Record one check."""
        check = ScoreCheck(
            name=name,
            category=category,
            status=status,
            weight=float(weight),
            detail=detail,
            evidence=evidence,
            severity=severity,
        )
        self.checks.append(check)
        return check

    def build(self, *, confidence: str = Confidence.MEDIUM.value, summary: str = "") -> ScoreBreakdown:
        """Compute the final breakdown."""
        total_weight = sum(check.weight for check in self.checks)
        earned = sum(check.earned for check in self.checks)
        score = (earned / total_weight * 100.0) if total_weight else 0.0
        return ScoreBreakdown(
            name=self.name,
            score=round(score, 1),
            maximum=100.0,
            checks=[check.to_dict() for check in self.checks],
            summary=summary,
            confidence=confidence,
        )


class DNSHealthReport(BaseModel):
    """The three DNS scores for one target."""

    target: str
    health: ScoreBreakdown = Field(default_factory=lambda: ScoreBreakdown(name="health"))
    reliability: ScoreBreakdown = Field(default_factory=lambda: ScoreBreakdown(name="reliability"))
    security: ScoreBreakdown = Field(default_factory=lambda: ScoreBreakdown(name="security"))
    #: 0..100 weighted blend used for dashboards and ranking.
    overall: float = 0.0
    #: Checks that failed across all three scores (deduplicated by name).
    issues: list[dict[str, Any]] = Field(default_factory=list)
    confidence: str = Confidence.MEDIUM.value

    def compute_overall(self) -> float:
        """Weighted blend: correctness matters most, security second."""
        self.overall = round(
            self.health.score * 0.4 + self.reliability.score * 0.3 + self.security.score * 0.3, 1
        )
        return self.overall

    def collect_issues(self) -> list[dict[str, Any]]:
        """Flatten failed checks into a single list."""
        seen: set[str] = set()
        issues: list[dict[str, Any]] = []
        for breakdown in (self.health, self.reliability, self.security):
            for check in breakdown.failures():
                key = f"{breakdown.name}:{check['name']}"
                if key in seen:
                    continue
                seen.add(key)
                issues.append({**check, "score": breakdown.name})
        self.issues = issues
        return issues

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        """JSON-ready dictionary including the overall blend."""
        data = {
            "target": self.target,
            "overall": self.overall,
            "confidence": self.confidence,
            "health": self.health.to_dict(),
            "reliability": self.reliability.to_dict(),
            "security": self.security.to_dict(),
            "issues": self.issues,
        }
        return data

    def summary_table(self) -> list[dict[str, Any]]:
        """Rows for the terminal score table."""
        return [
            {"score": "DNS Health", "value": f"{self.health.score:.1f}", "grade": self.health.grade},
            {
                "score": "DNS Reliability",
                "value": f"{self.reliability.score:.1f}",
                "grade": self.reliability.grade,
            },
            {
                "score": "DNS Security Configuration",
                "value": f"{self.security.score:.1f}",
                "grade": self.security.grade,
            },
            {"score": "Overall", "value": f"{self.overall:.1f}", "grade": ""},
        ]


class DNSHealthAnalyzer:
    """Produces :class:`DNSHealthReport` from observed DNS data.

    The analyzer only scores what it was given: if a check has no evidence it is
    marked ``UNKNOWN`` and contributes nothing, which prevents a score from
    implying more assurance than the scan actually provided.
    """

    def __init__(self, *, minimum_nameservers: int = 2) -> None:
        self.minimum_nameservers = max(1, minimum_nameservers)

    def analyze(
        self,
        target: str,
        answer: DNSAnswer,
        *,
        nameserver_profiles: Iterable[NameserverProfile] | None = None,
        dnssec: dict[str, Any] | None = None,
        email: dict[str, Any] | None = None,
        resolver_consistency: dict[str, Any] | None = None,
        rdap: dict[str, Any] | None = None,
    ) -> DNSHealthReport:
        """Score one target's DNS configuration."""
        report = DNSHealthReport(target=target)
        report.health = self._health(target, answer, rdap=rdap)
        report.reliability = self._reliability(
            target, answer, nameserver_profiles or [], resolver_consistency
        )
        report.security = self._security(target, answer, dnssec or {}, email or {})
        report.compute_overall()
        report.collect_issues()
        report.confidence = Confidence.HIGH.value if answer.record_count else Confidence.LOW.value
        return report

    # ------------------------------------------------------------------ health

    def _health(self, target: str, answer: DNSAnswer, *, rdap: dict[str, Any] | None) -> ScoreBreakdown:
        scorer = _Scorer("health")
        ns = answer.values("NS")
        soa = answer.by_type("SOA")
        a = answer.by_type("A")
        aaaa = answer.by_type("AAAA")
        mx = answer.by_type("MX")
        cname = answer.by_type("CNAME")

        scorer.add(
            "ns_records_present",
            "delegation",
            CHECK_PASS if ns else CHECK_FAIL,
            20.0,
            detail=f"{len(ns)} nameservers" if ns else "no NS records returned",
            evidence=", ".join(ns[:6]),
            severity=Severity.HIGH.value,
        )
        scorer.add(
            "soa_present",
            "zone",
            CHECK_PASS if (soa and soa.ok and soa.answer_count) else CHECK_FAIL,
            10.0,
            detail=(soa.values[0] if soa and soa.values else "no SOA record"),
            severity=Severity.MEDIUM.value,
        )
        if soa and soa.records:
            parsed = soa.records[0].parsed
            scorer.add(
                "soa_serial_valid",
                "zone",
                CHECK_PASS if int(parsed.get("serial", 0)) > 0 else CHECK_WARN,
                5.0,
                detail=f"serial={parsed.get('serial')}",
            )
            expire = int(parsed.get("expire", 0))
            scorer.add(
                "soa_expire_sane",
                "zone",
                CHECK_PASS if expire >= 604_800 else CHECK_WARN,
                5.0,
                detail=f"expire={expire}s ({expire // 86400}d)",
                severity=Severity.LOW.value,
            )

        if a is not None:
            if a.ok and a.answer_count:
                status, detail = CHECK_PASS, f"{a.answer_count} A record(s)"
            elif cname and cname.answer_count:
                status, detail = CHECK_PASS, "delegated via CNAME"
            elif a.nxdomain:
                status, detail = CHECK_FAIL, "apex does not resolve (NXDOMAIN)"
            else:
                status, detail = CHECK_WARN, "no A record at the apex"
            scorer.add(
                "apex_resolves",
                "resolution",
                status,
                20.0,
                detail=detail,
                evidence=", ".join(a.values[:6]) if a.values else "",
                severity=Severity.HIGH.value if status == CHECK_FAIL else Severity.MEDIUM.value,
            )

        scorer.add(
            "ipv6_support",
            "resolution",
            CHECK_PASS if (aaaa and aaaa.answer_count) else CHECK_WARN,
            10.0,
            detail=f"{aaaa.answer_count if aaaa else 0} AAAA record(s)",
            severity=Severity.LOW.value,
        )

        if mx is not None:
            null_mx = any(value.strip() in ("0 .", "0 .") for value in mx.values)
            if null_mx:
                status, detail = CHECK_PASS, "null MX declared (domain does not accept mail)"
            elif mx.answer_count:
                status, detail = CHECK_PASS, f"{mx.answer_count} MX record(s)"
            else:
                status, detail = CHECK_UNKNOWN, "no MX records (mail may be handled elsewhere)"
            scorer.add("mx_configuration", "mail", status, 10.0, detail=detail)

        ttl_issue = self._ttl_assessment(answer)
        scorer.add(
            "ttl_configuration",
            "caching",
            ttl_issue[0],
            10.0,
            detail=ttl_issue[1],
            severity=Severity.LOW.value,
        )

        if rdap:
            expiration = str(rdap.get("expiration_date") or "")
            status = CHECK_UNKNOWN
            detail = "no expiration date published"
            if expiration:
                days = _days_until(expiration)
                if days is None:
                    detail = f"expiration={expiration}"
                elif days < 30:
                    status, detail = CHECK_FAIL, f"domain expires in {days:.0f} days"
                elif days < 90:
                    status, detail = CHECK_WARN, f"domain expires in {days:.0f} days"
                else:
                    status, detail = CHECK_PASS, f"expires in {days:.0f} days"
            scorer.add(
                "registration_expiry",
                "registration",
                status,
                10.0,
                detail=detail,
                severity=Severity.HIGH.value if status == CHECK_FAIL else Severity.LOW.value,
            )
        return scorer.build(summary="correctness and completeness of the zone's DNS data")

    # ------------------------------------------------------------- reliability

    def _reliability(
        self,
        target: str,
        answer: DNSAnswer,
        profiles: list[NameserverProfile],
        consistency: dict[str, Any] | None,
    ) -> ScoreBreakdown:
        scorer = _Scorer("reliability")
        nameservers = sorted({value.strip(".").lower() for value in answer.values("NS")})
        count = len(nameservers)

        if count == 0:
            status, detail = CHECK_FAIL, "no nameservers observed"
        elif count < self.minimum_nameservers:
            status, detail = CHECK_FAIL, f"only {count} nameserver (minimum {self.minimum_nameservers})"
        elif count <= 7:
            status, detail = CHECK_PASS, f"{count} nameservers"
        else:
            status, detail = CHECK_WARN, f"{count} nameservers (unusually many)"
        scorer.add(
            "nameserver_redundancy",
            "redundancy",
            status,
            25.0,
            detail=detail,
            evidence=", ".join(nameservers),
            severity=Severity.HIGH.value if status == CHECK_FAIL else Severity.LOW.value,
        )

        providers = {ns_provider(item) for item in nameservers if ns_provider(item)}
        if not nameservers:
            provider_status, provider_detail = CHECK_UNKNOWN, "cannot assess provider spread"
        elif len(providers) == 1:
            provider_status = CHECK_WARN
            provider_detail = f"single provider dependency: {next(iter(providers))}"
        else:
            provider_status = CHECK_PASS
            provider_detail = f"{len(providers)} distinct providers: {', '.join(sorted(providers))}"
        scorer.add(
            "nameserver_provider_diversity",
            "redundancy",
            provider_status,
            15.0,
            detail=provider_detail,
            severity=Severity.MEDIUM.value if provider_status == CHECK_WARN else Severity.INFO.value,
        )

        if profiles:
            reachable = [p for p in profiles if p.available]
            slow = [p for p in reachable if (p.response_time_ms or 0) > 500]
            if not reachable:
                status, detail = CHECK_WARN, "no authoritative nameserver answered a direct query"
            elif len(reachable) == len(profiles):
                status, detail = CHECK_PASS, f"{len(reachable)}/{len(profiles)} nameservers reachable"
            else:
                status = CHECK_WARN
                detail = f"{len(reachable)}/{len(profiles)} nameservers reachable"
            if slow:
                detail += f"; {len(slow)} slower than 500ms"
            scorer.add(
                "nameserver_availability",
                "availability",
                status,
                20.0,
                detail=detail,
                evidence=", ".join(
                    f"{p.nameserver}={p.response_time_ms:.0f}ms" for p in reachable[:5]
                ),
            )
            inconsistent = [p for p in profiles if not p.consistent]
            scorer.add(
                "nameserver_consistency",
                "consistency",
                CHECK_PASS if not inconsistent else CHECK_WARN,
                10.0,
                detail="all nameservers agree"
                if not inconsistent
                else f"{len(inconsistent)} nameserver(s) answered differently",
            )
        else:
            scorer.add(
                "nameserver_availability",
                "availability",
                CHECK_UNKNOWN,
                20.0,
                detail="nameservers were not probed",
            )
            scorer.add(
                "nameserver_consistency",
                "consistency",
                CHECK_UNKNOWN,
                10.0,
                detail="nameservers were not probed",
            )

        if consistency:
            if consistency.get("consistent"):
                status, detail = CHECK_PASS, "all resolvers returned the same data"
            else:
                status = CHECK_WARN
                detail = f"resolvers disagree: {', '.join(consistency.get('distinct_values', [])[:5])}"
            failures = consistency.get("failures") or {}
            if failures:
                detail += f"; {len(failures)} resolver(s) did not answer"
            scorer.add("resolver_consistency", "consistency", status, 15.0, detail=detail)
        else:
            scorer.add(
                "resolver_consistency",
                "consistency",
                CHECK_UNKNOWN,
                15.0,
                detail="resolver comparison was not performed",
            )

        ttl_issue = self._ttl_assessment(answer)
        scorer.add(
            "ttl_sane",
            "caching",
            CHECK_PASS if ttl_issue[0] != CHECK_FAIL else CHECK_WARN,
            15.0,
            detail=ttl_issue[1],
        )
        return scorer.build(summary="likelihood that resolution keeps working under failure")

    # ---------------------------------------------------------------- security

    def _security(
        self,
        target: str,
        answer: DNSAnswer,
        dnssec: dict[str, Any],
        email: dict[str, Any],
    ) -> ScoreBreakdown:
        scorer = _Scorer("security")

        status_value = str(dnssec.get("status") or "UNKNOWN").upper()
        if status_value in ("SIGNED", "VALIDATED"):
            status, detail = CHECK_PASS, f"zone is signed ({dnssec.get('algorithm_summary', 'DNSSEC')})"
        elif status_value == "PARTIAL":
            status, detail = CHECK_WARN, "partial DNSSEC data observed"
        elif status_value == "UNSIGNED":
            status, detail = CHECK_FAIL, "zone is not signed (no DS/DNSKEY)"
        else:
            status, detail = CHECK_UNKNOWN, "DNSSEC was not evaluated"
        scorer.add(
            "dnssec_signed",
            "authentication",
            status,
            25.0,
            detail=detail,
            evidence=str(dnssec.get("evidence", "")),
            severity=Severity.MEDIUM.value,
        )

        caa = answer.by_type("CAA")
        if caa is None:
            scorer.add("caa_present", "certificate", CHECK_UNKNOWN, 20.0, detail="CAA was not queried")
        elif caa.answer_count:
            issuers = sorted({record.parsed.get("value", "") for record in caa.records})
            scorer.add(
                "caa_present",
                "certificate",
                CHECK_PASS,
                20.0,
                detail=f"{caa.answer_count} CAA record(s)",
                evidence=", ".join(item for item in issuers if item),
            )
        else:
            scorer.add(
                "caa_present",
                "certificate",
                CHECK_FAIL,
                20.0,
                detail=f"CAA query returned {caa.status} with no records",
                evidence=f"CAA {target} -> {caa.status}/{caa.answer_count}",
                severity=Severity.LOW.value,
            )

        spf = email.get("spf") or {}
        if not email:
            scorer.add("spf_present", "mail", CHECK_UNKNOWN, 15.0, detail="mail security was not evaluated")
        else:
            all_mechanism = str(spf.get("all_mechanism") or "")
            if not spf.get("found"):
                status, detail = CHECK_FAIL, "no SPF record published"
            elif all_mechanism in ("-all", "~all"):
                status, detail = CHECK_PASS, f"SPF present with {all_mechanism}"
            elif all_mechanism in ("+all", "?all"):
                status, detail = CHECK_WARN, f"SPF present but permissive ({all_mechanism})"
            else:
                status, detail = CHECK_WARN, "SPF present without an 'all' mechanism"
            scorer.add(
                "spf_present",
                "mail",
                status,
                15.0,
                detail=detail,
                evidence=str(spf.get("record", ""))[:160],
                severity=Severity.MEDIUM.value if status != CHECK_PASS else Severity.INFO.value,
            )

        dmarc = email.get("dmarc") or {}
        if not email:
            scorer.add("dmarc_present", "mail", CHECK_UNKNOWN, 20.0, detail="mail security was not evaluated")
        else:
            policy = str(dmarc.get("policy") or "")
            if not dmarc.get("found"):
                status, detail = CHECK_FAIL, "no DMARC policy published"
                severity = Severity.MEDIUM.value
            elif policy == "reject":
                status, detail, severity = CHECK_PASS, "DMARC p=reject", Severity.INFO.value
            elif policy == "quarantine":
                status, detail, severity = CHECK_PASS, "DMARC p=quarantine", Severity.INFO.value
            else:
                status, detail = CHECK_WARN, f"DMARC present but p={policy or 'none'} (monitoring only)"
                severity = Severity.LOW.value
            scorer.add(
                "dmarc_present",
                "mail",
                status,
                20.0,
                detail=detail,
                evidence=str(dmarc.get("record", ""))[:160],
                severity=severity,
            )

        dkim = email.get("dkim") or []
        if dkim:
            found = [item for item in dkim if item.get("found")]
            if found:
                status = CHECK_PASS
                detail = f"DKIM keys found for selectors: {', '.join(item['selector'] for item in found)}"
            else:
                status = CHECK_UNKNOWN
                detail = (
                    f"no DKIM key at tested selectors "
                    f"({', '.join(str(item.get('selector')) for item in dkim)}); "
                    "other selectors may exist"
                )
            scorer.add("dkim_present", "mail", status, 10.0, detail=detail)
        else:
            scorer.add(
                "dkim_present",
                "mail",
                CHECK_UNKNOWN,
                10.0,
                detail="no DKIM selectors were tested",
            )

        transport = email.get("mta_sts") or {}
        if email:
            scorer.add(
                "mta_sts",
                "mail",
                CHECK_PASS if transport.get("found") else CHECK_WARN,
                5.0,
                detail="MTA-STS policy record present" if transport.get("found") else "no MTA-STS record",
                severity=Severity.LOW.value,
            )
            tlsrpt = email.get("tls_rpt") or {}
            scorer.add(
                "tls_rpt",
                "mail",
                CHECK_PASS if tlsrpt.get("found") else CHECK_WARN,
                5.0,
                detail="TLS-RPT record present" if tlsrpt.get("found") else "no TLS-RPT record",
                severity=Severity.INFO.value,
            )
        else:
            scorer.add("mta_sts", "mail", CHECK_UNKNOWN, 5.0, detail="mail security was not evaluated")
            scorer.add("tls_rpt", "mail", CHECK_UNKNOWN, 5.0, detail="mail security was not evaluated")
        return scorer.build(summary="DNS-level protections that are actually configured")

    # ----------------------------------------------------------------- helpers

    def _ttl_assessment(self, answer: DNSAnswer) -> tuple[str, str]:
        """Assess TTL sanity across the answer set."""
        ttls = [record.ttl for query in answer.queries for record in query.records if record.ttl]
        if not ttls:
            return CHECK_UNKNOWN, "no TTLs observed"
        minimum, maximum = min(ttls), max(ttls)
        if minimum < 30:
            return CHECK_WARN, f"very low TTL observed ({minimum}s)"
        if maximum > 604_800:
            return CHECK_WARN, f"very high TTL observed ({maximum}s = {maximum // 86400}d)"
        return CHECK_PASS, f"TTL range {minimum}s-{maximum}s"


# ------------------------------------------------------------------ utilities


def ns_provider(nameserver: str) -> str:
    """Infer the DNS provider from a nameserver hostname (passive heuristic)."""
    host = nameserver.strip(".").lower()
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    second = labels[-2]
    known = {
        "cloudflare": "cloudflare",
        "awsdns": "aws-route53",
        "ultradns": "ultradns",
        "akam": "akamai",
        "dyn": "oracle-dyn",
        "dnsmadeeasy": "dns-made-easy",
        "dnsimple": "dnsimple",
        "linode": "linode",
        "digitalocean": "digitalocean",
        "googledomains": "google",
        "google": "google",
        "azure-dns": "azure",
        "azure": "azure",
        "vercel-dns": "vercel",
        "netlify": "netlify",
        "hover": "hover",
        "registrar-servers": "namecheap",
        "domaincontrol": "godaddy",
        "secureserver": "godaddy",
        "hostgator": "hostgator",
        "bluehost": "bluehost",
        "ovh": "ovh",
        "hetzner": "hetzner",
    }
    return known.get(second, second)


def _days_until(value: str) -> float | None:
    """Days from now until an ISO timestamp (``None`` when unparseable)."""
    from dnscope.utils.time_utils import now_utc, parse_timestamp

    moment = parse_timestamp(value)
    if moment is None:
        return None
    return (moment - now_utc()).total_seconds() / 86400.0


__all__ = [
    "CHECK_FAIL",
    "CHECK_PASS",
    "CHECK_UNKNOWN",
    "CHECK_WARN",
    "DNSHealthAnalyzer",
    "DNSHealthReport",
    "ScoreBreakdown",
    "ScoreCheck",
    "ns_provider",
]

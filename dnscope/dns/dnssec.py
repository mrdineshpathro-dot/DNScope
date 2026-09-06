"""DNSSEC analysis.

DNScope reports what is *observable*: whether the zone publishes DNSKEY/DS
records, which algorithms and key sizes are used, whether signatures are within
their validity window, and whether the resolver set the AD bit.

It deliberately does **not** claim that a chain of trust was validated end to
end - DNScope is not a validating resolver, and saying otherwise would be a
false security assurance.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from dnscope.models.common import Confidence, SchemaVersioned
from dnscope.models.dns import DNSAnswer, DNSQueryResult, DNSSECStatus

#: Algorithms considered weak by current guidance (RFC 8624).
WEAK_ALGORITHMS = {1, 3, 5, 6}  # RSA/MD5, DSA/SHA-1, RSA/SHA-1, DSA-NSEC3-SHA1
#: Minimum RSA key size we call out as small.
MIN_RSA_BITS = 2048


class KeyInfo(SchemaVersioned):
    """One DNSKEY observation."""

    flags: int = 0
    zone_key: bool = False
    secure_entry_point: bool = False
    revoked: bool = False
    protocol: int = 3
    algorithm: int = 0
    algorithm_name: str = ""
    key_size_bits: int | None = None
    role: str = ""  # KSK | ZSK | unknown


class DNSSECAnalysis(SchemaVersioned):
    """Aggregated DNSSEC state for a domain."""

    domain: str
    status: str = DNSSECStatus.UNKNOWN
    ds_records: list[dict[str, Any]] = Field(default_factory=list)
    keys: list[KeyInfo] = Field(default_factory=list)
    rrsig_types: list[str] = Field(default_factory=list)
    rrsig_expired: list[str] = Field(default_factory=list)
    nsec_present: bool = False
    nsec3_present: bool = False
    nsec3_opt_out: bool = False
    nsec3_iterations: int | None = None
    ad_bit_observed: bool = False
    resolver: str = ""
    algorithms: list[str] = Field(default_factory=list)
    algorithm_summary: str = ""
    issues: list[dict[str, Any]] = Field(default_factory=list)
    evidence: str = ""
    confidence: str = Confidence.MEDIUM.value
    #: ``True`` when the resolver performed validation (AD set on our query).
    resolver_validating: bool = False

    @property
    def signed(self) -> bool:
        """``True`` when DNSSEC material was observed."""
        return self.status in (DNSSECStatus.SIGNED, DNSSECStatus.VALIDATED, DNSSECStatus.PARTIAL)

    def summary(self) -> str:
        """One-line summary for terminal output."""
        if self.status == DNSSECStatus.UNKNOWN:
            return "DNSSEC: not evaluated"
        parts = [f"DNSSEC: {self.status}"]
        if self.keys:
            parts.append(f"{len(self.keys)} key(s)")
        if self.algorithm_summary:
            parts.append(self.algorithm_summary)
        if self.rrsig_expired:
            parts.append(f"{len(self.rrsig_expired)} expired signature type(s)")
        return " - ".join(parts)


class DNSSECAnalyzer:
    """Turns DNSSEC query results into an explainable :class:`DNSSECAnalysis`."""

    def analyze(self, domain: str, answer: DNSAnswer) -> DNSSECAnalysis:
        """Analyze DNSSEC data already present in ``answer``."""
        analysis = DNSSECAnalysis(domain=domain)
        dnskey = answer.by_type("DNSKEY")
        ds = answer.by_type("DS")
        rrsig = answer.by_type("RRSIG")
        nsec = answer.by_type("NSEC")
        nsec3 = answer.by_type("NSEC3")

        resolvers: set[str] = set()
        ad_seen = False
        for query in (dnskey, ds, rrsig, nsec, nsec3):
            if query is None:
                continue
            if query.meta.resolver:
                resolvers.add(query.meta.resolver)
            ad_seen = ad_seen or query.meta.authentic_data
        analysis.resolver = ",".join(sorted(resolvers))
        analysis.ad_bit_observed = ad_seen
        analysis.resolver_validating = ad_seen

        if ds is not None and ds.ok:
            analysis.ds_records = [record.parsed for record in ds.records]
        if dnskey is not None and dnskey.ok:
            for record in dnskey.records:
                parsed = record.parsed or {}
                key = KeyInfo(
                    flags=int(parsed.get("flags", 0)),
                    zone_key=bool(parsed.get("zone_key")),
                    secure_entry_point=bool(parsed.get("secure_entry_point")),
                    revoked=bool(parsed.get("revoke")),
                    protocol=int(parsed.get("protocol", 3)),
                    algorithm=int(parsed.get("algorithm", 0)),
                    algorithm_name=str(parsed.get("algorithm_name", "")),
                    key_size_bits=parsed.get("key_size_bits"),
                    role=_key_role(parsed),
                )
                analysis.keys.append(key)
        if rrsig is not None and rrsig.ok:
            self._analyze_rrsig(rrsig, analysis)
        if nsec is not None and nsec.ok and nsec.answer_count:
            analysis.nsec_present = True
        if nsec3 is not None and nsec3.ok and nsec3.answer_count:
            analysis.nsec3_present = True
            parsed = nsec3.records[0].parsed if nsec3.records else {}
            analysis.nsec3_opt_out = bool(parsed.get("opt_out"))
            analysis.nsec3_iterations = parsed.get("iterations")

        # RRSIGs also arrive inside the answer set of a signed query.
        for query in answer.queries:
            for record in query.records:
                if record.rtype == "RRSIG":
                    parsed = record.parsed or {}
                    covered = str(parsed.get("type_covered", "")).upper()
                    if covered and covered not in analysis.rrsig_types:
                        analysis.rrsig_types.append(covered)

        analysis.algorithms = sorted({key.algorithm_name for key in analysis.keys if key.algorithm_name})
        analysis.algorithm_summary = ", ".join(analysis.algorithms)
        self._classify(analysis, dnskey, ds)
        self._find_issues(analysis)
        analysis.evidence = self._evidence(analysis, dnskey, ds)
        return analysis

    # ---------------------------------------------------------------- internals

    def _classify(
        self,
        analysis: DNSSECAnalysis,
        dnskey: DNSQueryResult | None,
        ds: DNSQueryResult | None,
    ) -> None:
        """Decide the DNSSEC status from observed data."""
        has_keys = bool(analysis.keys)
        has_ds = bool(analysis.ds_records)
        if has_keys and has_ds:
            analysis.status = DNSSECStatus.VALIDATED if analysis.ad_bit_observed else DNSSECStatus.SIGNED
        elif has_keys or has_ds:
            analysis.status = DNSSECStatus.PARTIAL
        elif dnskey is not None or ds is not None:
            analysis.status = DNSSECStatus.UNSIGNED
        else:
            analysis.status = DNSSECStatus.UNKNOWN
        analysis.confidence = Confidence.HIGH.value if (has_keys or has_ds) else Confidence.MEDIUM.value

    def _analyze_rrsig(self, rrsig: DNSQueryResult, analysis: DNSSECAnalysis) -> None:
        """Record covered types and detect expired signatures."""
        from dnscope.utils.time_utils import now_utc, parse_timestamp

        for record in rrsig.records:
            parsed = record.parsed or {}
            covered = str(parsed.get("type_covered", "")).upper()
            if covered and covered not in analysis.rrsig_types:
                analysis.rrsig_types.append(covered)
            expiration = parse_timestamp(str(parsed.get("expiration", "")))
            if expiration is not None and expiration < now_utc() and covered not in analysis.rrsig_expired:
                analysis.rrsig_expired.append(covered)

    def _find_issues(self, analysis: DNSSECAnalysis) -> None:
        """Attach explainable issues to the analysis."""
        if analysis.status == DNSSECStatus.UNSIGNED:
            analysis.issues.append(
                {
                    "id": "DNSSEC-UNSIGNED-001",
                    "severity": "MEDIUM",
                    "detail": "zone publishes no DS/DNSKEY records; responses are not authenticated",
                }
            )
        if analysis.status == DNSSECStatus.PARTIAL:
            analysis.issues.append(
                {
                    "id": "DNSSEC-PARTIAL-001",
                    "severity": "MEDIUM",
                    "detail": "only part of the DNSSEC material was observed (keys without DS or vice versa)",
                }
            )
        for key in analysis.keys:
            if key.algorithm in WEAK_ALGORITHMS:
                analysis.issues.append(
                    {
                        "id": "DNSSEC-ALGO-001",
                        "severity": "MEDIUM",
                        "detail": f"weak DNSSEC algorithm in use: {key.algorithm_name} ({key.algorithm})",
                    }
                )
            if key.algorithm in (5, 7, 8, 10) and key.key_size_bits and key.key_size_bits < MIN_RSA_BITS:
                analysis.issues.append(
                    {
                        "id": "DNSSEC-KEYSIZE-001",
                        "severity": "LOW",
                        "detail": (
                            f"small RSA key observed: {key.key_size_bits} bits (role={key.role or 'unknown'})"
                        ),
                    }
                )
            if key.revoked:
                analysis.issues.append(
                    {
                        "id": "DNSSEC-REVOKE-001",
                        "severity": "LOW",
                        "detail": "a revoked DNSKEY is still published",
                    }
                )
        if analysis.rrsig_expired:
            analysis.issues.append(
                {
                    "id": "DNSSEC-EXPIRED-001",
                    "severity": "HIGH",
                    "detail": f"expired RRSIG observed for: {', '.join(analysis.rrsig_expired)}",
                }
            )
        if analysis.nsec3_opt_out:
            analysis.issues.append(
                {
                    "id": "DNSSEC-NSEC3-001",
                    "severity": "LOW",
                    "detail": "NSEC3 opt-out is set (unsigned delegations are not covered)",
                }
            )
        if analysis.nsec3_iterations and analysis.nsec3_iterations > 500:
            analysis.issues.append(
                {
                    "id": "DNSSEC-NSEC3-002",
                    "severity": "LOW",
                    "detail": f"high NSEC3 iteration count: {analysis.nsec3_iterations}",
                }
            )
        if analysis.status in (DNSSECStatus.SIGNED, DNSSECStatus.VALIDATED) and not analysis.keys:
            analysis.issues.append(
                {
                    "id": "DNSSEC-NOKEY-001",
                    "severity": "LOW",
                    "detail": "DS present but no DNSKEY records were returned",
                }
            )

    def _evidence(
        self,
        analysis: DNSSECAnalysis,
        dnskey: DNSQueryResult | None,
        ds: DNSQueryResult | None,
    ) -> str:
        """Build the evidence string that backs the status."""
        parts: list[str] = []
        if dnskey is not None:
            parts.append(f"DNSKEY {analysis.domain} -> {dnskey.status}/{dnskey.answer_count}")
        if ds is not None:
            parts.append(f"DS {analysis.domain} -> {ds.status}/{ds.answer_count}")
        if analysis.ad_bit_observed:
            parts.append("resolver set AD bit")
        if analysis.rrsig_types:
            parts.append(f"RRSIG covers: {', '.join(sorted(analysis.rrsig_types))}")
        return "; ".join(parts)


def _key_role(parsed: dict[str, Any]) -> str:
    """Classify a DNSKEY as KSK/ZSK from its flags (RFC 4034)."""
    zone_key = bool(parsed.get("zone_key"))
    sep = bool(parsed.get("secure_entry_point"))
    if zone_key and sep:
        return "KSK"
    if zone_key and not sep:
        return "ZSK"
    return "unknown"


def describe_algorithm(algorithm: int) -> str:
    """Human-readable DNSSEC algorithm name (re-exported for reports)."""
    from dnscope.dns.records import _dnssec_algorithm_name

    return _dnssec_algorithm_name(algorithm)


__all__ = ["DNSSECAnalysis", "DNSSECAnalyzer", "KeyInfo", "describe_algorithm"]

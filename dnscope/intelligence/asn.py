"""Autonomous System intelligence.

ASN facts come from the Team Cymru DNS service, which answers two queries:

* ``<reversed-ip>.origin.asn.cymru.com`` - the origin ASN for an address
* ``AS<number>.asn.cymru.com`` - the registered organization and country

Both are plain DNS TXT lookups, so ASN enrichment works with no API key and no
HTTP egress. Concentration analysis then answers the question operators actually
have: *how much of this target's infrastructure sits in a single network?*
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from pydantic import Field

from dnscope.dns.engine import DNSEngine
from dnscope.models.assets import ASNRecord
from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.utils.domains import ASN_ZONE, BOGON_ASNS, format_asn
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("intelligence.asn")

#: Above this share of addresses in one ASN we call the infrastructure concentrated.
CONCENTRATION_THRESHOLD = 0.6


class ASNIntelligence(SchemaVersioned):
    """Registration metadata for one autonomous system."""

    asn: str
    organization: str = ""
    country: str = ""
    rir: str = ""
    allocated: str = ""
    prefixes: list[str] = Field(default_factory=list)
    ip_count: int = 0
    domain_count: int = 0
    hosts: list[str] = Field(default_factory=list)
    is_bogon: bool = False
    #: Share of the target's addresses that live in this ASN.
    share: float = 0.0
    source: SourceRecord = Field(default_factory=SourceRecord)
    error: str = ""
    observed_at: str = Field(default_factory=utc_now_iso)

    @property
    def label(self) -> str:
        """``AS<number> - Organization`` for display."""
        return f"{self.asn} - {self.organization}" if self.organization else self.asn

    @property
    def number(self) -> int:
        """Numeric ASN (``0`` when unparseable)."""
        try:
            return int(self.asn.upper().lstrip("AS"))
        except (TypeError, ValueError):
            return 0

    def summary(self) -> str:
        """One-line human summary."""
        parts = [self.asn]
        if self.organization:
            parts.append(self.organization)
        if self.country:
            parts.append(f"({self.country})")
        parts.append(f"{self.ip_count} address(es)")
        if self.share:
            parts.append(f"{self.share * 100:.0f}% of target")
        return " ".join(parts)


class ASNSummary(SchemaVersioned):
    """Aggregate view of the ASNs behind a target."""

    target: str = ""
    asns: list[ASNIntelligence] = Field(default_factory=list)
    total_addresses: int = 0
    #: Largest share held by a single ASN.
    top_share: float = 0.0
    top_asn: str = ""
    #: ``True`` when a single ASN holds most of the addresses.
    concentrated: bool = False
    #: Distinct /24 (or /48) prefixes observed.
    prefixes: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def by_asn(self) -> dict[str, ASNIntelligence]:
        """Intelligence keyed by ASN."""
        return {item.asn: item for item in self.asns}

    def diversity_score(self) -> float:
        """Share of addresses *not* held by the dominant ASN (0..1).

        0.0 means one ASN holds everything; 0.6 means the largest ASN holds 40%.
        A single ASN for a large estate is a resilience and blast-radius concern
        rather than a vulnerability, so this is reported as context.
        """
        if not self.asns or not self.total_addresses:
            return 0.0
        return round(1.0 - self.top_share, 3)

    def known_asns(self) -> list[ASNIntelligence]:
        """ASNs that were actually identified (excludes the ``UNKNOWN`` bucket)."""
        return [item for item in self.asns if item.asn != "UNKNOWN"]

    def unresolved_addresses(self) -> int:
        """Addresses with no origin ASN published."""
        return sum(item.ip_count for item in self.asns if item.asn == "UNKNOWN")

    def risks(self) -> list[dict[str, Any]]:
        """Concentration and bogon observations."""
        issues: list[dict[str, Any]] = []
        if self.concentrated and self.top_asn:
            issues.append(
                {
                    "id": "ASN-CONCENTRATION",
                    "severity": "LOW",
                    "detail": (
                        f"{self.top_share * 100:.0f}% of identified addresses are in {self.top_asn}; "
                        "an incident in that network affects most of the estate"
                    ),
                    "evidence": f"top_asn={self.top_asn} share={self.top_share:.2f}",
                }
            )
        for item in self.asns:
            if item.is_bogon:
                issues.append(
                    {
                        "id": "ASN-BOGON",
                        "severity": "MEDIUM",
                        "detail": f"address space announces origin {item.asn}, which is not routable",
                        "evidence": f"asn={item.asn}",
                    }
                )
        identified = self.known_asns()
        if len(identified) == 1 and identified[0].ip_count > 1:
            issues.append(
                {
                    "id": "ASN-SINGLE",
                    "severity": "INFO",
                    "detail": "all identified addresses belong to a single autonomous system",
                    "evidence": f"asn={identified[0].asn} addresses={identified[0].ip_count}",
                }
            )
        unresolved = self.unresolved_addresses()
        if unresolved:
            issues.append(
                {
                    "id": "ASN-UNRESOLVED",
                    "severity": "INFO",
                    "detail": f"{unresolved} address(es) returned no origin ASN data",
                    "evidence": "team-cymru returned NXDOMAIN for these addresses",
                }
            )
        return issues

    def summary(self) -> str:
        """One-line human summary."""
        text = (
            f"{len(self.known_asns())} ASN(s) across {self.total_addresses} address(es); "
            f"top={self.top_asn or '-'} at {self.top_share * 100:.0f}%"
        )
        unresolved = self.unresolved_addresses()
        if unresolved:
            text += f"; {unresolved} address(es) without origin data"
        return text


class ASNIntelligenceEngine:
    """Looks up and rolls up autonomous-system data."""

    def __init__(self, engine: DNSEngine | None, *, zone: str = ASN_ZONE) -> None:
        self.engine = engine
        self.zone = zone
        self._cache: dict[str, ASNIntelligence] = {}

    # ------------------------------------------------------------------ public

    def lookup(self, asn: str) -> ASNIntelligence:
        """Return registration data for one ASN (cached within the process)."""
        normalized = format_asn(asn)
        if normalized in self._cache:
            return self._cache[normalized]
        info = ASNIntelligence(asn=normalized, is_bogon=normalized in BOGON_ASNS)
        info.source = SourceRecord(
            provider="team-cymru",
            source=f"{normalized}.{self.zone}",
            observed_at=utc_now_iso(),
            confidence=Confidence.HIGH,
            quality=EvidenceQuality.OBSERVED,
        )
        if self.engine is None:
            info.error = "no DNS engine available"
            return info
        name = f"{normalized}.{self.zone}"
        result = self.engine.query(name, "TXT")
        if not result.ok:
            info.error = f"{result.status}: {result.error}"
            return info
        parsed = self._parse(result.values)
        if parsed is None:
            info.error = "no ASN registration data published"
            return info
        info.organization = parsed["organization"]
        info.country = parsed["country"]
        info.rir = parsed["rir"]
        info.allocated = parsed["allocated"]
        self._cache[normalized] = info
        return info

    def rollup(self, report: Any, *, target: str = "") -> ASNSummary:
        """Aggregate an :class:`~dnscope.intelligence.ip_intel.IPIntelligenceReport`.

        The parameter is duck-typed (anything exposing ``records`` and
        ``target``) so this module does not import ``ip_intel`` - the two are
        used together but must not depend on each other.
        """
        summary = ASNSummary(target=target or report.target)
        grouped: dict[str, dict[str, Any]] = {}
        total = 0
        for record in report.records:
            asn = record.asn or "UNKNOWN"
            total += 1
            bucket = grouped.setdefault(
                asn, {"ips": [], "prefixes": set(), "hosts": set(), "country": "", "organization": ""}
            )
            bucket["ips"].append(record.ip)
            if record.prefix:
                bucket["prefixes"].add(record.prefix)
            bucket["hosts"].update(record.hosted_domains)
            bucket["country"] = bucket["country"] or record.country
            bucket["organization"] = bucket["organization"] or record.organization

        for asn, bucket in sorted(grouped.items()):
            info = ASNIntelligence(
                asn=asn,
                organization=str(bucket["organization"]),
                country=str(bucket["country"]),
                prefixes=sorted(bucket["prefixes"]),
                ip_count=len(bucket["ips"]),
                hosts=sorted(bucket["hosts"]),
                domain_count=len(bucket["hosts"]),
                is_bogon=asn in BOGON_ASNS,
            )
            # Fill gaps from the ASN registry when the origin lookup was sparse.
            if asn != "UNKNOWN" and not info.organization:
                looked_up = self.lookup(asn)
                info.organization = looked_up.organization
                info.country = looked_up.country or info.country
                info.rir = looked_up.rir
                info.allocated = looked_up.allocated
                info.error = looked_up.error
            info.share = round(len(bucket["ips"]) / total, 4) if total else 0.0
            info.source = SourceRecord(
                provider="team-cymru",
                source=f"origin.asn.cymru.com / {asn}.{self.zone}",
                observed_at=utc_now_iso(),
                confidence=Confidence.HIGH if info.organization else Confidence.MEDIUM,
                quality=EvidenceQuality.OBSERVED,
            )
            summary.asns.append(info)

        summary.total_addresses = total
        # Concentration is computed over *identified* ASNs only: addresses with
        # no published origin would otherwise count as a network of their own.
        identified = summary.known_asns()
        if identified:
            identified_total = sum(item.ip_count for item in identified)
            top = max(identified, key=lambda item: item.ip_count)
            summary.top_asn = top.asn
            summary.top_share = round(top.ip_count / identified_total, 4) if identified_total else 0.0
            summary.concentrated = summary.top_share >= CONCENTRATION_THRESHOLD and identified_total > 1
            # Re-balance every share against the identified total so the numbers
            # in the report describe the same denominator.
            for item in identified:
                item.share = round(item.ip_count / identified_total, 4) if identified_total else 0.0
        summary.prefixes = sorted({prefix for item in summary.asns for prefix in item.prefixes})
        summary.countries = sorted({item.country for item in summary.asns if item.country})
        if summary.concentrated:
            summary.notes.append(
                f"{summary.top_share * 100:.0f}% of identified addresses are in {summary.top_asn}"
            )
        unresolved = summary.unresolved_addresses()
        if unresolved:
            summary.notes.append(f"{unresolved} address(es) have no published origin ASN")
        if summary.countries:
            summary.notes.append(f"countries: {', '.join(summary.countries)}")
        return summary

    def records_for(self, summary: ASNSummary) -> list[ASNRecord]:
        """Convert the rollup into storable :class:`ASNRecord` assets."""
        return [
            ASNRecord(
                value=item.asn.lower(),
                asn=item.asn,
                label=item.label,
                organization=item.organization,
                country=item.country,
                prefixes=item.prefixes,
                ip_count=item.ip_count,
                domain_count=item.domain_count,
                confidence=item.source.confidence,
                quality=item.source.quality,
                sources=[item.source],
                attributes={"rir": item.rir, "allocated": item.allocated, "share": item.share},
            )
            for item in summary.asns
        ]

    def describe(self, asns: Iterable[str]) -> list[ASNIntelligence]:
        """Look up several ASNs (used by ``dnscope asn``)."""
        return [self.lookup(asn) for asn in asns]

    # --------------------------------------------------------------- internals

    def _parse(self, values: Sequence[str]) -> dict[str, str] | None:
        """Parse Cymru's ``ASN | CC | RIR | Allocated | Name`` TXT format."""
        for value in values:
            text = str(value).strip().strip('"')
            parts = [part.strip() for part in text.split("|")]
            if len(parts) < 5:
                continue
            organization = parts[4]
            if organization.upper() in ("", "NA"):
                continue
            return {
                "asn": format_asn(parts[0]),
                "country": parts[1].upper(),
                "rir": parts[2],
                "allocated": parts[3],
                "organization": organization,
            }
        return None


__all__ = [
    "ASN_ZONE",
    "ASNIntelligence",
    "ASNIntelligenceEngine",
    "ASNSummary",
    "CONCENTRATION_THRESHOLD",
]

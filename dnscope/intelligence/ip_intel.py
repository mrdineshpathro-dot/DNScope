"""IP address intelligence.

Combines three passive observations per address:

* **origin ASN** - via the Team Cymru DNS service (no API key, no HTTP)
* **reverse DNS (PTR)** - via the configured resolver
* **hosting fingerprint** - PTR/ASN/organization matched against the provider
  fingerprint store

The output is an :class:`IPRecord` asset plus an :class:`AddressRisk` assessment
that flags addresses worth a second look: private/reserved space in a public
answer, PTR that disagrees with the expected hostname, or many unrelated domains
sharing one address.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Sequence

from pydantic import Field

from dnscope.analyzers.cloud import CloudDetector
from dnscope.dns.engine import DNSEngine
from dnscope.models.assets import IPRecord
from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.providers.base import ProviderContext
from dnscope.providers.registry import ProviderRegistry
from dnscope.utils.domains import (
    ASN_ZONE,
    BOGON_ASNS,
    format_asn,
    is_private_ip,
    normalize_hostname,
    parse_ip,
    reverse_pointer,
)
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("intelligence.ip")

#: PTR suffixes that indicate the address has no meaningful reverse record.
UNINFORMATIVE_PTR = (
    ".in-addr.arpa",
    ".ip6.arpa",
    "no-reverse",
    "no.ptr",
    "nxdomain",
    "static.",
    "dsl.",
    "dynamic.",
)


class AddressRisk(SchemaVersioned):
    """Risk flags for one address, each with the observation behind it."""

    ip: str
    is_private: bool = False
    is_reserved: bool = False
    is_bogon_asn: bool = False
    #: ``True`` when the address has no informative reverse record.
    ptr_missing: bool = False
    #: ``True`` when the PTR does not forward-resolve back to the address.
    ptr_mismatch: bool = False
    #: Provider detected from PTR/ASN/organization fingerprints.
    provider: str = ""
    provider_category: str = ""
    provider_confidence: str = Confidence.UNKNOWN.value
    #: Other hostnames observed on the same address (shared infrastructure).
    co_hosted: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def shared_hosting(self) -> bool:
        """``True`` when at least one other hostname shares this address."""
        return bool(self.co_hosted)

    @property
    def notable(self) -> bool:
        """``True`` when at least one flag is set."""
        return bool(
            self.is_private
            or self.is_reserved
            or self.is_bogon_asn
            or self.ptr_missing
            or self.ptr_mismatch
        )

    def flags(self) -> list[str]:
        """The set flags as short identifiers."""
        found: list[str] = []
        if self.is_private:
            found.append("PRIVATE_ADDRESS")
        if self.is_reserved:
            found.append("RESERVED_ADDRESS")
        if self.is_bogon_asn:
            found.append("BOGON_ASN")
        if self.ptr_missing:
            found.append("PTR_MISSING")
        if self.ptr_mismatch:
            found.append("PTR_FORWARD_MISMATCH")
        if self.shared_hosting:
            found.append("SHARED_HOSTING")
        return found

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dictionary."""
        data = self.model_dump(mode="json")
        data["flags"] = self.flags()
        return data


class IPIntelligenceReport(SchemaVersioned):
    """Result of enriching a set of addresses."""

    target: str = ""
    records: list[IPRecord] = Field(default_factory=list)
    risks: list[AddressRisk] = Field(default_factory=list)
    #: Addresses that could not be enriched, with the reason.
    failures: dict[str, str] = Field(default_factory=dict)
    providers_used: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    #: ``True`` when no external source was reachable.
    degraded: bool = False
    observed_at: str = Field(default_factory=utc_now_iso)

    def by_ip(self) -> dict[str, IPRecord]:
        """Records keyed by address."""
        return {record.ip: record for record in self.records}

    def risk_for(self, ip: str) -> AddressRisk | None:
        """The risk assessment for one address."""
        return next((item for item in self.risks if item.ip == ip), None)

    def providers(self) -> list[str]:
        """Distinct providers detected across all addresses."""
        return sorted({risk.provider for risk in self.risks if risk.provider})

    def asns(self) -> list[str]:
        """Distinct ASNs observed."""
        return sorted({record.asn for record in self.records if record.asn})

    def flagged(self) -> list[AddressRisk]:
        """Addresses with at least one risk flag."""
        return [risk for risk in self.risks if risk.notable]

    def summary(self) -> str:
        """One-line human summary."""
        return (
            f"{len(self.records)} address(es) enriched, {len(self.asns())} ASN(s), "
            f"{len(self.flagged())} flagged"
            + (f", providers={','.join(self.providers())}" if self.providers() else "")
        )


def _is_rfc1918_or_ula(address: Any) -> bool:
    """``True`` only for genuinely private address space.

    IPv4: 10/8, 172.16/12, 192.168/16. IPv6: fc00::/7 (unique local). Everything
    else that is not globally routable is special-purpose rather than private.
    """
    private_ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
    return any(address in ipaddress.ip_network(block) for block in private_ranges)


class IPIntelligenceEngine:
    """Enriches IP addresses with ASN, PTR and hosting context."""

    def __init__(
        self,
        engine: DNSEngine | None,
        registry: ProviderRegistry | None = None,
        *,
        detector: CloudDetector | None = None,
        asn_engine: Any = None,
        asn_provider: str = "team-cymru",
        resolve_ptr: bool = True,
        allow_external: bool = True,
        offline: bool = False,
    ) -> None:
        self.engine = engine
        self.registry = registry or ProviderRegistry()
        self.detector = detector or CloudDetector()
        #: Optional :class:`ASNIntelligenceEngine` used to resolve the registered
        #: organization for an ASN (Cymru's origin lookup has no org name).
        self.asn_engine = asn_engine
        self.asn_provider = asn_provider
        self.resolve_ptr = resolve_ptr
        self.allow_external = allow_external
        self.offline = offline

    # ------------------------------------------------------------------ public

    def enrich(
        self,
        addresses: Iterable[str],
        *,
        target: str = "",
        co_hosted: dict[str, Sequence[str]] | None = None,
    ) -> IPIntelligenceReport:
        """Enrich every address and return the combined report."""
        import time

        started = time.monotonic()
        report = IPIntelligenceReport(target=target)
        hosts = co_hosted or {}
        unique: list[str] = []
        for address in addresses:
            text = str(address).strip()
            if text and parse_ip(text) is not None and text not in unique:
                unique.append(text)
            elif text:
                report.failures[text] = "not a valid IP address"

        provider = self.registry.get(self.asn_provider)
        context = self._context()
        if provider is None:
            report.degraded = True
            report.failures.setdefault("*", f"ASN provider {self.asn_provider} is not registered")

        for address in unique:
            record = IPRecord(value=address, ip=address, label=address)
            record.version = 6 if ":" in address else 4
            risk = AddressRisk(ip=address)
            record.scope_status = "OUT_OF_SCOPE" if is_private_ip(address) else "IN_SCOPE"

            self._apply_asn(record, risk, provider, context, report)
            self._apply_ptr(record, risk, address)
            self._apply_provider(record, risk)
            self._apply_risk_flags(risk, address, record, hosts.get(address, ()))

            record.sources.append(
                SourceRecord(
                    provider=self.asn_provider if record.asn else "dns",
                    source="origin.asn.cymru.com" if record.asn else "PTR",
                    observed_at=utc_now_iso(),
                    confidence=record.confidence,
                    quality=record.quality,
                )
            )
            report.records.append(record)
            report.risks.append(risk)

        report.providers_used = sorted(
            {
                *(record.provider for record in report.records if record.provider),
                *(
                    str(record.attributes.get("asn_source"))
                    for record in report.records
                    if record.attributes.get("asn_source")
                ),
            }
        )
        report.duration_ms = (time.monotonic() - started) * 1000.0
        return report

    def single(self, address: str, *, target: str = "") -> tuple[IPRecord | None, AddressRisk]:
        """Enrich one address (convenience wrapper for ``dnscope ip``)."""
        report = self.enrich([address], target=target)
        record = report.records[0] if report.records else None
        risk = report.risks[0] if report.risks else AddressRisk(ip=address)
        return record, risk

    # --------------------------------------------------------------- internals

    def _context(self) -> ProviderContext:
        """Provider context carrying the TXT-only resolver facade."""
        dns = self.engine.txt_resolver() if self.engine is not None else None
        return ProviderContext(
            dns=dns,
            offline=self.offline,
            allow_external=self.allow_external,
        )

    def _apply_asn(
        self,
        record: IPRecord,
        risk: AddressRisk,
        provider: Any,
        context: ProviderContext,
        report: IPIntelligenceReport,
    ) -> None:
        """Attach origin ASN data from the configured provider."""
        if provider is None:
            return
        if not provider.is_configured():
            report.degraded = True
            return
        if not self.registry.is_enabled(provider.name):
            report.degraded = True
            return
        try:
            result = provider.query(record.ip, context)
        except Exception as exc:  # noqa: BLE001 - one bad address must not abort the batch
            report.failures[record.ip] = f"ASN lookup failed: {exc}"
            return
        if not result.ok:
            if result.error:
                report.failures[record.ip] = result.error
            return
        for item in result.ip_records:
            record.asn = format_asn(str(item.get("asn", "")))
            record.prefix = str(item.get("prefix", ""))
            record.country = str(item.get("country", ""))
            record.organization = str(item.get("organization", ""))
            # ``record.provider`` is reserved for the *hosting* provider detected
            # from fingerprints; the ASN feed is provenance, not a hoster.
            record.attributes["asn_source"] = provider.name
            record.confidence = Confidence.coerce(item.get("confidence", Confidence.HIGH.value))
            record.quality = EvidenceQuality.coerce(item.get("quality", EvidenceQuality.OBSERVED.value))
            record.attributes.update(
                {
                    "rir": str(item.get("rir", "")),
                    "allocated": str(item.get("allocated", "")),
                    "asn_cached": bool(result.cached),
                }
            )
            break
        if record.asn in BOGON_ASNS:
            risk.is_bogon_asn = True
            risk.notes.append(f"origin {record.asn} is a bogon/documentation ASN")
        if record.asn and not record.organization and self.asn_engine is not None:
            info = self.asn_engine.lookup(record.asn)
            if info.organization:
                record.organization = info.organization
                record.country = record.country or info.country
                record.attributes["organization_source"] = f"{info.asn}.{ASN_ZONE}"

    def _apply_ptr(self, record: IPRecord, risk: AddressRisk, address: str) -> None:
        """Resolve and assess the reverse record."""
        if not self.resolve_ptr or self.engine is None:
            return
        name = reverse_pointer(address)
        result = self.engine.query(name, "PTR")
        if not result.ok:
            risk.ptr_missing = True
            record.attributes["ptr_status"] = result.status
            return
        names = sorted({normalize_hostname(str(value)) for value in result.values if value})
        record.ptr = names
        informative = [
            item
            for item in names
            if item and not any(needle in item for needle in UNINFORMATIVE_PTR)
        ]
        if not informative:
            risk.ptr_missing = True
            risk.notes.append(f"PTR {', '.join(names) or 'none'} is not informative")
            return
        record.attributes["ptr_informative"] = informative
        if self._forward_confirms(informative[0], address) is False:
            risk.ptr_mismatch = True
            risk.notes.append(f"PTR {informative[0]} does not forward-resolve back to {address}")

    def _forward_confirms(self, hostname: str, address: str) -> bool | None:
        """Forward-Confirm the PTR (FCrDNS). ``None`` when unverifiable."""
        if self.engine is None:
            return None
        rtype = "AAAA" if ":" in address else "A"
        result = self.engine.query(hostname, rtype)
        if not result.ok:
            return None
        return address in set(result.values)

    def _apply_provider(self, record: IPRecord, risk: AddressRisk) -> None:
        """Match PTR/ASN/organization against the hosting fingerprint store."""
        matches = self.detector.detect_cloud(
            {
                "subject": record.ip,
                "ptrs": record.ptr,
                "asns": [record.asn] if record.asn else [],
                "organizations": [record.organization] if record.organization else [],
            }
        )
        if not matches:
            return
        best = matches[0]
        risk.provider = best.provider
        risk.provider_category = best.category
        risk.provider_confidence = best.confidence
        record.is_cloud = best.category in ("cloud", "hosting")
        record.is_cdn = best.category == "cdn"
        if not record.provider:
            record.provider = best.provider
        record.tags.extend(tag for tag in (f"provider:{best.provider}", f"category:{best.category}") if tag)

    def _apply_risk_flags(
        self,
        risk: AddressRisk,
        address: str,
        record: IPRecord,
        co_hosted: Sequence[str],
    ) -> None:
        """Set the remaining risk flags."""
        parsed = parse_ip(address)
        if parsed is not None:
            # ``ipaddress.is_private`` is broader than "RFC 1918/ULA": it also
            # covers documentation and other special-purpose ranges. Reporting a
            # TEST-NET address as "private" would mislead the reader, so the
            # routability test comes first and the two cases are kept distinct.
            risk.is_private = not parsed.is_global and _is_rfc1918_or_ula(parsed)
            risk.is_reserved = not parsed.is_global and not risk.is_private
            if risk.is_private:
                risk.notes.append(f"{address} is private space; it is not routable on the internet")
            elif risk.is_reserved:
                risk.notes.append(f"{address} is special-purpose/reserved space (not routable)")
        risk.co_hosted = sorted({normalize_hostname(item) for item in co_hosted if item})
        if len(risk.co_hosted) > 1:
            risk.notes.append(f"{len(risk.co_hosted)} hostnames share {address}")


__all__ = [
    "ASN_ZONE",
    "BOGON_ASNS",
    "AddressRisk",
    "IPIntelligenceEngine",
    "IPIntelligenceReport",
    "UNINFORMATIVE_PTR",
]

"""Intelligence orchestration.

One entry point that runs every passive enrichment source for a scan, keeps each
source's failure isolated, and hands the combined result to the graph builder and
the database. Individual engines stay independent so a scan can ask for just the
parts it needs (``--no-threat``, offline mode, privacy mode).

Nothing here decides severity: it produces *observations with evidence*. Turning
those into findings is the rule engine's job, so the same observation can be
weighed differently by different policies.
"""

from __future__ import annotations

import time
from typing import Any, Iterable, Sequence

from pydantic import Field

from dnscope.analyzers.cloud import CloudDetector
from dnscope.analyzers.tls_probe import TLSProbe
from dnscope.dns.engine import DNSEngine
from dnscope.intelligence.asn import ASNIntelligenceEngine, ASNSummary
from dnscope.intelligence.certificates import CertificateEngine, CertificateReport, certificate_observations
from dnscope.intelligence.ip_intel import IPIntelligenceEngine, IPIntelligenceReport
from dnscope.intelligence.registration import RDAPClient, RegistrationData
from dnscope.intelligence.threat import ThreatIntelligence, ThreatReport
from dnscope.models.common import SchemaVersioned
from dnscope.providers.registry import ProviderRegistry
from dnscope.utils.domains import is_private_ip, normalize_hostname, registered_domain
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("intelligence.enricher")


class EnrichmentOptions(SchemaVersioned):
    """Which intelligence sources a run should consult."""

    registration: bool = True
    ip_intel: bool = True
    asn: bool = True
    certificates: bool = True
    threat: bool = False
    #: Hosts the operator explicitly authorized for a TLS handshake.
    authorized_hosts: list[str] = Field(default_factory=list)
    #: TLS port used for authorized handshakes.
    tls_port: int = 443
    #: Skip intelligence for private/reserved addresses.
    skip_private_addresses: bool = True
    #: Hard cap on how many addresses get enriched in one run.
    max_addresses: int = 500
    #: Hard cap on threat subjects (each is a separate API call).
    max_threat_subjects: int = 25

    def disabled(self) -> list[str]:
        """Names of the sources this run will not consult."""
        found = [
            name
            for name, enabled in (
                ("registration", self.registration),
                ("ip-intel", self.ip_intel),
                ("asn", self.asn),
                ("certificates", self.certificates),
                ("threat", self.threat),
            )
            if not enabled
        ]
        return found


class IntelligenceReport(SchemaVersioned):
    """Everything the intelligence layer learned about one target."""

    target: str
    workspace: str = "default"
    registration: RegistrationData | None = None
    ip_intelligence: IPIntelligenceReport | None = None
    asn_summary: ASNSummary | None = None
    certificates: CertificateReport | None = None
    threat: ThreatReport | None = None
    #: Names of sources that ran.
    sources_consulted: list[str] = Field(default_factory=list)
    #: Names of sources that were skipped or failed, with the reason.
    sources_skipped: dict[str, str] = Field(default_factory=dict)
    options: EnrichmentOptions = Field(default_factory=EnrichmentOptions)
    duration_ms: float = 0.0
    observed_at: str = Field(default_factory=utc_now_iso)

    # ------------------------------------------------------------- derivations

    def observations(self) -> list[dict[str, Any]]:
        """All evidence-backed observations, ready for the rule engine."""
        found: list[dict[str, Any]] = []
        if self.registration is not None:
            for item in self.registration.risks():
                found.append(
                    {
                        **item,
                        "target": self.target,
                        "quality": "OBSERVED",
                        "source": self.registration.source.provider or "rdap",
                    }
                )
        if self.ip_intelligence is not None:
            for risk in self.ip_intelligence.flagged():
                for flag in risk.flags():
                    if flag == "SHARED_HOSTING":
                        continue
                    found.append(
                        {
                            "id": f"IP-{flag}",
                            "severity": "HIGH" if flag in ("PRIVATE_ADDRESS", "PTR_FORWARD_MISMATCH") else "MEDIUM",
                            "target": risk.ip,
                            "detail": "; ".join(risk.notes) or flag.replace("_", " ").lower(),
                            "evidence": f"ip={risk.ip} flags={','.join(risk.flags())}",
                            "quality": "OBSERVED",
                            "source": "dns",
                        }
                    )
        if self.asn_summary is not None:
            for item in self.asn_summary.risks():
                found.append(
                    {**item, "target": self.target, "quality": "OBSERVED", "source": "team-cymru"}
                )
        if self.certificates is not None:
            found.extend(certificate_observations(self.certificates, target=self.target))
        if self.threat is not None:
            for item in self.threat.observations():
                found.append({**item, "source": "threat-provider"})
        return found

    def providers(self) -> list[str]:
        """Every external provider that contributed data."""
        found: set[str] = set()
        if self.registration is not None and self.registration.found:
            found.add(self.registration.source.provider or "rdap")
        if self.ip_intelligence is not None:
            found.update(self.ip_intelligence.providers_used)
        if self.asn_summary is not None and self.asn_summary.asns:
            found.add("team-cymru")
        if self.certificates is not None:
            found.update(self.certificates.ct_sources)
        if self.threat is not None:
            found.update(self.threat.providers_used)
        return sorted(item for item in found if item)

    def degraded(self) -> bool:
        """``True`` when at least one requested source produced nothing."""
        return bool(self.sources_skipped)

    def summary(self) -> str:
        """One-line human summary."""
        parts = [self.target]
        if self.registration is not None and self.registration.found:
            parts.append(f"registrar={self.registration.registrar or 'unknown'}")
        if self.asn_summary is not None and self.asn_summary.asns:
            parts.append(f"{len(self.asn_summary.known_asns())} ASN(s)")
            unresolved = self.asn_summary.unresolved_addresses()
            if unresolved:
                parts.append(f"{unresolved} address(es) without origin data")
        if self.certificates is not None:
            parts.append(f"{len(self.certificates.certificates)} cert(s)")
        if self.threat is not None and self.threat.available:
            parts.append(f"{len(self.threat.hostile())} hostile indicator(s)")
        parts.append(f"sources={','.join(self.sources_consulted) or 'none'}")
        return " ".join(parts)

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        """JSON-ready dictionary (models serialized to plain data)."""
        return {
            "target": self.target,
            "workspace": self.workspace,
            "sources_consulted": self.sources_consulted,
            "sources_skipped": self.sources_skipped,
            "providers": self.providers(),
            "options": self.options.model_dump(),
            "registration": self.registration.model_dump(mode="json") if self.registration else None,
            "ip_intelligence": self.ip_intelligence.model_dump(mode="json") if self.ip_intelligence else None,
            "asn_summary": self.asn_summary.model_dump(mode="json") if self.asn_summary else None,
            "certificates": self.certificates.model_dump(mode="json") if self.certificates else None,
            "threat": self.threat.model_dump(mode="json") if self.threat else None,
            "observations": self.observations(),
            "duration_ms": round(self.duration_ms, 2),
            "observed_at": self.observed_at,
        }


class IntelligenceEngine:
    """Runs the passive enrichment sources for one target."""

    def __init__(
        self,
        engine: DNSEngine | None,
        registry: ProviderRegistry | None = None,
        *,
        http: Any = None,
        detector: CloudDetector | None = None,
        probe: TLSProbe | None = None,
        allow_external: bool = True,
        offline: bool = False,
        privacy: bool = False,
        workspace: str = "default",
    ) -> None:
        self.engine = engine
        self.registry = registry or ProviderRegistry()
        self.http = http
        self.detector = detector or CloudDetector()
        self.probe = probe
        self.allow_external = allow_external
        self.offline = offline
        self.privacy = privacy
        self.workspace = workspace
        self.rdap = RDAPClient(
            self.registry,
            http=http,
            allow_external=allow_external,
            offline=offline,
        )
        self.asn = ASNIntelligenceEngine(engine)
        self.ip_intel = IPIntelligenceEngine(
            engine,
            self.registry,
            detector=self.detector,
            asn_engine=self.asn,
            allow_external=allow_external,
            offline=offline,
        )
        self.certificates = CertificateEngine(
            self.registry,
            probe=probe,
            http=http,
            allow_external=allow_external,
            offline=offline,
        )
        self.threat = ThreatIntelligence(
            self.registry,
            http=http,
            allow_external=allow_external,
            offline=offline,
            privacy=privacy,
        )

    # ------------------------------------------------------------------ public

    def enrich(
        self,
        target: str,
        *,
        hostnames: Sequence[str] = (),
        addresses: Sequence[str] = (),
        nameservers: Sequence[str] = (),
        co_hosted: dict[str, Sequence[str]] | None = None,
        options: EnrichmentOptions | None = None,
    ) -> IntelligenceReport:
        """Run every enabled source and return the combined report."""
        started = time.monotonic()
        opts = options or EnrichmentOptions()
        name = normalize_hostname(target)
        report = IntelligenceReport(target=name, workspace=self.workspace, options=opts)

        if opts.registration:
            report.registration = self._registration(name, nameservers, report)
        else:
            report.sources_skipped["registration"] = "disabled by options"

        if opts.ip_intel:
            report.ip_intelligence = self._ip_intelligence(name, addresses, co_hosted, opts, report)
        else:
            report.sources_skipped["ip-intel"] = "disabled by options"

        if opts.asn:
            if report.ip_intelligence is not None and report.ip_intelligence.records:
                report.asn_summary = self.asn.rollup(report.ip_intelligence, target=name)
                report.sources_consulted.append("asn")
            else:
                report.sources_skipped["asn"] = "no address intelligence available to roll up"
        else:
            report.sources_skipped["asn"] = "disabled by options"

        if opts.certificates:
            report.certificates = self._certificates(name, hostnames, opts, report)
        else:
            report.sources_skipped["certificates"] = "disabled by options"

        if opts.threat:
            report.threat = self._threat(name, hostnames, addresses, opts, report)
        else:
            report.sources_skipped["threat"] = "disabled by options"

        report.duration_ms = (time.monotonic() - started) * 1000.0
        return report

    # ------------------------------------------------------------------- graph

    def apply_to_graph(self, report: IntelligenceReport, builder: Any) -> None:
        """Attach intelligence results to a :class:`GraphBuilder`."""
        if report.registration is not None and report.registration.registrar:
            builder.add_registrar(report.target, report.registration.registrar)
        if report.ip_intelligence is not None:
            for record in report.ip_intelligence.records:
                builder.add_ip_intelligence(
                    record.ip,
                    asn=record.asn,
                    organization=record.organization,
                    prefix=record.prefix,
                    provider=record.provider,
                )
                risk = report.ip_intelligence.risk_for(record.ip)
                if risk is not None and risk.provider:
                    builder.add_cloud_provider(
                        record.ip,
                        risk.provider,
                        category=risk.provider_category or "cloud",
                        evidence=f"ptr={','.join(record.ptr) or '-'} asn={record.asn or '-'}",
                        confidence=risk.provider_confidence,
                        source="fingerprint",
                    )
        if report.certificates is not None:
            for certificate in report.certificates.certificates:
                builder.add_certificate(
                    {
                        "fingerprint_sha256": certificate.fingerprint_sha256,
                        "serial_number": certificate.serial_number,
                        "subject_cn": certificate.subject_cn,
                        "issuer_cn": certificate.issuer_cn,
                        "not_before": certificate.not_before.isoformat() if certificate.not_before else "",
                        "not_after": certificate.not_after.isoformat() if certificate.not_after else "",
                    },
                    covered_hosts=certificate.subject_alternative_names,
                    source=certificate.source,
                )
        if report.threat is not None:
            for indicator in report.threat.hostile():
                builder.add_threat_indicator(
                    indicator.subject,
                    indicator.verdict or "hostile",
                    provider=indicator.provider,
                    detail=indicator.summary(),
                )

    def persist(self, report: IntelligenceReport, database: Any) -> dict[str, int]:
        """Write intelligence results into the database; returns row counts."""
        counts = {"ip": 0, "asn": 0, "certificates": 0, "events": 0}
        if report.registration is not None and report.registration.found:
            database.upsert_target(
                report.target,
                attributes={
                    "registrar": report.registration.registrar,
                    "expiration_date": report.registration.expiration_date,
                    "registration_date": report.registration.registration_date,
                    "registry_locked": report.registration.registry_locked,
                    "dnssec_at_registry": report.registration.dnssec_at_registry,
                },
            )
            database.record_event(
                report.target,
                "registration_observed",
                detail=report.registration.summary(),
                category="registration",
                source=report.registration.source.provider or "rdap",
            )
            counts["events"] += 1
        if report.ip_intelligence is not None:
            for record in report.ip_intelligence.records:
                database.upsert_ip(
                    record.ip,
                    version=record.version,
                    ptr=record.ptr,
                    asn=record.asn,
                    organization=record.organization,
                    prefix=record.prefix,
                    country=record.country,
                    provider=record.provider,
                    source="team-cymru" if record.asn else "dns",
                )
                counts["ip"] += 1
        if report.asn_summary is not None:
            for item in self.asn.records_for(report.asn_summary):
                database.upsert_asn(
                    item.asn,
                    organization=item.organization,
                    country=item.country,
                    prefixes=item.prefixes,
                    ip_count=item.ip_count,
                    domain_count=item.domain_count,
                )
                counts["asn"] += 1
        if report.certificates is not None:
            for certificate in report.certificates.certificates:
                remaining = certificate.days_until_expiry()
                database.upsert_certificate(
                    fingerprint=certificate.fingerprint_sha256 or certificate.identity,
                    serial_number=certificate.serial_number,
                    subject_cn=certificate.subject_cn,
                    sans=certificate.subject_alternative_names,
                    issuer_cn=certificate.issuer_cn,
                    not_before=certificate.not_before.isoformat() if certificate.not_before else "",
                    not_after=certificate.not_after.isoformat() if certificate.not_after else "",
                    signature_algorithm=certificate.signature_algorithm,
                    public_key_algorithm=certificate.public_key_algorithm,
                    public_key_bits=certificate.public_key_bits,
                    source=certificate.source,
                    source_detail=certificate.source_detail,
                    expired=remaining is not None and remaining < 0,
                    hostnames=certificate.subject_alternative_names,
                )
                counts["certificates"] += 1
        return counts

    # --------------------------------------------------------------- internals

    def _registration(
        self,
        target: str,
        nameservers: Sequence[str],
        report: IntelligenceReport,
    ) -> RegistrationData:
        """RDAP lookup for the registered domain."""
        domain = registered_domain(target) or target
        try:
            data = self.rdap.lookup(domain)
        except Exception as exc:  # noqa: BLE001 - one source failing must not abort the run
            data = RegistrationData(domain=domain)
            data.error = f"{type(exc).__name__}: {exc}"
        self.rdap.with_live_nameservers(data, nameservers)
        if data.found:
            report.sources_consulted.append("rdap")
        else:
            report.sources_skipped["rdap"] = data.error or "no registration data returned"
        return data

    def _ip_intelligence(
        self,
        target: str,
        addresses: Sequence[str],
        co_hosted: dict[str, Sequence[str]] | None,
        opts: EnrichmentOptions,
        report: IntelligenceReport,
    ) -> IPIntelligenceReport | None:
        """Address enrichment, bounded and private-address aware."""
        candidates = [str(item) for item in addresses if str(item).strip()]
        if opts.skip_private_addresses:
            kept = [item for item in candidates if not is_private_ip(item)]
            dropped = len(candidates) - len(kept)
            if dropped:
                report.sources_skipped["ip-intel-private"] = f"{dropped} private address(es) skipped"
            candidates = kept
        if len(candidates) > opts.max_addresses:
            report.sources_skipped["ip-intel-limit"] = (
                f"only the first {opts.max_addresses} of {len(candidates)} addresses were enriched"
            )
            candidates = candidates[: opts.max_addresses]
        if not candidates:
            report.sources_skipped.setdefault("ip-intel", "no addresses to enrich")
            return None
        try:
            result = self.ip_intel.enrich(candidates, target=target, co_hosted=co_hosted)
        except Exception as exc:  # noqa: BLE001
            report.sources_skipped["ip-intel"] = f"{type(exc).__name__}: {exc}"
            return None
        if result.records:
            report.sources_consulted.append("ip-intel")
        return result

    def _certificates(
        self,
        target: str,
        hostnames: Sequence[str],
        opts: EnrichmentOptions,
        report: IntelligenceReport,
    ) -> CertificateReport | None:
        """CT (always passive) plus authorized TLS handshakes."""
        hosts = sorted({normalize_hostname(item) for item in hostnames if item} | {target})
        authorized = sorted({normalize_hostname(item) for item in opts.authorized_hosts if item})
        try:
            result = self.certificates.collect(
                target,
                hosts=hosts,
                authorized_hosts=authorized,
                port=opts.tls_port,
            )
        except Exception as exc:  # noqa: BLE001
            report.sources_skipped["certificates"] = f"{type(exc).__name__}: {exc}"
            return None
        if result.certificates:
            report.sources_consulted.append("certificates")
        elif result.errors:
            report.sources_skipped["certificates"] = result.errors[0]
        return result

    def _threat(
        self,
        target: str,
        hostnames: Sequence[str],
        addresses: Sequence[str],
        opts: EnrichmentOptions,
        report: IntelligenceReport,
    ) -> ThreatReport:
        """Reputation lookup for the target, its hosts and its addresses."""
        subjects: list[str] = [target]
        subjects.extend(normalize_hostname(item) for item in hostnames if item)
        subjects.extend(str(item) for item in addresses if item)
        unique: list[str] = []
        for subject in subjects:
            if subject and subject not in unique:
                unique.append(subject)
        if len(unique) > opts.max_threat_subjects:
            report.sources_skipped["threat-limit"] = (
                f"only the first {opts.max_threat_subjects} of {len(unique)} subjects were queried"
            )
            unique = unique[: opts.max_threat_subjects]
        try:
            result = self.threat.enrich(unique, target=target)
        except Exception as exc:  # noqa: BLE001
            result = ThreatReport(target=target, note=f"{type(exc).__name__}: {exc}")
        if result.available:
            report.sources_consulted.append("threat")
        elif result.note:
            report.sources_skipped["threat"] = result.note
        return result


def addresses_from_answers(answers: Iterable[Any]) -> dict[str, list[str]]:
    """Extract ``ip -> hostnames`` from a mapping of :class:`DNSAnswer` objects."""
    mapping: dict[str, list[str]] = {}
    for hostname, answer in dict(answers).items():
        for query in getattr(answer, "queries", []):
            if query.rtype not in ("A", "AAAA"):
                continue
            for value in query.values:
                mapping.setdefault(str(value), [])
                if hostname not in mapping[str(value)]:
                    mapping[str(value)].append(hostname)
    return mapping


__all__ = [
    "EnrichmentOptions",
    "IntelligenceEngine",
    "IntelligenceReport",
    "addresses_from_answers",
]

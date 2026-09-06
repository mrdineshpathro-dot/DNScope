"""Certificate intelligence: CT logs, live chains, expiry and set changes.

Two sources, clearly separated:

* **Certificate Transparency** - public logs via the crt.sh provider. No
  connection to the target is made; this is pure log reading.
* **TLS handshake** - only for hosts the operator explicitly authorized, and
  only through :class:`dnscope.analyzers.tls_probe.TLSProbe`, which refuses to
  connect unless ``authorized=True``.

The engine also diffs two certificate sets so monitoring can report *added*,
*removed*, *replaced* and *newly expiring* certificates as typed changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import Field

from dnscope.analyzers.tls_probe import TLSProbe, describe_expiry
from dnscope.models.certificates import CertificateChain, CertificateInfo
from dnscope.models.changes import ChangeRecord, ChangeType
from dnscope.models.common import SchemaVersioned
from dnscope.providers.base import ProviderContext
from dnscope.providers.http import default_client
from dnscope.providers.registry import ProviderRegistry
from dnscope.utils.domains import normalize_hostname, wildcard_strip
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import now_utc, utc_now_iso

_log = get_logger("intelligence.certificates")

#: Days before expiry at which a certificate is worth reporting.
EXPIRY_WARNING_DAYS = 30
#: Days before expiry at which it becomes urgent.
EXPIRY_CRITICAL_DAYS = 7
#: Key sizes below this are reported for RSA/ECDSA respectively.
WEAK_KEY_BITS = {"rsa": 2048, "dsa": 2048, "ec": 224}
#: Signature algorithms that are considered broken.
WEAK_SIGNATURES = ("md2", "md5", "sha1", "sha-1")


class CertificateReport(SchemaVersioned):
    """Certificates observed for a target, with derived observations."""

    target: str = ""
    certificates: list[CertificateInfo] = Field(default_factory=list)
    #: Chain presented by an authorized TLS handshake, when one was performed.
    chain: CertificateChain | None = None
    #: Hostnames covered by the observed certificates.
    covered_hosts: list[str] = Field(default_factory=list)
    #: Hostnames in scope that no observed certificate covers.
    uncovered_hosts: list[str] = Field(default_factory=list)
    ct_sources: list[str] = Field(default_factory=list)
    ct_count: int = 0
    tls_attempted: bool = False
    tls_authorized: bool = False
    errors: list[str] = Field(default_factory=list)
    #: ``True`` when no source produced data.
    degraded: bool = False
    observed_at: str = Field(default_factory=utc_now_iso)

    def expiring(self, days: int = EXPIRY_WARNING_DAYS) -> list[CertificateInfo]:
        """Certificates expiring within ``days`` (already-expired included)."""
        found: list[CertificateInfo] = []
        for certificate in self.certificates:
            remaining = certificate.days_until_expiry()
            if remaining is not None and remaining < days:
                found.append(certificate)
        return sorted(found, key=lambda item: item.not_after or now_utc())

    def expired(self) -> list[CertificateInfo]:
        """Certificates whose validity has ended."""
        return [
            certificate
            for certificate in self.certificates
            if (certificate.days_until_expiry() is not None and certificate.days_until_expiry() < 0)
        ]

    def weak(self) -> list[dict[str, Any]]:
        """Certificates with weak key material or signature algorithms."""
        issues: list[dict[str, Any]] = []
        for certificate in self.certificates:
            algorithm = (certificate.public_key_algorithm or "").lower()
            bits = certificate.public_key_bits or 0
            threshold = next(
                (limit for name, limit in WEAK_KEY_BITS.items() if name in algorithm),
                0,
            )
            if threshold and bits and bits < threshold:
                issues.append(
                    {
                        "certificate": certificate.identity,
                        "issue": f"{algorithm.upper()} key is {bits} bits (minimum {threshold})",
                        "severity": "MEDIUM",
                    }
                )
            signature = (certificate.signature_algorithm or "").lower()
            if any(needle in signature for needle in WEAK_SIGNATURES):
                issues.append(
                    {
                        "certificate": certificate.identity,
                        "issue": (
                            f"signature algorithm {certificate.signature_algorithm} is considered broken"
                        ),
                        "severity": "HIGH",
                    }
                )
        return issues

    def shared_certificates(self, hosts: Sequence[str]) -> list[dict[str, Any]]:
        """Certificates covering more than one in-scope host.

        A shared certificate is not a vulnerability; it is topology. Reporting it
        lets an operator see that renewing one certificate affects many hosts.
        """
        wanted = {normalize_hostname(item) for item in hosts if item}
        groups: list[dict[str, Any]] = []
        for certificate in self.certificates:
            covered = sorted(
                {
                    normalize_hostname(wildcard_strip(name))
                    for name in certificate.subject_alternative_names
                    if normalize_hostname(wildcard_strip(name)) in wanted
                }
            )
            if len(covered) > 1:
                groups.append(
                    {
                        "certificate": certificate.identity,
                        "issuer": certificate.issuer_cn,
                        "hosts": covered,
                        "expires": describe_expiry(certificate),
                    }
                )
        return groups

    def issuers(self) -> list[str]:
        """Distinct issuing CAs observed."""
        return sorted({certificate.issuer_cn for certificate in self.certificates if certificate.issuer_cn})

    def summary(self) -> str:
        """One-line human summary."""
        return (
            f"{len(self.certificates)} certificate(s), {len(self.issuers())} issuer(s), "
            f"{len(self.expiring())} expiring within {EXPIRY_WARNING_DAYS}d"
            + (f", {len(self.errors)} source error(s)" if self.errors else "")
        )


class CertificateSetChange(SchemaVersioned):
    """Difference between two observations of a target's certificate set."""

    target: str = ""
    added: list[CertificateInfo] = Field(default_factory=list)
    removed: list[CertificateInfo] = Field(default_factory=list)
    #: Fingerprints present in both, where the issuer or validity changed.
    renewed: list[dict[str, Any]] = Field(default_factory=list)
    newly_expired: list[CertificateInfo] = Field(default_factory=list)
    newly_expiring: list[CertificateInfo] = Field(default_factory=list)

    @property
    def changed(self) -> bool:
        """``True`` when anything differs."""
        return bool(self.added or self.removed or self.renewed or self.newly_expired or self.newly_expiring)

    def to_changes(self) -> list[ChangeRecord]:
        """Convert the diff into typed :class:`ChangeRecord` rows."""
        changes: list[ChangeRecord] = []
        for certificate in self.added:
            changes.append(
                ChangeRecord(
                    change_type=ChangeType.CERTIFICATE_ADDED,
                    target=self.target,
                    field=certificate.identity,
                    previous=None,
                    current={
                        "issuer": certificate.issuer_cn,
                        "not_after": certificate.not_after.isoformat() if certificate.not_after else "",
                        "sans": certificate.subject_alternative_names,
                    },
                    first_observation=True,
                    context={"source": certificate.source},
                )
            )
        for certificate in self.removed:
            changes.append(
                ChangeRecord(
                    change_type=ChangeType.CERTIFICATE_REMOVED,
                    target=self.target,
                    field=certificate.identity,
                    previous={
                        "issuer": certificate.issuer_cn,
                        "not_after": certificate.not_after.isoformat() if certificate.not_after else "",
                    },
                    current=None,
                    context={"source": certificate.source},
                )
            )
        for item in self.renewed:
            changes.append(
                ChangeRecord(
                    change_type=ChangeType.CERTIFICATE_REPLACED,
                    target=self.target,
                    field=str(item.get("fingerprint", "")),
                    previous=item.get("previous"),
                    current=item.get("current"),
                    context={"issuer": str(item.get("issuer", ""))},
                )
            )
        for certificate in self.newly_expired:
            changes.append(
                ChangeRecord(
                    change_type=ChangeType.CERTIFICATE_EXPIRED,
                    target=self.target,
                    field=certificate.identity,
                    previous=certificate.not_after.isoformat() if certificate.not_after else "",
                    current="expired",
                    context={"issuer": certificate.issuer_cn},
                )
            )
        return changes

    def summary(self) -> str:
        """One-line human summary."""
        if not self.changed:
            return f"{self.target}: certificate set unchanged"
        return (
            f"{self.target}: +{len(self.added)} -{len(self.removed)} "
            f"renewed={len(self.renewed)} expired={len(self.newly_expired)}"
        )


class CertificateEngine:
    """Collects certificates from CT logs and (optionally) live TLS."""

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        *,
        probe: TLSProbe | None = None,
        ct_provider: str = "crt.sh",
        http: Any = None,
        allow_external: bool = True,
        offline: bool = False,
    ) -> None:
        self.registry = registry or ProviderRegistry()
        self.probe = probe
        self.ct_provider = ct_provider
        self.http = http
        self.allow_external = allow_external
        self.offline = offline

    # ------------------------------------------------------------------ public

    def collect(
        self,
        domain: str,
        *,
        hosts: Sequence[str] = (),
        authorized_hosts: Sequence[str] = (),
        port: int = 443,
    ) -> CertificateReport:
        """Gather certificates for ``domain`` and the given hosts."""
        target = normalize_hostname(domain)
        report = CertificateReport(target=target)
        self._from_ct(target, report)
        authorized = {normalize_hostname(item) for item in authorized_hosts if item}
        wanted = sorted({normalize_hostname(item) for item in hosts if item} | {target})
        if authorized:
            report.tls_attempted = True
            report.tls_authorized = True
            for host in wanted:
                if host not in authorized:
                    continue
                self._from_tls(host, port, report)
        elif wanted:
            report.tls_attempted = False
            report.errors.append(
                "TLS inspection skipped: no hosts were explicitly authorized for a handshake"
            )

        report.covered_hosts = self._covered(report, wanted)
        report.uncovered_hosts = sorted(set(wanted) - set(report.covered_hosts))
        report.degraded = not report.certificates
        return report

    def diff(
        self,
        previous: Sequence[CertificateInfo] | Sequence[dict[str, Any]],
        current: Sequence[CertificateInfo],
        *,
        target: str = "",
        expiring_days: int = EXPIRY_WARNING_DAYS,
    ) -> CertificateSetChange:
        """Compare two certificate sets and describe the difference."""
        change = CertificateSetChange(target=target)
        before = {self._identity(item): self._coerce(item) for item in previous}
        after = {self._identity(item): item for item in current}

        for identity, certificate in after.items():
            if identity not in before:
                change.added.append(certificate)
                continue
            prior = before[identity]
            if self._validity_changed(prior, certificate) or self._issuer_changed(prior, certificate):
                change.renewed.append(
                    {
                        "fingerprint": identity,
                        "issuer": certificate.issuer_cn,
                        "previous": {
                            "not_after": (
                                prior.not_after.isoformat() if getattr(prior, "not_after", None) else ""
                            ),
                            "issuer": getattr(prior, "issuer_cn", ""),
                        },
                        "current": {
                            "not_after": certificate.not_after.isoformat() if certificate.not_after else "",
                            "issuer": certificate.issuer_cn,
                        },
                    }
                )

        for identity, certificate in before.items():
            if identity not in after:
                change.removed.append(certificate)

        for certificate in current:
            remaining = certificate.days_until_expiry()
            if remaining is None:
                continue
            if remaining < 0:
                change.newly_expired.append(certificate)
            elif remaining < expiring_days:
                change.newly_expiring.append(certificate)
        return change

    # --------------------------------------------------------------- internals

    def _from_ct(self, target: str, report: CertificateReport) -> None:
        """Read Certificate Transparency entries for ``target``."""
        provider = self.registry.get(self.ct_provider)
        if provider is None:
            report.errors.append(f"CT provider {self.ct_provider} is not registered")
            return
        if self.offline or not self.allow_external:
            report.errors.append("CT lookup skipped (offline or privacy mode)")
            return
        if not self.registry.is_enabled(provider.name):
            report.errors.append(f"CT provider {self.ct_provider} is disabled")
            return
        context = ProviderContext(
            http=self.http or default_client(self.registry),
            offline=self.offline,
            allow_external=self.allow_external,
        )
        try:
            result = provider.query(target, context)
        except Exception as exc:
            report.errors.append(f"{self.ct_provider}: {type(exc).__name__}: {exc}")
            _log.warning("CT lookup for %s failed: %s", target, exc)
            return
        if not result.ok:
            report.errors.append(f"{self.ct_provider}: {result.error or 'lookup failed'}")
            return
        report.ct_count = result.raw_count
        report.ct_sources.append(result.source.provider or provider.name)
        for entry in result.certificates:
            report.certificates.append(self._certificate_from_ct(entry, result))

    def _certificate_from_ct(self, entry: dict[str, Any], result: Any) -> CertificateInfo:
        """Normalize one CT log entry."""
        return CertificateInfo(
            serial_number=str(entry.get("serial_number", "")),
            fingerprint_sha256=str(entry.get("fingerprint_sha256", "")).lower(),
            fingerprint_sha1=str(entry.get("fingerprint_sha1", "")).lower(),
            subject_cn=str(entry.get("subject_cn", "")),
            subject_alternative_names=[str(item) for item in entry.get("subject_alternative_names", [])],
            issuer_cn=str(entry.get("issuer_cn", "")),
            issuer_organization=str(entry.get("issuer_organization", "")),
            not_before=entry.get("not_before"),
            not_after=entry.get("not_after"),
            signature_algorithm=str(entry.get("signature_algorithm", "")),
            public_key_algorithm=str(entry.get("public_key_algorithm", "")),
            public_key_bits=entry.get("public_key_bits"),
            source="ct",
            source_detail=str(entry.get("source_detail", "") or "crt.sh"),
            observed_at=now_utc(),
            confidence=result.confidence,
            raw=entry,
        )

    def _from_tls(self, host: str, port: int, report: CertificateReport) -> None:
        """Perform an authorized handshake and record the chain."""
        if self.probe is None:
            report.errors.append("no TLS probe configured")
            return
        try:
            chain = self.probe.chain(host, port, authorized=True)
        except Exception as exc:
            report.errors.append(f"TLS {host}:{port} - {type(exc).__name__}: {exc}")
            return
        report.chain = chain
        for certificate in chain.certificates:
            certificate.source = "tls"
            certificate.source_detail = f"{host}:{port}"
            certificate.observed_at = now_utc()
            report.certificates.append(certificate)
        if not chain.verified:
            report.errors.append(f"TLS {host}:{port} - chain did not verify: {chain.error}")

    def _covered(self, report: CertificateReport, hosts: Sequence[str]) -> list[str]:
        """Hosts covered by at least one observed certificate."""
        covered: set[str] = set()
        for certificate in report.certificates:
            for name in [certificate.subject_cn, *certificate.subject_alternative_names]:
                stripped = normalize_hostname(wildcard_strip(str(name)))
                if not stripped:
                    continue
                for host in hosts:
                    if host == stripped or host.endswith(f".{stripped}"):
                        covered.add(host)
        return sorted(covered)

    def _identity(self, item: CertificateInfo | dict[str, Any]) -> str:
        """Stable identity for a certificate (fingerprint, serial or CN)."""
        if isinstance(item, CertificateInfo):
            return item.identity
        return str(
            item.get("fingerprint_sha256") or item.get("serial_number") or item.get("subject_cn") or ""
        ).lower()

    def _coerce(self, item: CertificateInfo | dict[str, Any]) -> CertificateInfo:
        """Accept either a model or a stored dictionary."""
        if isinstance(item, CertificateInfo):
            return item
        return CertificateInfo.model_validate(item)

    def _validity_changed(self, prior: CertificateInfo, current: CertificateInfo) -> bool:
        """``True`` when the validity window moved."""
        before = prior.not_after
        after = current.not_after
        if before is None and after is None:
            return False
        if before is None or after is None:
            return True
        return before != after

    def _issuer_changed(self, prior: CertificateInfo, current: CertificateInfo) -> bool:
        """``True`` when the issuing CA differs."""
        return bool(prior.issuer_cn and current.issuer_cn and prior.issuer_cn != current.issuer_cn)


def certificate_observations(report: CertificateReport, *, target: str = "") -> list[dict[str, Any]]:
    """Turn a certificate report into evidence-backed observations.

    Each observation names the certificate, the check that failed and the exact
    value observed, so a downstream rule can produce a finding without guessing.
    """
    subject = target or report.target
    observations: list[dict[str, Any]] = []
    for certificate in report.expired():
        observations.append(
            {
                "id": "CERT-EXPIRED",
                "severity": "HIGH",
                "target": subject,
                "detail": f"certificate {certificate.identity[:16]} {describe_expiry(certificate)}",
                "evidence": f"not_after={certificate.not_after} issuer={certificate.issuer_cn}",
            }
        )
    for certificate in report.expiring(EXPIRY_WARNING_DAYS):
        remaining = certificate.days_until_expiry()
        if remaining is not None and remaining < 0:
            continue
        severity = "HIGH" if (remaining is not None and remaining < EXPIRY_CRITICAL_DAYS) else "MEDIUM"
        observations.append(
            {
                "id": "CERT-EXPIRING",
                "severity": severity,
                "target": subject,
                "detail": f"certificate {certificate.identity[:16]} {describe_expiry(certificate)}",
                "evidence": f"not_after={certificate.not_after} issuer={certificate.issuer_cn}",
            }
        )
    for issue in report.weak():
        observations.append(
            {
                "id": "CERT-WEAK",
                "severity": str(issue["severity"]),
                "target": subject,
                "detail": str(issue["issue"]),
                "evidence": f"certificate={str(issue['certificate'])[:16]}",
            }
        )
    if report.tls_attempted and report.chain is not None and not report.chain.verified:
        observations.append(
            {
                "id": "CERT-UNVERIFIED",
                "severity": "HIGH",
                "target": subject,
                "detail": f"the presented chain did not verify: {report.chain.error or 'unknown reason'}",
                "evidence": f"host={report.chain.host} chain_depth={len(report.chain.certificates)}",
            }
        )
    return observations


__all__ = [
    "EXPIRY_CRITICAL_DAYS",
    "EXPIRY_WARNING_DAYS",
    "CertificateEngine",
    "CertificateReport",
    "CertificateSetChange",
    "certificate_observations",
]

"""Immutable scan snapshots.

A snapshot is the normalized state of a target at one moment, plus a hash of that
state. Hashing is what makes change detection trustworthy: two snapshots with the
same hash are byte-identical, so "nothing changed" is a proof rather than an
opinion.

Snapshots are deliberately small and free of secrets - they record DNS answers,
certificate metadata and scores, never credentials and never raw provider JSON.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import Field

from dnscope.models.common import SchemaVersioned
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.hashing import payload_hash
from dnscope.utils.time_utils import utc_now_iso

#: Record types captured per host. Anything outside this list is ignored so a
#: new record type cannot silently change snapshot hashes.
SNAPSHOT_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
    "SRV",
    "NAPTR",
    "TLSA",
    "SSHFP",
    "DNSKEY",
    "DS",
)


class Snapshot(SchemaVersioned):
    """One immutable observation of a target."""

    snapshot_id: str
    target: str
    workspace: str = "default"
    label: str = ""
    created_at: str = Field(default_factory=utc_now_iso)
    #: Content hash - identical payloads always produce the identical hash.
    payload_hash: str = ""
    #: Normalized state, keyed by section.
    payload: dict[str, Any] = Field(default_factory=dict)
    #: Run metadata reproduced so a scan can be repeated.
    reproducibility: dict[str, Any] = Field(default_factory=dict)
    #: ``True`` when the snapshot came from the database rather than a live scan.
    from_database: bool = False

    @property
    def hosts(self) -> dict[str, Any]:
        """Per-host record sets."""
        return dict(self.payload.get("hosts") or {})

    @property
    def subdomains(self) -> dict[str, str]:
        """Hostname -> state."""
        return {str(key): str(value) for key, value in (self.payload.get("subdomains") or {}).items()}

    @property
    def certificates(self) -> dict[str, Any]:
        """Fingerprint -> certificate metadata."""
        return dict(self.payload.get("certificates") or {})

    @property
    def addresses(self) -> dict[str, Any]:
        """IP -> origin metadata."""
        return dict(self.payload.get("ips") or {})

    def section(self, name: str) -> Any:
        """One top-level section of the payload."""
        return self.payload.get(name)

    def summary(self) -> str:
        """One-line human summary."""
        return (
            f"{self.snapshot_id} {self.target} {self.created_at} "
            f"hosts={len(self.hosts)} certs={len(self.certificates)} hash={self.payload_hash[:12]}"
        )

    def to_dict(self, *, include_payload: bool = True) -> dict[str, Any]:
        """JSON-ready dictionary (payload optional, it can be large)."""
        data = {
            "snapshot_id": self.snapshot_id,
            "target": self.target,
            "workspace": self.workspace,
            "label": self.label,
            "created_at": self.created_at,
            "payload_hash": self.payload_hash,
            "from_database": self.from_database,
            "reproducibility": self.reproducibility,
            "counts": self.counts(),
        }
        if include_payload:
            data["payload"] = self.payload
        return data

    def counts(self) -> dict[str, int]:
        """Section sizes, for ``snapshot show`` summaries."""
        return {
            "hosts": len(self.hosts),
            "subdomains": len(self.subdomains),
            "certificates": len(self.certificates),
            "ips": len(self.addresses),
            "records": sum(
                len(values)
                for host in self.hosts.values()
                for values in (host.get("records") or {}).values()
            ),
            "providers": len(self.payload.get("cloud") or {}),
            "dangling": len(self.payload.get("dangling") or {}),
        }


class SnapshotBuilder:
    """Builds a :class:`Snapshot` from analyzer output."""

    def __init__(self, workspace: str = "default") -> None:
        self.workspace = workspace

    # ------------------------------------------------------------------ public

    def build(
        self,
        target: str,
        *,
        snapshot_id: str = "",
        label: str = "",
        answers: Mapping[str, Any] | None = None,
        discovery: Any = None,
        email: Any = None,
        dnssec: Any = None,
        health: Any = None,
        intelligence: Any = None,
        risk: Any = None,
        cloud: Sequence[Any] = (),
        takeover: Sequence[Any] = (),
        reproducibility: Mapping[str, Any] | None = None,
    ) -> Snapshot:
        """Normalize everything into one comparable payload."""
        from dnscope.utils.ids import new_id

        name = normalize_hostname(target)
        payload: dict[str, Any] = {
            "target": name,
            "hosts": self._hosts(name, answers or {}),
            "subdomains": self._subdomains(discovery),
            "email": self._email(name, email),
            "dnssec": self._dnssec(dnssec),
            "certificates": self._certificates(intelligence),
            "ips": self._ips(intelligence),
            "cloud": self._cloud(cloud),
            "dangling": self._dangling(takeover),
            "health": self._health(health),
            "risk": self._risk(risk),
        }
        snapshot = Snapshot(
            snapshot_id=snapshot_id or new_id("snap"),
            target=name,
            workspace=self.workspace,
            label=label,
            payload=payload,
            reproducibility=dict(reproducibility or {}),
        )
        snapshot.payload_hash = self.hash_of(payload)
        return snapshot

    def from_database(self, row: Mapping[str, Any]) -> Snapshot:
        """Rebuild a snapshot from a stored row."""
        return Snapshot(
            snapshot_id=str(row.get("snapshot_id", "")),
            target=str(row.get("target", "")),
            workspace=str(row.get("workspace", self.workspace)),
            label=str(row.get("label", "")),
            created_at=str(row.get("created_at", "")),
            payload_hash=str(row.get("payload_hash", "")),
            payload=dict(row.get("payload") or {}),
            from_database=True,
        )

    @staticmethod
    def hash_of(payload: Mapping[str, Any]) -> str:
        """Deterministic hash of a snapshot payload."""
        return payload_hash(dict(payload))

    # --------------------------------------------------------------- internals

    def _hosts(self, target: str, answers: Mapping[str, Any]) -> dict[str, Any]:
        """Per-host record sets, sorted so ordering never causes a false diff."""
        hosts: dict[str, Any] = {}
        for hostname, answer in answers.items():
            name = normalize_hostname(str(hostname))
            if not name:
                continue
            records: dict[str, list[str]] = {}
            ttls: dict[str, int] = {}
            for query in getattr(answer, "queries", []):
                rtype = str(query.rtype).upper()
                if rtype not in SNAPSHOT_RECORD_TYPES:
                    continue
                values = sorted({str(value) for value in query.values})
                if values:
                    records[rtype] = values
                    # The lowest TTL of the set is what a cache will honour.
                    ttls[rtype] = int(query.min_ttl() or 0)
            hosts[name] = {
                "records": records,
                "ttls": ttls,
                "status": {
                    str(query.rtype).upper(): str(query.status)
                    for query in getattr(answer, "queries", [])
                },
            }
        if target not in hosts:
            hosts[target] = {"records": {}, "ttls": {}, "status": {}}
        return dict(sorted(hosts.items()))

    def _subdomains(self, discovery: Any) -> dict[str, str]:
        """Hostname -> lifecycle state."""
        if discovery is None:
            return {}
        found: dict[str, str] = {}
        for host in getattr(discovery, "hosts", []) or []:
            name = normalize_hostname(str(getattr(host, "hostname", "")))
            if name:
                found[name] = str(getattr(host, "state", "UNKNOWN"))
        return dict(sorted(found.items()))

    def _email(self, target: str, email: Any) -> dict[str, Any]:
        """Mail-authentication state, reduced to comparable values."""
        if email is None:
            return {}
        spf = getattr(email, "spf", None)
        dmarc = getattr(email, "dmarc", None)
        caa = getattr(email, "caa", None)
        mta_sts = getattr(email, "mta_sts", None)
        tls_rpt = getattr(email, "tls_rpt", None)
        return {
            "spf_found": bool(getattr(spf, "found", False)),
            "spf_all": str(getattr(spf, "all_mechanism", "") or ""),
            "spf_lookups": int(getattr(spf, "lookup_count", 0) or 0),
            "spf_includes": sorted(str(item) for item in getattr(spf, "include_chain", []) or []),
            "dmarc_found": bool(getattr(dmarc, "found", False)),
            "dmarc_policy": str(getattr(dmarc, "policy", "") or ""),
            "dmarc_subdomain_policy": str(getattr(dmarc, "subdomain_policy", "") or ""),
            "dmarc_pct": getattr(dmarc, "percentage", None),
            "dmarc_rua": sorted(str(item) for item in getattr(dmarc, "rua", []) or []),
            "dkim": sorted(
                {
                    f"{result.selector}:{result.key_size_bits or 0}"
                    for result in (getattr(email, "dkim", []) or [])
                    if getattr(result, "found", False)
                }
            ),
            "dkim_selectors_tested": sorted(str(item) for item in getattr(email, "dkim_selectors_tested", []) or []),
            "caa_issuers": sorted(str(item) for item in (caa.issuers() if caa else []) or []),
            "mta_sts_found": bool(getattr(mta_sts, "found", False)),
            "mta_sts_mode": str(getattr(mta_sts, "policy_mode", "") or ""),
            "tls_rpt_found": bool(getattr(tls_rpt, "found", False)),
            "mx": sorted(str(item) for item in getattr(email, "mx_hosts", []) or []),
            "mx_providers": sorted(str(item) for item in getattr(email, "mx_providers", []) or []),
        }

    def _dnssec(self, dnssec: Any) -> dict[str, Any]:
        """DNSSEC state, reduced to comparable values."""
        if dnssec is None:
            return {}
        return {
            "status": str(getattr(dnssec, "status", "") or ""),
            "algorithms": sorted(str(item) for item in getattr(dnssec, "algorithms", []) or []),
            "key_count": len(getattr(dnssec, "keys", []) or []),
            "ds_count": len(getattr(dnssec, "ds_records", []) or []),
            "rrsig_types": sorted(str(item) for item in getattr(dnssec, "rrsig_types", []) or []),
            "nsec_present": bool(getattr(dnssec, "nsec_present", False)),
            "ad_bit_observed": bool(getattr(dnssec, "ad_bit_observed", False)),
        }

    def _certificates(self, intelligence: Any) -> dict[str, Any]:
        """Certificate metadata keyed by fingerprint."""
        report = getattr(intelligence, "certificates", None) if intelligence is not None else None
        if report is None:
            return {}
        found: dict[str, Any] = {}
        for certificate in getattr(report, "certificates", []) or []:
            identity = str(certificate.identity or "")
            if not identity:
                continue
            found[identity] = {
                "issuer": str(certificate.issuer_cn or ""),
                "not_after": certificate.not_after.isoformat() if certificate.not_after else "",
                "sans": sorted(str(item) for item in certificate.subject_alternative_names or []),
                "key_bits": certificate.public_key_bits,
                "key_algorithm": str(certificate.public_key_algorithm or ""),
                "source": str(certificate.source or ""),
            }
        return dict(sorted(found.items()))

    def _ips(self, intelligence: Any) -> dict[str, Any]:
        """Address origin metadata."""
        report = getattr(intelligence, "ip_intelligence", None) if intelligence is not None else None
        if report is None:
            return {}
        found: dict[str, Any] = {}
        for record in getattr(report, "records", []) or []:
            found[str(record.ip)] = {
                "asn": str(record.asn or ""),
                "prefix": str(record.prefix or ""),
                "provider": str(record.provider or ""),
                "ptr": sorted(str(item) for item in record.ptr or []),
            }
        return dict(sorted(found.items()))

    def _cloud(self, cloud: Sequence[Any]) -> dict[str, list[str]]:
        """Provider -> subjects."""
        found: dict[str, set[str]] = {}
        for match in cloud or []:
            provider = str(getattr(match, "provider", "") or "")
            subject = str(getattr(match, "subject", "") or "")
            if provider:
                found.setdefault(provider, set()).add(subject)
        return {key: sorted(value) for key, value in sorted(found.items())}

    def _dangling(self, takeover: Sequence[Any]) -> dict[str, str]:
        """Hostname -> CNAME target for dangling candidates."""
        found: dict[str, str] = {}
        for indicator in takeover or []:
            if not getattr(indicator, "is_dangling", False):
                continue
            name = normalize_hostname(str(getattr(indicator, "hostname", "")))
            if name:
                found[name] = str(getattr(indicator, "cname_target", ""))
        return dict(sorted(found.items()))

    def _health(self, health: Any) -> dict[str, Any]:
        """The three scores, rounded so tiny jitter does not create changes."""
        if health is None:
            return {}
        return {
            "health": round(float(getattr(health.health, "score", 0.0)), 1),
            "reliability": round(float(getattr(health.reliability, "score", 0.0)), 1),
            "security": round(float(getattr(health.security, "score", 0.0)), 1),
            "overall": round(float(getattr(health, "overall", 0.0)), 1),
        }

    def _risk(self, risk: Any) -> dict[str, Any]:
        """Risk score and level."""
        if risk is None:
            return {}
        return {
            "score": round(float(getattr(risk, "normalized", 0.0)), 1),
            "level": str(getattr(risk, "level", "") or ""),
            "findings": int(getattr(risk, "findings", 0) or 0),
        }


def snapshot_diff_size(previous: Snapshot, current: Snapshot) -> dict[str, int]:
    """Cheap comparison used to decide whether a full diff is worth running."""
    if previous.payload_hash == current.payload_hash:
        return {"identical": 1}
    return {
        "hosts": len(set(previous.hosts) ^ set(current.hosts)),
        "subdomains": len(set(previous.subdomains) ^ set(current.subdomains)),
        "certificates": len(set(previous.certificates) ^ set(current.certificates)),
        "ips": len(set(previous.addresses) ^ set(current.addresses)),
    }


__all__ = [
    "SNAPSHOT_RECORD_TYPES",
    "Snapshot",
    "SnapshotBuilder",
    "snapshot_diff_size",
]

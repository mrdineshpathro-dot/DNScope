"""Change detection between snapshots.

The detector walks two snapshots section by section and emits a typed
:class:`~dnscope.models.changes.ChangeRecord` for every difference it can name.
Each record says what the previous value was, what it is now, and - after the
significance engine runs - whether an operator needs to hear about it.

Design choices that matter:

* A field that is *absent* in both snapshots produces no change. Absence of data
  is not a change from "nothing" to "nothing".
* A field present in the previous snapshot and absent in the current one is a
  removal, which is usually the most interesting kind of change.
* Order-insensitive comparisons are used for record sets, so a resolver returning
  the same records in a different order is not a change.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field

from dnscope.models.changes import ChangeRecord, ChangeType
from dnscope.models.common import SchemaVersioned
from dnscope.monitoring.snapshot import Snapshot
from dnscope.scoring.significance import SignificanceEngine
from dnscope.utils.domains import registered_domain
from dnscope.utils.ids import new_id
from dnscope.utils.time_utils import utc_now_iso

#: TTL ratios below which a TTL change counts as a real change rather than noise.
TTL_NOISE_RATIO = 0.9


class DiffSummary(SchemaVersioned):
    """Outcome of comparing two snapshots."""

    target: str
    from_snapshot: str = ""
    to_snapshot: str = ""
    compared_at: str = Field(default_factory=utc_now_iso)
    changes: list[ChangeRecord] = Field(default_factory=list)
    #: ``True`` when the two payloads were byte-identical.
    identical: bool = False
    #: Sections that were present in one snapshot but not the other.
    missing_sections: dict[str, str] = Field(default_factory=dict)

    @property
    def count(self) -> int:
        """Total number of changes."""
        return len(self.changes)

    def significant(self, minimum: str = "MEDIUM") -> list[ChangeRecord]:
        """Changes at or above ``minimum`` significance."""
        from dnscope.models.common import Significance

        threshold = Significance.coerce(minimum)
        return [
            change
            for change in self.changes
            if Significance.coerce(change.significance).rank >= threshold.rank
        ]

    def by_type(self) -> dict[str, int]:
        """Change counts per change type."""
        counts: dict[str, int] = {}
        for change in self.changes:
            counts[change.change_type] = counts.get(change.change_type, 0) + 1
        return dict(sorted(counts.items()))

    def by_significance(self) -> dict[str, int]:
        """Change counts per significance level."""
        counts: dict[str, int] = {}
        for change in self.changes:
            counts[change.significance] = counts.get(change.significance, 0) + 1
        return counts

    def summary(self) -> str:
        """One-line human summary."""
        if self.identical:
            return f"{self.target}: no change between {self.from_snapshot[:12]} and {self.to_snapshot[:12]}"
        notable = len(self.significant())
        return (
            f"{self.target}: {self.count} change(s), {notable} at MEDIUM or above "
            f"({self.from_snapshot[:12]} -> {self.to_snapshot[:12]})"
        )

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return {
            "target": self.target,
            "from_snapshot": self.from_snapshot,
            "to_snapshot": self.to_snapshot,
            "compared_at": self.compared_at,
            "identical": self.identical,
            "count": self.count,
            "by_type": self.by_type(),
            "by_significance": self.by_significance(),
            "missing_sections": self.missing_sections,
            "changes": [change.model_dump(mode="json") for change in self.changes],
        }


class ChangeDetector:
    """Produces typed changes from two snapshots."""

    def __init__(self, engine: SignificanceEngine | None = None, *, workspace: str = "default") -> None:
        self.engine = engine or SignificanceEngine()
        self.workspace = workspace

    # ------------------------------------------------------------------ public

    def compare(
        self,
        previous: Snapshot,
        current: Snapshot,
        *,
        classify: bool = True,
    ) -> DiffSummary:
        """Diff two snapshots and (optionally) classify each change."""
        summary = DiffSummary(
            target=current.target,
            from_snapshot=previous.snapshot_id,
            to_snapshot=current.snapshot_id,
        )
        if previous.payload_hash and previous.payload_hash == current.payload_hash:
            summary.identical = True
            return summary

        before = previous.payload or {}
        after = current.payload or {}
        for section in set(before) | set(after):
            if section not in before:
                summary.missing_sections[section] = "absent in the previous snapshot"
                continue
            if section not in after:
                summary.missing_sections[section] = "absent in the current snapshot"
                continue

        summary.changes.extend(self._hosts(before, after, current.target))
        summary.changes.extend(self._subdomains(before, after, current.target))
        summary.changes.extend(self._email(before, after, current.target))
        summary.changes.extend(self._dnssec(before, after, current.target))
        summary.changes.extend(self._certificates(before, after, current.target))
        summary.changes.extend(self._ips(before, after, current.target))
        summary.changes.extend(self._cloud(before, after, current.target))
        summary.changes.extend(self._dangling(before, after, current.target))
        summary.changes.extend(self._scores(before, after, current.target))

        if classify:
            context = {"target": current.target, "domain": registered_domain(current.target)}
            self.engine.classify_many(summary.changes, context)
        return summary

    # --------------------------------------------------------------- internals

    def _change(
        self,
        change_type: str,
        target: str,
        field: str,
        previous: Any,
        current: Any,
        *,
        first_observation: bool = False,
        context: dict[str, Any] | None = None,
        from_snapshot: str = "",
        to_snapshot: str = "",
    ) -> ChangeRecord:
        """Build one change record."""
        return ChangeRecord(
            change_id=new_id("chg"),
            change_type=change_type,
            target=target,
            workspace=self.workspace,
            field=field,
            previous=previous,
            current=current,
            first_observation=first_observation,
            context=context or {},
            from_snapshot=from_snapshot,
            to_snapshot=to_snapshot,
        )

    def _hosts(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Per-host, per-record-type changes."""
        changes: list[ChangeRecord] = []
        previous_hosts = dict(before.get("hosts") or {})
        current_hosts = dict(after.get("hosts") or {})
        type_map = {
            "A": ChangeType.A_CHANGED,
            "AAAA": ChangeType.AAAA_CHANGED,
            "CNAME": ChangeType.CNAME_CHANGED,
            "MX": ChangeType.MX_CHANGED,
            "NS": ChangeType.NS_CHANGED,
            "TXT": ChangeType.TXT_CHANGED,
            "SOA": ChangeType.SOA_CHANGED,
            "CAA": ChangeType.CAA_CHANGED,
        }
        for hostname in sorted(set(previous_hosts) | set(current_hosts)):
            prior_records = dict((previous_hosts.get(hostname) or {}).get("records") or {})
            current_records = dict((current_hosts.get(hostname) or {}).get("records") or {})
            for rtype in sorted(set(prior_records) | set(current_records)):
                prior = sorted(prior_records.get(rtype) or [])
                current = sorted(current_records.get(rtype) or [])
                if prior == current:
                    continue
                if rtype in ("DNSKEY", "DS"):
                    change_type = ChangeType.DNSSEC_CHANGED
                else:
                    # Record types without a dedicated change type are reported
                    # generically, with the type named in the field.
                    change_type = type_map.get(rtype, ChangeType.RECORD_CHANGED)
                changes.append(
                    self._change(
                        change_type,
                        hostname,
                        rtype,
                        prior or None,
                        current or None,
                        first_observation=not prior,
                        context={
                            "added": sorted(set(current) - set(prior)),
                            "removed": sorted(set(prior) - set(current)),
                            "record_type": rtype,
                        },
                    )
                )
            prior_ttls = dict((previous_hosts.get(hostname) or {}).get("ttls") or {})
            current_ttls = dict((current_hosts.get(hostname) or {}).get("ttls") or {})
            if prior_ttls and current_ttls and rtype_ttl_changed(prior_ttls, current_ttls):
                changes.append(
                    self._change(
                        ChangeType.TTL_CHANGED,
                        hostname,
                        "TTL",
                        _ttl_view(prior_ttls),
                        _ttl_view(current_ttls),
                        context={"record_type": "TTL"},
                    )
                )
        return changes

    def _subdomains(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Subdomain lifecycle changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("subdomains") or {})
        current = dict(after.get("subdomains") or {})
        for hostname in sorted(set(previous) | set(current)):
            prior_state = previous.get(hostname)
            current_state = current.get(hostname)
            if prior_state == current_state:
                continue
            if prior_state is None:
                changes.append(
                    self._change(
                        ChangeType.SUBDOMAIN_ADDED,
                        hostname,
                        "hostname",
                        None,
                        current_state,
                        first_observation=True,
                        context={"state": current_state},
                    )
                )
                # A subdomain that appears already dangling is worth its own
                # typed change: SUBDOMAIN_ADDED alone would rate it as an
                # ordinary discovery.
                if str(current_state).upper() == "POSSIBLE_DANGLING":
                    changes.append(
                        self._change(
                            ChangeType.DANGLING_DETECTED,
                            hostname,
                            "state",
                            None,
                            current_state,
                            first_observation=True,
                            context={"state": current_state},
                        )
                    )
            elif current_state is None:
                changes.append(
                    self._change(
                        ChangeType.SUBDOMAIN_REMOVED,
                        hostname,
                        "hostname",
                        prior_state,
                        None,
                        context={"previous_state": prior_state},
                    )
                )
            else:
                changes.append(
                    self._change(
                        ChangeType.SUBDOMAIN_STATE_CHANGED,
                        hostname,
                        "state",
                        prior_state,
                        current_state,
                        context={"from": prior_state, "to": current_state},
                    )
                )
                if str(current_state).upper() == "POSSIBLE_DANGLING":
                    changes.append(
                        self._change(
                            ChangeType.DANGLING_DETECTED,
                            hostname,
                            "state",
                            prior_state,
                            current_state,
                            context={"from": prior_state},
                        )
                    )
        return changes

    def _email(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Mail-authentication changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("email") or {})
        current = dict(after.get("email") or {})
        if not previous and not current:
            return changes

        # Each field maps to the change type that describes it, so the
        # significance engine can tell a DMARC policy regression from an
        # unrelated TXT edit.
        watched = {
            "spf_found": ChangeType.SPF_CHANGED,
            "spf_all": ChangeType.SPF_CHANGED,
            "spf_includes": ChangeType.SPF_CHANGED,
            "spf_lookups": ChangeType.SPF_CHANGED,
            "dmarc_found": ChangeType.DMARC_CHANGED,
            "dmarc_policy": ChangeType.DMARC_CHANGED,
            "dmarc_subdomain_policy": ChangeType.DMARC_CHANGED,
            "dmarc_pct": ChangeType.DMARC_CHANGED,
            "dmarc_rua": ChangeType.DMARC_CHANGED,
            "dkim": ChangeType.DKIM_CHANGED,
            "dkim_selectors_tested": ChangeType.DKIM_CHANGED,
            "mta_sts_found": ChangeType.TRANSPORT_POLICY_CHANGED,
            "mta_sts_mode": ChangeType.TRANSPORT_POLICY_CHANGED,
            "tls_rpt_found": ChangeType.TRANSPORT_POLICY_CHANGED,
            "caa_issuers": ChangeType.CAA_CHANGED,
            "mx": ChangeType.MX_CHANGED,
            "mx_providers": ChangeType.MX_CHANGED,
        }
        for key, change_type in watched.items():
            prior = previous.get(key)
            now = current.get(key)
            if prior == now or (prior is None and now is None):
                continue
            changes.append(
                self._change(
                    change_type,
                    target,
                    key,
                    prior,
                    now,
                    first_observation=prior is None,
                    context={"field": key, "mechanism": key.split("_", 1)[0]},
                )
            )
        return changes

    def _dnssec(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """DNSSEC state changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("dnssec") or {})
        current = dict(after.get("dnssec") or {})
        if not previous and not current:
            return changes
        for key in ("status", "algorithms", "key_count", "ds_count", "rrsig_types", "nsec_present"):
            prior = previous.get(key)
            now = current.get(key)
            if prior == now or (prior is None and now is None):
                continue
            changes.append(
                self._change(
                    ChangeType.DNSSEC_CHANGED,
                    target,
                    key,
                    prior,
                    now,
                    first_observation=prior is None,
                    context={"field": key},
                )
            )
        return changes

    def _certificates(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Certificate set changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("certificates") or {})
        current = dict(after.get("certificates") or {})
        for fingerprint in sorted(set(previous) | set(current)):
            prior = previous.get(fingerprint)
            now = current.get(fingerprint)
            if prior == now:
                continue
            if prior is None and now is not None:
                changes.append(
                    self._change(
                        ChangeType.CERTIFICATE_ADDED,
                        target,
                        fingerprint,
                        None,
                        now,
                        first_observation=True,
                        context={"issuer": now.get("issuer", "")},
                    )
                )
            elif now is None and prior is not None:
                changes.append(
                    self._change(
                        ChangeType.CERTIFICATE_REMOVED,
                        target,
                        fingerprint,
                        prior,
                        None,
                        context={"issuer": prior.get("issuer", "")},
                    )
                )
            else:
                if dict(prior).get("issuer") != dict(now).get("issuer"):
                    changes.append(
                        self._change(
                            ChangeType.CERTIFICATE_ISSUER_CHANGED,
                            target,
                            fingerprint,
                            dict(prior).get("issuer"),
                            dict(now).get("issuer"),
                            context={"fingerprint": fingerprint},
                        )
                    )
                if sorted(dict(prior).get("sans") or []) != sorted(dict(now).get("sans") or []):
                    changes.append(
                        self._change(
                            ChangeType.SAN_CHANGED,
                            target,
                            fingerprint,
                            sorted(dict(prior).get("sans") or []),
                            sorted(dict(now).get("sans") or []),
                        )
                    )
                if dict(prior).get("key_algorithm") != dict(now).get("key_algorithm") or dict(prior).get(
                    "key_bits"
                ) != dict(now).get("key_bits"):
                    changes.append(
                        self._change(
                            ChangeType.KEY_ALGORITHM_CHANGED,
                            target,
                            fingerprint,
                            {
                                "algorithm": dict(prior).get("key_algorithm"),
                                "bits": dict(prior).get("key_bits"),
                            },
                            {"algorithm": dict(now).get("key_algorithm"), "bits": dict(now).get("key_bits")},
                        )
                    )
        return changes

    def _ips(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Address and ASN changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("ips") or {})
        current = dict(after.get("ips") or {})
        for address in sorted(set(previous) | set(current)):
            prior = previous.get(address)
            now = current.get(address)
            if prior == now:
                continue
            if prior is None and now is not None:
                changes.append(
                    self._change(ChangeType.IP_ADDED, target, address, None, now, first_observation=True)
                )
                continue
            if now is None and prior is not None:
                changes.append(self._change(ChangeType.IP_REMOVED, target, address, prior, None))
                continue
            if dict(prior).get("asn") != dict(now).get("asn"):
                changes.append(
                    self._change(
                        ChangeType.ASN_CHANGED,
                        target,
                        address,
                        dict(prior).get("asn"),
                        dict(now).get("asn"),
                        context={"ip": address, "prefix": dict(now).get("prefix", "")},
                    )
                )
        return changes

    def _cloud(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Provider assignment changes."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("cloud") or {})
        current = dict(after.get("cloud") or {})
        if previous == current:
            return changes
        added = sorted(set(current) - set(previous))
        removed = sorted(set(previous) - set(current))
        if added or removed:
            changes.append(
                self._change(
                    ChangeType.CLOUD_PROVIDER_CHANGED,
                    target,
                    "providers",
                    sorted(previous),
                    sorted(current),
                    first_observation=not previous,
                    context={"added": added, "removed": removed},
                )
            )
        return changes

    def _dangling(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Newly detected dangling records."""
        changes: list[ChangeRecord] = []
        previous = dict(before.get("dangling") or {})
        current = dict(after.get("dangling") or {})
        for hostname in sorted(set(current) - set(previous)):
            changes.append(
                self._change(
                    ChangeType.DANGLING_DETECTED,
                    hostname,
                    "cname_target",
                    None,
                    current.get(hostname),
                    first_observation=True,
                    context={"state": "POSSIBLE_DANGLING"},
                )
            )
        return changes

    def _scores(self, before: Mapping[str, Any], after: Mapping[str, Any], target: str) -> list[ChangeRecord]:
        """Health and risk score movement."""
        changes: list[ChangeRecord] = []
        previous_health = dict(before.get("health") or {})
        current_health = dict(after.get("health") or {})
        if previous_health and current_health and previous_health != current_health:
            changes.append(
                self._change(
                    ChangeType.HEALTH_SCORE_CHANGED,
                    target,
                    "health",
                    previous_health,
                    current_health,
                    context={
                        "delta": round(
                            float(current_health.get("overall", 0.0)) - float(previous_health.get("overall", 0.0)),
                            1,
                        )
                    },
                )
            )
        previous_risk = dict(before.get("risk") or {})
        current_risk = dict(after.get("risk") or {})
        if previous_risk and current_risk and previous_risk != current_risk:
            changes.append(
                self._change(
                    ChangeType.POLICY_CHANGED,
                    target,
                    "risk",
                    previous_risk,
                    current_risk,
                    context={"from_level": previous_risk.get("level"), "to_level": current_risk.get("level")},
                )
            )
        return changes


def _ttl_view(records: Mapping[str, Any]) -> dict[str, Any]:
    """Compact TTL view used when TTLs move."""
    return {key: value for key, value in sorted(records.items()) if value}


def rtype_ttl_changed(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """``True`` when TTLs moved by more than the noise threshold.

    TTLs count down in a resolver's cache, so small movements are expected. Only
    a change of more than ten percent is treated as a configuration change.
    """
    keys = set(previous) | set(current)
    for key in keys:
        try:
            before = float(previous.get(key) or 0)
            after = float(current.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if before == 0 or after == 0:
            continue
        ratio = min(before, after) / max(before, after)
        if ratio < TTL_NOISE_RATIO:
            return True
    return False


__all__ = ["TTL_NOISE_RATIO", "ChangeDetector", "DiffSummary", "rtype_ttl_changed"]

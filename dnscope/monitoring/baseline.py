"""Baselines and policy comparison.

A baseline is "the state this target is supposed to be in". Comparing a snapshot
against it produces *policy violations* - statements that a specific expectation
is not met, each naming the expectation and the observed value.

DNScope never claims compliance with an external standard here. A baseline is the
operator's own expectation set; when an organization wants to map these to a
standard, the mapping has to be written down explicitly in the policy pack.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import Field

from dnscope.models.common import SchemaVersioned
from dnscope.monitoring.snapshot import Snapshot
from dnscope.utils.ids import new_id
from dnscope.utils.time_utils import utc_now_iso

#: Severity used for a violated expectation.
VIOLATION_SEVERITIES = {"require": "HIGH", "forbid": "HIGH", "max": "MEDIUM", "min": "MEDIUM"}


class Expectation(SchemaVersioned):
    """One thing a baseline requires of a target."""

    name: str
    #: ``require`` | ``forbid`` | ``min`` | ``max``.
    kind: str = "require"
    #: What the expectation applies to.
    subject: str = ""
    #: Expected value(s); interpretation depends on ``kind``.
    expected: Any = None
    description: str = ""
    severity: str = "MEDIUM"
    #: Optional reference (RFC, internal policy document) for the report.
    reference: str = ""

    def summary(self) -> str:
        """One-line human description."""
        return f"{self.kind} {self.subject} = {self.expected}"


class Violation(SchemaVersioned):
    """An expectation that the observed state does not meet."""

    expectation: str
    kind: str = "require"
    subject: str = ""
    expected: Any = None
    observed: Any = None
    severity: str = "MEDIUM"
    description: str = ""
    reference: str = ""

    def summary(self) -> str:
        """One-line human description."""
        return f"{self.severity} {self.expectation}: expected {self.expected}, observed {self.observed}"

    def to_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return self.model_dump(mode="json", exclude_none=exclude_none)


class Baseline(SchemaVersioned):
    """A recorded expected state for one target."""

    baseline_id: str
    target: str
    workspace: str = "default"
    label: str = "default"
    #: Hash of the snapshot the baseline was taken from.
    payload_hash: str = ""
    snapshot_id: str = ""
    created_at: str = Field(default_factory=utc_now_iso)
    #: Explicit expectations, evaluated independently of the snapshot hash.
    expectations: list[Expectation] = Field(default_factory=list)
    #: Normalized state captured when the baseline was taken.
    payload: dict[str, Any] = Field(default_factory=dict)
    #: Who recorded it, for the audit trail.
    recorded_by: str = ""

    def summary(self) -> str:
        """One-line human description."""
        return (
            f"{self.baseline_id} {self.target} label={self.label} "
            f"expectations={len(self.expectations)} hash={self.payload_hash[:12]}"
        )

    def to_dict(self, *, exclude_none: bool = True, include_payload: bool = False) -> dict[str, Any]:
        """JSON-ready dictionary (payload omitted by default, it can be large)."""
        data: dict[str, Any] = {
            "baseline_id": self.baseline_id,
            "target": self.target,
            "workspace": self.workspace,
            "label": self.label,
            "payload_hash": self.payload_hash,
            "snapshot_id": self.snapshot_id,
            "created_at": self.created_at,
            "recorded_by": self.recorded_by,
            "expectations": [item.model_dump(mode="json") for item in self.expectations],
        }
        if include_payload:
            data["payload"] = self.payload
        return data


class BaselineManager:
    """Creates baselines and compares snapshots against them."""

    def __init__(self, workspace: str = "default") -> None:
        self.workspace = workspace

    # ------------------------------------------------------------------ create

    def from_snapshot(
        self,
        snapshot: Snapshot,
        *,
        label: str = "default",
        expectations: Sequence[Expectation | Mapping[str, Any]] = (),
        recorded_by: str = "",
        baseline_id: str = "",
    ) -> Baseline:
        """Record the current state as the expected state."""
        return Baseline(
            baseline_id=baseline_id or new_id("base"),
            target=snapshot.target,
            workspace=snapshot.workspace or self.workspace,
            label=label,
            payload_hash=snapshot.payload_hash,
            snapshot_id=snapshot.snapshot_id,
            expectations=[self._expectation(item) for item in expectations],
            payload=dict(snapshot.payload or {}),
            recorded_by=recorded_by,
        )

    def from_policy(
        self,
        target: str,
        expectations: Sequence[Expectation | Mapping[str, Any]],
        *,
        label: str = "policy",
        recorded_by: str = "",
    ) -> Baseline:
        """Create a baseline from expectations alone (no captured state)."""
        return Baseline(
            baseline_id=new_id("base"),
            target=target,
            workspace=self.workspace,
            label=label,
            expectations=[self._expectation(item) for item in expectations],
            recorded_by=recorded_by,
        )

    def from_database(self, row: Mapping[str, Any]) -> Baseline:
        """Rebuild a baseline from a stored row."""
        raw = row.get("payload") or {}
        expectations = raw.get("expectations") if isinstance(raw, dict) else None
        return Baseline(
            baseline_id=str(row.get("baseline_id", "")),
            target=str(row.get("target", "")),
            workspace=str(row.get("workspace", self.workspace)),
            label=str(row.get("label", "default")),
            payload_hash=str(row.get("payload_hash", "")),
            created_at=str(row.get("created_at", "")),
            expectations=[self._expectation(item) for item in (expectations or [])],
            payload=dict(raw.get("state") or {}) if isinstance(raw, dict) else {},
        )

    def payload_for_storage(self, baseline: Baseline) -> dict[str, Any]:
        """Shape stored in the ``baselines.payload`` column."""
        return {
            "expectations": [item.model_dump(mode="json") for item in baseline.expectations],
            "state": baseline.payload,
            "recorded_by": baseline.recorded_by,
            "snapshot_id": baseline.snapshot_id,
        }

    # ----------------------------------------------------------------- compare

    def compare(self, baseline: Baseline, snapshot: Snapshot) -> list[Violation]:
        """Return every expectation the snapshot fails to meet."""
        violations = [self._check(item, snapshot) for item in baseline.expectations]
        return [item for item in violations if item is not None]

    def drift(self, baseline: Baseline, snapshot: Snapshot) -> dict[str, Any]:
        """Structural drift between the baseline state and the current one.

        Unlike :meth:`compare`, this does not judge anything: it lists what
        differs so an operator can decide whether the baseline is stale or the
        target has changed.
        """
        from dnscope.monitoring.detector import ChangeDetector

        if not baseline.payload:
            return {"available": False, "reason": "the baseline captured no state"}
        detector = ChangeDetector(workspace=baseline.workspace)
        previous = Snapshot(
            snapshot_id=baseline.snapshot_id or baseline.baseline_id,
            target=baseline.target,
            workspace=baseline.workspace,
            payload=dict(baseline.payload),
            payload_hash=baseline.payload_hash,
            created_at=baseline.created_at,
        )
        diff = detector.compare(previous, snapshot)
        return {
            "available": True,
            "identical": diff.identical,
            "count": diff.count,
            "by_type": diff.by_type(),
            "by_significance": diff.by_significance(),
            "changes": [change.model_dump(mode="json") for change in diff.changes],
        }

    # --------------------------------------------------------------- internals

    def _expectation(self, item: Expectation | Mapping[str, Any]) -> Expectation:
        """Accept either a model or a plain mapping."""
        if isinstance(item, Expectation):
            return item
        data = dict(item)
        return Expectation(
            name=str(data.get("name") or data.get("id") or "expectation"),
            kind=str(data.get("kind") or "require").lower(),
            subject=str(data.get("subject") or ""),
            expected=data.get("expected"),
            description=str(data.get("description") or ""),
            severity=str(data.get("severity") or VIOLATION_SEVERITIES.get(str(data.get("kind")), "MEDIUM")),
            reference=str(data.get("reference") or ""),
        )

    def _check(self, expectation: Expectation, snapshot: Snapshot) -> Violation | None:
        """Evaluate one expectation, returning ``None`` when it is met."""
        observed = self._observe(expectation.subject, snapshot)
        expected = expectation.expected
        failed = False
        if expectation.kind == "require":
            failed = not self._matches(observed, expected)
        elif expectation.kind == "forbid":
            failed = self._matches(observed, expected)
        elif expectation.kind in ("min", "max"):
            observed_number = _to_number(observed)
            expected_number = _to_number(expected)
            if observed_number is None or expected_number is None:
                # A missing or non-numeric value cannot satisfy a numeric bound,
                # and comparing against None would raise.
                failed = True
            elif expectation.kind == "min":
                failed = observed_number < expected_number
            else:
                failed = observed_number > expected_number
        else:
            return Violation(
                expectation=expectation.name,
                kind=expectation.kind,
                subject=expectation.subject,
                expected=expected,
                observed=observed,
                severity="INFO",
                description=f"unknown expectation kind '{expectation.kind}'",
                reference=expectation.reference,
            )
        if not failed:
            return None
        return Violation(
            expectation=expectation.name,
            kind=expectation.kind,
            subject=expectation.subject,
            expected=expected,
            observed=observed,
            severity=expectation.severity,
            description=expectation.description,
            reference=expectation.reference,
        )

    def _observe(self, subject: str, snapshot: Snapshot) -> Any:
        """Read one value out of a snapshot using a dotted subject path.

        Subjects are deliberately simple - ``dnssec.status``,
        ``email.dmarc_policy``, ``hosts.example.com.records.NS`` - so a policy
        author can see exactly what is being compared.
        """
        parts = [item for item in str(subject).split(".") if item]
        if not parts:
            return None
        current: Any = snapshot.payload
        for part in parts:
            if isinstance(current, Mapping):
                if part not in current:
                    return None
                current = current[part]
            else:
                return None
        return current

    def _matches(self, observed: Any, expected: Any) -> bool:
        """Compare an observed value with an expectation.

        Lists are compared as sets so ordering never causes a false violation,
        and a list expectation means "every listed value must be present".
        """
        if isinstance(expected, (list, tuple, set)):
            observed_set = (
                {str(item) for item in observed}
                if isinstance(observed, (list, tuple, set))
                else {str(observed)}
            )
            return {str(item) for item in expected}.issubset(observed_set)
        if isinstance(observed, (list, tuple, set)):
            return str(expected) in {str(item) for item in observed}
        if isinstance(expected, bool) or isinstance(observed, bool):
            return bool(observed) is bool(expected)
        return str(observed).lower() == str(expected).lower()


def _to_number(value: Any) -> float | None:
    """Numeric coercion for min/max expectations; counts lists and mappings."""
    if isinstance(value, (list, tuple, set)):
        return float(len(value))
    if isinstance(value, Mapping):
        return float(len(value))
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def common_expectations() -> list[Expectation]:
    """A starting set of expectations an operator can copy into a policy pack.

    These are DNS hygiene expectations, not a compliance framework: each one
    names what it checks so nobody mistakes the list for an audit.
    """
    return [
        Expectation(
            name="dnssec-enabled",
            kind="forbid",
            subject="dnssec.status",
            expected="UNSIGNED",
            severity="MEDIUM",
            description="the zone should be signed with DNSSEC",
            reference="https://datatracker.ietf.org/doc/html/rfc4033",
        ),
        Expectation(
            name="spf-not-permissive",
            kind="forbid",
            subject="email.spf_all",
            expected="+all",
            severity="HIGH",
            description="SPF must not authorize arbitrary senders",
            reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
        ),
        Expectation(
            name="dmarc-enforcing",
            kind="forbid",
            subject="email.dmarc_policy",
            expected="none",
            severity="HIGH",
            description="DMARC should quarantine or reject failing mail",
            reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
        ),
        Expectation(
            name="dmarc-reporting",
            kind="min",
            subject="email.dmarc_rua",
            expected=1,
            severity="LOW",
            description="DMARC should collect aggregate reports",
            reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.2",
        ),
        Expectation(
            name="no-dangling-records",
            kind="max",
            subject="dangling",
            expected=0,
            severity="HIGH",
            description="no hostname should point at a resource that no longer resolves",
        ),
        Expectation(
            name="caa-published",
            kind="min",
            subject="email.caa_issuers",
            expected=1,
            severity="MEDIUM",
            description="a CAA record should restrict which CAs may issue",
            reference="https://datatracker.ietf.org/doc/html/rfc8659",
        ),
    ]


__all__ = [
    "VIOLATION_SEVERITIES",
    "Baseline",
    "BaselineManager",
    "Expectation",
    "Violation",
    "common_expectations",
]

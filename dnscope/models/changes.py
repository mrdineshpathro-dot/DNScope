"""Change records, significance classification and the event timeline."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import SchemaVersioned, Significance, SourceRecord
from dnscope.utils.time_utils import utc_now_iso


class ChangeType:
    """Kinds of change DNScope detects."""

    A_CHANGED = "A_CHANGED"
    AAAA_CHANGED = "AAAA_CHANGED"
    CNAME_CHANGED = "CNAME_CHANGED"
    MX_CHANGED = "MX_CHANGED"
    NS_CHANGED = "NS_CHANGED"
    TXT_CHANGED = "TXT_CHANGED"
    CAA_CHANGED = "CAA_CHANGED"
    SOA_CHANGED = "SOA_CHANGED"
    DNSSEC_CHANGED = "DNSSEC_CHANGED"
    TTL_CHANGED = "TTL_CHANGED"
    #: Record types without a dedicated change type (SRV, NAPTR, TLSA, SSHFP...).
    RECORD_CHANGED = "RECORD_CHANGED"
    #: Mail-authentication policy changes, tracked separately from generic TXT so
    #: a weakened SPF or DMARC policy is never rated as an ordinary text edit.
    SPF_CHANGED = "SPF_CHANGED"
    DMARC_CHANGED = "DMARC_CHANGED"
    DKIM_CHANGED = "DKIM_CHANGED"
    #: MTA-STS / TLS-RPT.
    TRANSPORT_POLICY_CHANGED = "TRANSPORT_POLICY_CHANGED"
    CERTIFICATE_ADDED = "CERTIFICATE_ADDED"
    CERTIFICATE_REMOVED = "CERTIFICATE_REMOVED"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    CERTIFICATE_ISSUER_CHANGED = "CERTIFICATE_ISSUER_CHANGED"
    CERTIFICATE_REPLACED = "CERTIFICATE_REPLACED"
    SAN_CHANGED = "SAN_CHANGED"
    KEY_ALGORITHM_CHANGED = "KEY_ALGORITHM_CHANGED"
    ASN_CHANGED = "ASN_CHANGED"
    IP_ADDED = "IP_ADDED"
    IP_REMOVED = "IP_REMOVED"
    CLOUD_PROVIDER_CHANGED = "CLOUD_PROVIDER_CHANGED"
    SUBDOMAIN_ADDED = "SUBDOMAIN_ADDED"
    SUBDOMAIN_REMOVED = "SUBDOMAIN_REMOVED"
    SUBDOMAIN_STATE_CHANGED = "SUBDOMAIN_STATE_CHANGED"
    DANGLING_DETECTED = "DANGLING_DETECTED"
    REGISTRAR_CHANGED = "REGISTRAR_CHANGED"
    EXPIRATION_CHANGED = "EXPIRATION_CHANGED"
    POLICY_CHANGED = "POLICY_CHANGED"
    HEALTH_SCORE_CHANGED = "HEALTH_SCORE_CHANGED"

    ALL = (
        A_CHANGED,
        AAAA_CHANGED,
        CNAME_CHANGED,
        MX_CHANGED,
        NS_CHANGED,
        TXT_CHANGED,
        CAA_CHANGED,
        SOA_CHANGED,
        DNSSEC_CHANGED,
        TTL_CHANGED,
        RECORD_CHANGED,
        SPF_CHANGED,
        DMARC_CHANGED,
        DKIM_CHANGED,
        TRANSPORT_POLICY_CHANGED,
        CERTIFICATE_ADDED,
        CERTIFICATE_REMOVED,
        CERTIFICATE_EXPIRED,
        CERTIFICATE_ISSUER_CHANGED,
        CERTIFICATE_REPLACED,
        SAN_CHANGED,
        KEY_ALGORITHM_CHANGED,
        ASN_CHANGED,
        IP_ADDED,
        IP_REMOVED,
        CLOUD_PROVIDER_CHANGED,
        SUBDOMAIN_ADDED,
        SUBDOMAIN_REMOVED,
        SUBDOMAIN_STATE_CHANGED,
        DANGLING_DETECTED,
        REGISTRAR_CHANGED,
        EXPIRATION_CHANGED,
        POLICY_CHANGED,
        HEALTH_SCORE_CHANGED,
    )

    #: Changes that affect name resolution.
    RESOLUTION = (A_CHANGED, AAAA_CHANGED, CNAME_CHANGED, MX_CHANGED, NS_CHANGED, SOA_CHANGED)

    #: Changes affecting security posture.
    SECURITY = (
        DNSSEC_CHANGED,
        CAA_CHANGED,
        CERTIFICATE_EXPIRED,
        DANGLING_DETECTED,
        SPF_CHANGED,
        DMARC_CHANGED,
        DKIM_CHANGED,
        TRANSPORT_POLICY_CHANGED,
    )

    #: Changes considered informational by default.
    INFORMATIONAL = (TTL_CHANGED, HEALTH_SCORE_CHANGED)


class ChangeRecord(SchemaVersioned):
    """A single detected change between two observations."""

    change_id: str = ""
    change_type: str
    target: str
    workspace: str = "default"
    #: Where the change occurred (hostname, record type, cert serial...).
    field: str = ""
    previous: Any = None
    current: Any = None
    detected_at: str = Field(default_factory=utc_now_iso)
    #: Significance assigned by the significance engine.
    significance: str = Significance.LOW.value
    #: Why the change was classified this way (explainability).
    reason: str = ""
    #: ``True`` when the previous value was never observed (first sighting).
    first_observation: bool = False
    source: SourceRecord = Field(default_factory=SourceRecord)
    #: Optional snapshot identifiers the change was derived from.
    from_snapshot: str = ""
    to_snapshot: str = ""
    #: Machine-readable context (network distance, counts...).
    context: dict[str, Any] = Field(default_factory=dict)
    alert_sent: bool = False
    acknowledged: bool = False

    @field_validator("significance", mode="before")
    @classmethod
    def _coerce(cls, value: Any) -> Any:
        if isinstance(value, Significance):
            return value.value
        text = str(value).strip().upper()
        for member in Significance:
            if member.value == text:
                return text
        return Significance.LOW.value

    @property
    def significance_level(self) -> Significance:
        """Typed significance."""
        return Significance.coerce(self.significance)

    @property
    def is_significant(self) -> bool:
        """``True`` for MEDIUM and above (the default alert threshold)."""
        return self.significance_level.rank >= Significance.MEDIUM.rank

    def describe(self) -> str:
        """Human-readable one-liner."""
        return f"{self.change_type} on {self.target}" + (f" [{self.field}]" if self.field else "")

    def summary_line(self) -> str:
        """Timeline-style summary with values."""
        previous = _compact(self.previous)
        current = _compact(self.current)
        if previous and current:
            return f"{self.change_type}: {previous} -> {current}"
        if current:
            return f"{self.change_type}: {current}"
        if previous:
            return f"{self.change_type}: {previous} -> (removed)"
        return self.change_type


def _compact(value: Any, *, max_length: int = 80) -> str:
    """Compact rendering of a change value."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        text = ", ".join(str(item) for item in sorted(value, key=str))
    elif isinstance(value, dict):
        text = ", ".join(f"{k}={v}" for k, v in sorted(value.items()))
    else:
        text = str(value)
    return text if len(text) <= max_length else text[: max_length - 1] + "..."


class EventTimelineEntry(SchemaVersioned):
    """One row of the exported event timeline."""

    timestamp: str
    event: str
    target: str
    detail: str = ""
    significance: str = Significance.LOW.value
    category: str = ""
    source: str = ""

    def to_csv_row(self) -> dict[str, str]:
        """Flat dictionary for CSV export."""
        return {
            "timestamp": self.timestamp,
            "event": self.event,
            "target": self.target,
            "detail": self.detail,
            "significance": self.significance,
            "category": self.category,
            "source": self.source,
        }


class TimelineReport(SchemaVersioned):
    """Ordered timeline for a target, ready for JSON/CSV/MD/HTML export."""

    target: str
    workspace: str = "default"
    entries: list[EventTimelineEntry] = Field(default_factory=list)
    generated_at: str = Field(default_factory=utc_now_iso)
    period_start: str | None = None
    period_end: str | None = None

    def sorted_entries(self) -> list[EventTimelineEntry]:
        """Entries ordered oldest-first."""
        return sorted(self.entries, key=lambda entry: entry.timestamp)

    def by_significance(self, minimum: Significance = Significance.TRIVIAL) -> list[EventTimelineEntry]:
        """Entries at or above ``minimum`` significance."""
        return [
            entry
            for entry in self.sorted_entries()
            if Significance.coerce(entry.significance).rank >= minimum.rank
        ]

    def add(
        self,
        event: str,
        target: str,
        *,
        detail: str = "",
        significance: str = Significance.LOW.value,
        timestamp: str | None = None,
        category: str = "",
        source: str = "",
    ) -> EventTimelineEntry:
        """Append an entry and return it."""
        entry = EventTimelineEntry(
            timestamp=timestamp or utc_now_iso(),
            event=event,
            target=target,
            detail=detail,
            significance=significance,
            category=category,
            source=source,
        )
        self.entries.append(entry)
        return entry

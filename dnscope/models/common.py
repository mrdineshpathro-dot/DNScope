"""Common building blocks shared by every DNScope model.

The central idea is that *nothing* is asserted without provenance: every
observation carries a :class:`SourceRecord` (who told us, when, how much to
trust it) and every finding carries :class:`Evidence` (the query and response
that produced it).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from dnscope.constants import PRODUCT_VERSION, SCHEMA_VERSION
from dnscope.utils.time_utils import parse_timestamp, utc_now_iso


class StrEnum(str, Enum):
    """String enum base that serializes to its value."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @classmethod
    def values(cls) -> tuple[str, ...]:
        """All member values."""
        return tuple(member.value for member in cls)

    @classmethod
    def coerce(cls, value: Any) -> "StrEnum":
        """Case-insensitively convert ``value`` to a member."""
        if isinstance(value, cls):
            return value
        text = str(value).strip().upper()
        for member in cls:
            if member.value == text:
                return member
        raise ValueError(f"invalid {cls.__name__}: {value!r}")


class Confidence(StrEnum):
    """How much DNScope trusts a conclusion."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def weight(self) -> float:
        """Numeric weight used by scoring."""
        return {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, "UNKNOWN": 0.1}[self.value]


class Severity(StrEnum):
    """Finding severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Ordinal used for threshold comparisons."""
        return ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").index(self.value)

    def at_least(self, other: "Severity") -> bool:
        """Return ``True`` when this severity meets or exceeds ``other``."""
        return self.rank >= other.rank

    @property
    def sarif_level(self) -> str:
        """Map to a SARIF result level."""
        if self.value in ("CRITICAL", "HIGH"):
            return "error"
        if self.value == "MEDIUM":
            return "warning"
        if self.value == "LOW":
            return "note"
        return "none"

    @property
    def color(self) -> str:
        """Rich colour name for terminal output."""
        return {
            "INFO": "blue",
            "LOW": "cyan",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold white on red",
        }[self.value]


class Significance(StrEnum):
    """How much a *change* matters (not the same as severity)."""

    TRIVIAL = "TRIVIAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return ("TRIVIAL", "LOW", "MEDIUM", "HIGH", "CRITICAL").index(self.value)

    def at_least(self, other: "Significance") -> bool:
        return self.rank >= other.rank


class EvidenceQuality(StrEnum):
    """How the conclusion was derived - critical to avoid misleading claims."""

    #: Directly measured (e.g. a DNS answer we received).
    OBSERVED = "OBSERVED"
    #: Derived by rules from observations (e.g. cloud provider from CNAME).
    INFERRED = "INFERRED"
    #: Joined across two or more observations (e.g. shared certificate).
    CORRELATED = "CORRELATED"
    #: Best-effort guess with weak signal.
    HEURISTIC = "HEURISTIC"


class ScopeStatus(StrEnum):
    """Result of scope validation for a discovered asset."""

    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class SchemaVersioned(BaseModel):
    """Base model that stamps every payload with schema/tool versions."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True, use_enum_values=False)

    schema_version: str = SCHEMA_VERSION
    tool_version: str = PRODUCT_VERSION

    def to_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        """JSON-ready dictionary of this model."""
        return self.model_dump(mode="json", exclude_none=exclude_none, by_alias=True)

    def to_json(self, *, indent: int | None = None) -> str:
        """JSON text of this model."""
        import json

        return json.dumps(self.to_dict(), indent=indent, default=str)


class SourceRecord(SchemaVersioned):
    """Provenance for a single external observation.

    ``provider`` names the system (``crt.sh``), ``source`` the endpoint or
    dataset (``https://crt.sh/?q=...``). Both are required for intelligence
    data so results are never mixed without attribution.
    """

    provider: str = "dnscope"
    source: str = ""
    observed_at: datetime = Field(default_factory=lambda: parse_timestamp(utc_now_iso()) or datetime.now())
    confidence: Confidence = Confidence.UNKNOWN
    quality: EvidenceQuality = EvidenceQuality.OBSERVED
    request_id: str = ""

    @field_validator("observed_at", mode="before")
    @classmethod
    def _parse_time(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value


class Evidence(SchemaVersioned):
    """The observable basis for a finding.

    A finding without evidence is not produced by DNScope: the rule engine
    rejects it. ``response`` holds the normalized answer text, ``raw`` an
    optional (already redacted) excerpt for human verification.
    """

    query: str = ""
    response: str = ""
    record_type: str = ""
    observed_at: datetime = Field(default_factory=lambda: parse_timestamp(utc_now_iso()) or datetime.now())
    source: SourceRecord = Field(default_factory=SourceRecord)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at", mode="before")
    @classmethod
    def _parse_time(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    def summary(self, *, max_length: int = 120) -> str:
        """Single-line evidence description used in reports."""
        text = f"{self.query} -> {self.response}".strip(" ->")
        return text if len(text) <= max_length else text[: max_length - 1] + "..."

    def describe(self) -> str:
        """Multi-line evidence block for terminal output."""
        lines = [f"query     : {self.query or 'n/a'}", f"response  : {self.response or 'n/a'}"]
        if self.record_type:
            lines.append(f"type      : {self.record_type}")
        if self.source.provider != "dnscope" or self.source.source:
            lines.append(f"source    : {self.source.provider} / {self.source.source or 'local'}")
        lines.append(f"quality   : {self.source.quality.value}")
        lines.append(f"observed  : {self.observed_at.isoformat()}")
        return "\n".join(lines)


class Observation(SchemaVersioned):
    """Anything DNScope records about the world, with lifetime tracking.

    ``first_seen``/``last_seen`` are populated by the storage layer so history
    queries can reconstruct infrastructure as it existed at a point in time.
    """

    workspace: str = "default"
    target: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    observed_at: datetime = Field(default_factory=lambda: parse_timestamp(utc_now_iso()) or datetime.now())
    source: SourceRecord = Field(default_factory=SourceRecord)
    scope_status: ScopeStatus = ScopeStatus.UNKNOWN
    notes: str = ""

    @field_validator("first_seen", "last_seen", "observed_at", mode="before")
    @classmethod
    def _parse_times(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @property
    def age_days(self) -> float | None:
        """Days since the last observation (``None`` when never seen)."""
        if self.last_seen is None:
            return None
        from dnscope.utils.time_utils import now_utc

        return max(0.0, (now_utc() - self.last_seen).total_seconds() / 86400.0)

    def touch(self, when: datetime | None = None) -> None:
        """Update lifetime markers for a new observation."""
        from dnscope.utils.time_utils import now_utc

        moment = when or now_utc()
        self.observed_at = moment
        if self.first_seen is None or moment < self.first_seen:
            self.first_seen = moment
        if self.last_seen is None or moment > self.last_seen:
            self.last_seen = moment


class ErrorRecord(SchemaVersioned):
    """A non-fatal error captured during a scan.

    Errors are part of the result payload rather than exceptions so partial
    results stay usable and reports show what could not be checked.
    """

    stage: str
    message: str
    detail: str = ""
    target: str = ""
    provider: str = ""
    recoverable: bool = True
    occurred_at: datetime = Field(default_factory=lambda: parse_timestamp(utc_now_iso()) or datetime.now())

    @field_validator("occurred_at", mode="before")
    @classmethod
    def _parse_time(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    def to_line(self) -> str:
        """Compact single-line rendering."""
        prefix = f"[{self.stage}]"
        suffix = f" ({self.provider})" if self.provider else ""
        return f"{prefix} {self.message}{suffix}: {self.detail}".rstrip(": ")

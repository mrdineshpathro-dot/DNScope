"""Finding model: an evidence-backed, lifecycle-tracked security observation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import Confidence, Evidence, SchemaVersioned, Severity
from dnscope.utils.time_utils import parse_timestamp, utc_now_iso


class FindingStatus:
    """Finding lifecycle states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    SUPPRESSED = "SUPPRESSED"

    ALL = (OPEN, ACKNOWLEDGED, RESOLVED, REOPENED, SUPPRESSED)
    ACTIVE = (OPEN, REOPENED)


class RuleReference(SchemaVersioned):
    """Pointer to a rule definition (built-in or plugin supplied)."""

    rule_id: str
    title: str = ""
    category: str = ""
    source: str = "builtin"  # builtin | yaml | plugin
    version: str = ""
    references: list[str] = Field(default_factory=list)


class FindingSuppression(SchemaVersioned):
    """Record of a finding being suppressed or resolved by an operator."""

    finding_id: str
    reason: str
    user: str = ""
    suppressed_at: str = Field(default_factory=utc_now_iso)
    expires_at: str | None = None
    #: ``suppress`` keeps it out of reports; ``resolve`` marks it fixed.
    action: str = "suppress"

    @field_validator("expires_at", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        return value or None

    def is_expired(self, when: datetime | None = None) -> bool:
        """``True`` when the suppression window has elapsed."""
        if not self.expires_at:
            return False
        moment = parse_timestamp(self.expires_at)
        if moment is None:
            return False
        from dnscope.utils.time_utils import now_utc

        return moment < (when or now_utc())


class Finding(SchemaVersioned):
    """A single analysis result.

    Invariants enforced by :meth:`validate`:
      * at least one :class:`Evidence` entry with a non-empty query or response
      * severity/confidence from the canonical enums
      * a rule reference so consumers can look up the logic
    """

    finding_id: str
    rule: RuleReference
    title: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    target: str = ""
    workspace: str = "default"
    category: str = ""
    #: Where the issue lives (hostname, IP, record type...).
    location: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    status: str = FindingStatus.OPEN
    suppression: FindingSuppression | None = None
    first_seen: str | None = None
    last_seen: str = Field(default_factory=utc_now_iso)
    #: Free-form machine readable context (counts, values, thresholds).
    context: dict[str, Any] = Field(default_factory=dict)
    #: ``True`` when the conclusion needs more evidence before being trusted.
    needs_verification: bool = False
    #: Distinguishes rule-based output from AI interpretation.
    analysis_type: str = "RULE_BASED"  # RAW_OBSERVATION | RULE_BASED | AI_INTERPRETATION
    score_impact: float = 0.0

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: Any) -> Any:
        if isinstance(value, Severity):
            return value
        return Severity.coerce(value)

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> Any:
        if isinstance(value, Confidence):
            return value
        return Confidence.coerce(value)

    # ------------------------------------------------------------- validation

    def validation_problems(self) -> list[str]:
        """Return a list of reasons this finding is not reportable.

        The rule engine calls this before accepting a finding, which is how
        DNScope avoids publishing unsupported claims.
        """
        problems: list[str] = []
        if not self.finding_id:
            problems.append("finding_id is required")
        if not self.rule.rule_id:
            problems.append("rule id is required")
        if not self.title:
            problems.append("title is required")
        if not self.evidence:
            problems.append("finding has no evidence")
        elif not any(item.query or item.response or item.raw for item in self.evidence):
            problems.append("finding evidence is empty")
        if self.confidence is Confidence.LOW and not self.needs_verification:
            problems.append("low-confidence findings must be flagged needs_verification")
        return problems

    @property
    def is_valid(self) -> bool:
        """``True`` when :meth:`validate` reports no problems."""
        return not self.validation_problems()

    # ----------------------------------------------------------------- helpers

    @property
    def is_active(self) -> bool:
        """``True`` when the finding is neither resolved nor suppressed."""
        if self.status in (FindingStatus.RESOLVED, FindingStatus.SUPPRESSED):
            return False
        return not (self.suppression and not self.suppression.is_expired())

    @property
    def severity_rank(self) -> int:
        return self.severity.rank

    def evidence_text(self) -> str:
        """Concatenated evidence summaries for terminal/JSON reports."""
        return " | ".join(item.summary() for item in self.evidence[:5])

    def matches_severity(self, minimum: Severity) -> bool:
        """``True`` when this finding meets the ``minimum`` threshold."""
        return self.severity.at_least(minimum)

    def fingerprint(self) -> str:
        """Stable identity used to correlate the same finding across scans."""
        from dnscope.utils.hashing import blake2b_hex

        parts = [
            self.rule.rule_id,
            self.target.lower(),
            str(self.location.get("name", "")).lower(),
            str(self.location.get("value", "")).lower(),
        ]
        return blake2b_hex("\x1f".join(parts), size=16)

    def to_sarif_result(self) -> dict[str, Any]:
        """SARIF 2.1.0 result object for this finding."""
        location = self.location or {}
        artifact = str(location.get("name") or self.target or "")
        result: dict[str, Any] = {
            "ruleId": self.rule.rule_id,
            "level": self.severity.sarif_level,
            "message": {"text": self.title + (f" - {self.description}" if self.description else "")},
            "properties": {
                "confidence": self.confidence.value,
                "status": self.status,
                "evidence": [item.summary() for item in self.evidence],
            },
        }
        if artifact:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact, "uriBaseId": "DNS"},
                    },
                    "logicalLocations": [
                        {
                            "name": artifact,
                            "kind": str(location.get("kind", "dnsName")),
                            "fullyQualifiedName": self.target,
                        }
                    ],
                }
            ]
        if self.recommendation:
            result["fixes"] = [
                {
                    "description": {"text": self.recommendation},
                }
            ]
        return result

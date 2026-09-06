"""Alert models for the notification engine."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import SchemaVersioned
from dnscope.utils.time_utils import utc_now_iso


class AlertChannel:
    """Supported notification channels."""

    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"
    WEBHOOK = "webhook"
    TEAMS = "teams"
    STDOUT = "stdout"
    FILE = "file"

    ALL = (SLACK, DISCORD, TELEGRAM, EMAIL, WEBHOOK, TEAMS, STDOUT, FILE)
    #: Channels that talk to a remote HTTP endpoint (SSRF checks apply).
    REMOTE = (SLACK, DISCORD, TELEGRAM, WEBHOOK, TEAMS)


class AlertEventType:
    """Alert event types."""

    DNS_CHANGE = "DNS_CHANGE"
    CERTIFICATE_CHANGE = "CERTIFICATE_CHANGE"
    NS_CHANGE = "NS_CHANGE"
    MX_CHANGE = "MX_CHANGE"
    SECURITY_FINDING = "SECURITY_FINDING"
    TAKEOVER_INDICATOR = "TAKEOVER_INDICATOR"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"

    ALL = (
        DNS_CHANGE,
        CERTIFICATE_CHANGE,
        NS_CHANGE,
        MX_CHANGE,
        SECURITY_FINDING,
        TAKEOVER_INDICATOR,
        POLICY_VIOLATION,
        PROVIDER_FAILURE,
    )


class Alert(SchemaVersioned):
    """A notification DNScope wants to deliver."""

    alert_id: str
    event_type: str
    target: str = ""
    workspace: str = "default"
    title: str
    message: str
    severity: str = "INFO"
    significance: str = "LOW"
    #: Stable fingerprint used for de-duplication.
    fingerprint: str = ""
    created_at: str = Field(default_factory=utc_now_iso)
    context: dict[str, Any] = Field(default_factory=dict)
    #: Finding/change identifiers this alert summarises.
    references: list[str] = Field(default_factory=list)
    #: Channels the alert was requested on.
    channels: list[str] = Field(default_factory=list)
    suppressed: bool = False
    suppression_reason: str = ""

    @field_validator("event_type", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return str(value).upper() if isinstance(value, str) else value

    def to_payload(self) -> dict[str, Any]:
        """Redacted, transport-neutral payload for channel formatters."""
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type,
            "target": self.target,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "significance": self.significance,
            "created_at": self.created_at,
            "context": self.context,
        }


class AlertDelivery(SchemaVersioned):
    """Outcome of delivering one alert to one channel."""

    alert_id: str
    channel: str
    ok: bool = False
    status_code: int | None = None
    error: str = ""
    attempts: int = 1
    delivered_at: str = Field(default_factory=utc_now_iso)
    #: ``True`` when the payload was signed with HMAC.
    signed: bool = False

    def to_line(self) -> str:
        """One-line summary for CLI output."""
        state = "OK" if self.ok else "FAILED"
        detail = f" ({self.error})" if self.error else ""
        return f"{self.channel}: {state}{detail}"

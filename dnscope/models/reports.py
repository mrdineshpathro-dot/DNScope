"""Report metadata and scan reproducibility records."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from dnscope.constants import (
    AUTHOR,
    GITHUB_URL,
    PRODUCT_DESCRIPTION,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    SCHEMA_VERSION,
    YOUTUBE_URL,
)
from dnscope.models.common import SchemaVersioned
from dnscope.utils.time_utils import utc_now_iso


class ReportMetadata(SchemaVersioned):
    """Metadata block embedded in every generated report."""

    tool: str = PRODUCT_NAME
    tool_version: str = PRODUCT_VERSION
    description: str = PRODUCT_DESCRIPTION
    tagline: str = "DNS Intelligence, Clearly Scoped."
    author: str = AUTHOR
    github: str = GITHUB_URL
    youtube: str = YOUTUBE_URL
    generated_at: str = Field(default_factory=utc_now_iso)
    generated_by: str = ""
    profile: str = ""
    schema_version: str = SCHEMA_VERSION
    report_format: str = ""
    integrity_sha256: str = ""
    signed: bool = False
    signature_algorithm: str = ""

    def footer_html(self) -> str:
        """HTML footer used by the HTML report and dashboard."""
        return (
            f'<a href="{GITHUB_URL}">{PRODUCT_NAME} {PRODUCT_VERSION}</a> by {AUTHOR} &middot; '
            f'<a href="https://github.com/mrdineshpathro-dot">GitHub</a> &middot; '
            f'<a href="{YOUTUBE_URL}">YouTube</a>'
        )


class ScanReproducibility(SchemaVersioned):
    """Everything needed to explain how a scan was produced.

    Stored with each scan so a later analyst can tell which rules, resolver and
    providers were in play - without ever recording credentials.
    """

    scan_id: str
    tool_version: str = PRODUCT_VERSION
    schema_version: str = SCHEMA_VERSION
    profile: str = ""
    resolver: str = ""
    resolvers: list[str] = Field(default_factory=list)
    transport: str = ""
    providers: list[str] = Field(default_factory=list)
    ruleset_version: str = ""
    ruleset_hash: str = ""
    configuration_hash: str = ""
    #: Redacted copy of the effective configuration.
    configuration: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)
    started_at: str = Field(default_factory=utc_now_iso)
    finished_at: str = ""
    duration_ms: float = 0.0
    privacy_mode: bool = False
    offline_mode: bool = False
    ai_used: bool = False
    #: Command line invocation with secrets stripped.
    command: str = ""

    def to_summary(self) -> str:
        """Short human summary."""
        parts = [
            f"tool={self.tool_version}",
            f"schema={self.schema_version}",
            f"profile={self.profile or 'default'}",
            f"resolver={self.resolver or 'system'}",
        ]
        if self.ruleset_version:
            parts.append(f"rules={self.ruleset_version}")
        if self.configuration_hash:
            parts.append(f"config={self.configuration_hash[:12]}")
        return " ".join(parts)


class ReportBundle(SchemaVersioned):
    """Container for a generated report (content + metadata + integrity)."""

    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    format: str = "json"
    content: str = ""
    path: str = ""
    size_bytes: int = 0
    sha256: str = ""
    findings_count: int = 0
    changes_count: int = 0
    warnings: list[str] = Field(default_factory=list)

    def to_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data = super().to_dict(exclude_none=exclude_none)
        # Content can be megabytes; keep the summary payload small.
        if "content" in data and self.format != "json":
            data["content"] = f"<{self.format} document, {self.size_bytes} bytes>"
        return data

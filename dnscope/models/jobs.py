"""Job, schedule and monitoring-target models (SQLite backed)."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import SchemaVersioned
from dnscope.utils.time_utils import utc_now_iso


class JobState:
    """Background job lifecycle."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    ALL = (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED)
    ACTIVE = (QUEUED, RUNNING)
    TERMINAL = (COMPLETED, FAILED, CANCELLED)


class JobPriority:
    """Job priorities.

    Priority affects *ordering only* - it never bypasses global rate limits or
    safety ceilings, which are enforced downstream.
    """

    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"

    ALL = (LOW, NORMAL, HIGH)

    _WEIGHTS = {"LOW": 0, "NORMAL": 1, "HIGH": 2}

    @classmethod
    def weight(cls, value: str) -> int:
        """Ordering weight (higher runs first)."""
        return cls._WEIGHTS.get(str(value).upper(), 1)


class Job(SchemaVersioned):
    """A unit of background work (scan, monitor run, report...)."""

    job_id: str
    kind: str = "scan"  # scan | monitor | report | baseline | policy | export
    target: str = ""
    workspace: str = "default"
    state: str = JobState.QUEUED
    priority: str = JobPriority.NORMAL
    profile: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    attempts: int = 0
    max_attempts: int = 3
    timeout_seconds: int = 900
    error: str = ""
    progress: float = 0.0
    #: Set by the worker so a stuck job can be reclaimed.
    worker_id: str = ""
    lease_expires_at: str | None = None
    scan_id: str = ""

    @field_validator("state", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return str(value).upper() if isinstance(value, str) else value

    @property
    def is_active(self) -> bool:
        return self.state in JobState.ACTIVE

    @property
    def is_terminal(self) -> bool:
        return self.state in JobState.TERMINAL

    def can_retry(self) -> bool:
        """``True`` when another attempt is allowed."""
        return self.attempts < self.max_attempts and self.state != JobState.CANCELLED


class Schedule(SchemaVersioned):
    """A recurring monitoring or reporting schedule."""

    schedule_id: str
    target: str
    workspace: str = "default"
    kind: str = "monitor"  # monitor | report | baseline | policy | scan
    interval_seconds: int = 3600
    profile: str = ""
    enabled: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=utc_now_iso)
    last_run_at: str | None = None
    next_run_at: str | None = None
    last_status: str = ""
    run_count: int = 0
    consecutive_failures: int = 0
    #: Report format when ``kind == "report"``.
    report_format: str = ""
    #: Alert channels used when the schedule produces changes.
    alert_channels: list[str] = Field(default_factory=list)

    @field_validator("interval_seconds", mode="before")
    @classmethod
    def _int(cls, value: Any) -> Any:
        return int(value)

    @property
    def interval_label(self) -> str:
        """Human friendly interval (``1h``, ``15m``...)."""
        from dnscope.utils.time_utils import format_duration

        return format_duration(self.interval_seconds, compact=False)


class MonitorJob(SchemaVersioned):
    """Monitoring target configuration (``dnscope monitor``)."""

    job_id: str
    target: str
    workspace: str = "default"
    profile: str = "standard"
    interval_seconds: int = 3600
    enabled: bool = True
    last_run: str | None = None
    next_run: str | None = None
    status: str = "IDLE"
    created_at: str = Field(default_factory=utc_now_iso)
    run_count: int = 0
    last_changes: int = 0
    alert_channels: list[str] = Field(default_factory=list)
    #: Minimum significance that triggers an alert.
    min_significance: str = "MEDIUM"
    error: str = ""

    @property
    def interval_label(self) -> str:
        from dnscope.utils.time_utils import format_duration

        return format_duration(self.interval_seconds, compact=False)


class CheckpointState(SchemaVersioned):
    """Bulk-run checkpoint used by ``dnscope bulk --resume``."""

    bulk_id: str
    source_file: str = ""
    total: int = 0
    completed: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    started_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    output: str = ""

    @property
    def remaining(self) -> int:
        """Targets not yet processed."""
        return max(0, self.total - len(self.completed) - len(self.failed) - len(self.skipped))

    @property
    def progress(self) -> float:
        """Completion fraction (0..1)."""
        if not self.total:
            return 0.0
        done = len(self.completed) + len(self.failed) + len(self.skipped)
        return round(min(1.0, done / self.total), 4)

    def is_done(self, target: str) -> bool:
        """``True`` when ``target`` was already processed."""
        return target in self.completed or target in self.failed or target in self.skipped

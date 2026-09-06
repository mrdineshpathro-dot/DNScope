"""Monitoring schedules.

A schedule is a recurring job; a monitor is the recurring comparison of one
target against its own history. Both live in the database so a run survives a
restart and several workers can share one queue.

Two guardrails are enforced here rather than left to the caller:

* an interval below :data:`MIN_MONITOR_INTERVAL` is rejected with an explanation
  - querying a third-party resolver in a tight loop is how a scanner gets blocked
* a schedule that has never run gets ``next_run_at`` immediately, while one that
  just ran is pushed a full interval ahead, so a restart cannot cause a stampede
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any

from pydantic import BaseModel

from dnscope.constants import MIN_MONITOR_INTERVAL
from dnscope.exceptions import ConfigurationError
from dnscope.models.jobs import JobPriority, MonitorJob, Schedule
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.ids import new_id
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import (
    now_utc,
    parse_interval,
    parse_timestamp,
    utc_iso,
    utc_now_iso,
)

_log = get_logger("monitoring.scheduler")

#: Human names for the interval presets accepted by the CLI.
INTERVAL_PRESETS = {
    "5m": 300,
    "15m": 900,
    "30m": 1800,
    "1h": 3600,
    "6h": 21600,
    "12h": 43200,
    "24h": 86400,
}

#: Back-off applied after repeated failures, in multiples of the interval. The
#: first entry is the multiplier for the *first* failure, so a target that starts
#: failing is not retried at full rate.
FAILURE_BACKOFF = (2, 4, 8, 16)


class ScheduleCheck(BaseModel):
    """Result of validating a requested interval."""

    requested: str = ""
    requested_seconds: int = 0
    accepted_seconds: int = 0
    ok: bool = True
    reason: str = ""

    def summary(self) -> str:
        """One-line human description."""
        if self.ok and self.accepted_seconds == self.requested_seconds:
            return f"interval {self.accepted_seconds}s accepted"
        return f"interval {self.requested} -> {self.accepted_seconds}s ({self.reason})"


def validate_interval(interval: str | int) -> ScheduleCheck:
    """Validate and normalize a monitoring interval.

    Accepts ``3600``, ``"1h"``, ``"30m"`` or a preset name. Anything below the
    safe minimum is raised to it, and the caller is told why.
    """
    check = ScheduleCheck(requested=str(interval))
    seconds = parse_interval(interval)
    if seconds <= 0:
        raise ConfigurationError(f"invalid monitoring interval: {interval!r}")
    check.requested_seconds = seconds
    if seconds < MIN_MONITOR_INTERVAL:
        check.accepted_seconds = MIN_MONITOR_INTERVAL
        check.ok = False
        check.reason = (
            f"the minimum safe interval is {MIN_MONITOR_INTERVAL}s; shorter intervals "
            "hammer the resolver and risk being rate-limited or blocked"
        )
    else:
        check.accepted_seconds = seconds
    return check


def next_run_after(
    interval_seconds: int,
    *,
    from_time: Any = None,
    consecutive_failures: int = 0,
) -> str:
    """Compute the next run time, backing off after repeated failures.

    The result uses the same ``Z``-suffixed format as every other timestamp
    DNScope stores, so lexicographic ordering in SQL matches chronological
    ordering.
    """
    base = now_utc() if from_time is None else from_time
    multiplier = 1
    if consecutive_failures > 0:
        index = min(consecutive_failures, len(FAILURE_BACKOFF)) - 1
        multiplier = FAILURE_BACKOFF[index]
    return utc_iso(base + timedelta(seconds=interval_seconds * multiplier))


class Scheduler:
    """Creates and drives monitoring schedules on top of the database."""

    def __init__(self, database: Any, *, workspace: str = "default") -> None:
        self.db = database
        self.workspace = workspace

    # ----------------------------------------------------------------- monitors

    def add_monitor(
        self,
        target: str,
        *,
        interval: str | int = "1h",
        profile: str = "standard",
        min_significance: str = "MEDIUM",
        alert_channels: Sequence[str] = (),
        enabled: bool = True,
        job_id: str = "",
    ) -> MonitorJob:
        """Create a recurring monitor for one target."""
        check = validate_interval(interval)
        if not check.ok:
            _log.warning("monitor interval adjusted: %s", check.reason)
        name = normalize_hostname(target)
        if not name:
            raise ConfigurationError(f"invalid monitor target: {target!r}")
        identifier = job_id or new_id("mon")
        job = MonitorJob(
            job_id=identifier,
            target=name,
            workspace=self.workspace,
            profile=profile,
            interval_seconds=check.accepted_seconds,
            enabled=enabled,
            min_significance=min_significance,
            alert_channels=[str(item) for item in alert_channels],
            next_run=utc_now_iso() if enabled else None,
        )
        self.db.upsert_monitor(
            identifier,
            name,
            profile=profile,
            interval_seconds=check.accepted_seconds,
            enabled=enabled,
            min_significance=min_significance,
            alert_channels=job.alert_channels,
            next_run=job.next_run,
        )
        return job

    def list_monitors(self, *, enabled_only: bool = False) -> list[MonitorJob]:
        """Stored monitors as models."""
        return [
            MonitorJob.model_validate({**row, "alert_channels": row.get("alert_channels") or []})
            for row in self.db.list_monitors(enabled_only=enabled_only)
        ]

    def remove_monitor(self, job_id: str) -> bool:
        """Delete a monitor."""
        return bool(self.db.delete_monitor(job_id))

    def set_monitor_enabled(self, job_id: str, enabled: bool) -> bool:
        """Enable or disable a monitor without deleting it."""
        monitors = {item.job_id: item for item in self.list_monitors()}
        monitor = monitors.get(job_id)
        if monitor is None:
            return False
        monitor.enabled = enabled
        monitor.next_run = utc_now_iso() if enabled else None
        self.db.upsert_monitor(
            job_id,
            monitor.target,
            profile=monitor.profile,
            interval_seconds=monitor.interval_seconds,
            enabled=enabled,
            min_significance=monitor.min_significance,
            alert_channels=monitor.alert_channels,
            next_run=monitor.next_run,
        )
        return True

    def due_monitors(self, *, now: Any = None) -> list[MonitorJob]:
        """Monitors whose next run is at or before ``now``."""
        moment = now or now_utc()
        found: list[MonitorJob] = []
        for monitor in self.list_monitors(enabled_only=True):
            if monitor.next_run is None:
                found.append(monitor)
                continue
            scheduled = parse_timestamp(monitor.next_run)
            if scheduled is None or scheduled <= moment:
                found.append(monitor)
        return found

    def mark_monitor_run(
        self,
        job_id: str,
        *,
        status: str,
        changes: int | None = None,
        error: str = "",
    ) -> None:
        """Record a monitor run and schedule the next one.

        Consecutive failures accumulate so the back-off keeps growing while a
        target stays unreachable, and reset on the first success.
        """
        monitors = {item.job_id: item for item in self.list_monitors()}
        monitor = monitors.get(job_id)
        interval = monitor.interval_seconds if monitor else 3600
        previous_failed = str(monitor.status).upper() == "FAILED" if monitor else False
        if status.upper() == "FAILED":
            failures = self._failure_streak(job_id) + 1
        else:
            failures = 0
        self.db.update_monitor_run(
            job_id,
            status=status.upper(),
            last_run=utc_now_iso(),
            next_run=next_run_after(interval, consecutive_failures=failures),
            last_changes=changes,
            error=error,
        )
        if status.upper() == "FAILED":
            self.db.audit("monitor_failed", "monitor", job_id, {"error": error, "streak": failures})
        elif previous_failed:
            self.db.audit("monitor_recovered", "monitor", job_id, {"streak": 0})
        if previous_failed and failures == 0:
            _log.info("monitor %s recovered after a failure streak", job_id)

    def _failure_streak(self, job_id: str) -> int:
        """How many times this monitor has failed in a row.

        The monitors table stores only the latest status, so the streak is
        rebuilt from the run history that the database does keep.
        """
        rows = self.db.query(
            "SELECT COUNT(*) AS count FROM audit_log "
            "WHERE workspace = ? AND action = 'monitor_failed' AND object_id = ? "
            "AND created_at > COALESCE((SELECT MAX(created_at) FROM audit_log "
            "  WHERE workspace = ? AND action = 'monitor_recovered' AND object_id = ?), '')",
            (self.workspace, job_id, self.workspace, job_id),
        )
        return int(rows[0]["count"]) if rows else 0

    # ---------------------------------------------------------------- schedules

    def add_schedule(
        self,
        target: str,
        *,
        kind: str = "monitor",
        interval: str | int = "1h",
        profile: str = "",
        report_format: str = "",
        alert_channels: Sequence[str] = (),
        enabled: bool = True,
        payload: Mapping[str, Any] | None = None,
        schedule_id: str = "",
    ) -> Schedule:
        """Create a recurring schedule of any kind."""
        check = validate_interval(interval)
        if not check.ok:
            _log.warning("schedule interval adjusted: %s", check.reason)
        name = normalize_hostname(target) or str(target)
        identifier = schedule_id or new_id("sched")
        schedule = Schedule(
            schedule_id=identifier,
            target=name,
            workspace=self.workspace,
            kind=kind,
            interval_seconds=check.accepted_seconds,
            profile=profile,
            report_format=report_format,
            alert_channels=[str(item) for item in alert_channels],
            enabled=enabled,
            payload=dict(payload or {}),
            next_run_at=utc_now_iso() if enabled else None,
        )
        self.db.upsert_schedule(
            identifier,
            name,
            kind=kind,
            interval_seconds=check.accepted_seconds,
            profile=profile,
            report_format=report_format,
            alert_channels=schedule.alert_channels,
            enabled=enabled,
            payload=schedule.payload,
            next_run=schedule.next_run_at,
        )
        return schedule

    def list_schedules(self, *, due_only: bool = False) -> list[Schedule]:
        """Stored schedules as models."""
        found: list[Schedule] = []
        for row in self.db.list_schedules(due_only=due_only):
            data = dict(row)
            data["alert_channels"] = data.get("alert_channels") or []
            data["payload"] = data.get("payload") or {}
            found.append(Schedule.model_validate(data))
        return found

    def remove_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        return bool(self.db.delete_schedule(schedule_id))

    def due_schedules(self, *, now: Any = None) -> list[Schedule]:
        """Schedules whose next run is at or before ``now``."""
        return self.list_schedules(due_only=True)

    def mark_schedule_run(self, schedule_id: str, *, status: str) -> None:
        """Record a schedule run and compute the next one."""
        schedules = {item.schedule_id: item for item in self.list_schedules()}
        schedule = schedules.get(schedule_id)
        if schedule is None:
            return
        failures = schedule.consecutive_failures + (0 if status.upper() == "COMPLETED" else 1)
        self.db.update_schedule_run(
            schedule_id,
            status=status.upper(),
            next_run=next_run_after(schedule.interval_seconds, consecutive_failures=failures),
        )

    # -------------------------------------------------------------------- queue

    def enqueue(
        self,
        target: str,
        *,
        kind: str = "scan",
        priority: str = JobPriority.NORMAL,
        profile: str = "",
        payload: Mapping[str, Any] | None = None,
        timeout_seconds: int = 900,
    ) -> str:
        """Add a one-off job to the queue."""
        identifier = new_id("job")
        self.db.enqueue_job(
            identifier,
            kind=kind,
            target=normalize_hostname(target) or str(target),
            priority=priority,
            profile=profile,
            payload=dict(payload or {}),
            timeout_seconds=timeout_seconds,
        )
        return identifier

    def claim(self, worker_id: str, *, lease_seconds: int = 900) -> dict[str, Any] | None:
        """Claim the next queued job for a worker."""
        return self.db.claim_job(worker_id, lease_seconds=lease_seconds)

    def complete(self, job_id: str, result: Mapping[str, Any] | None = None, *, scan_id: str = "") -> None:
        """Mark a job complete."""
        self.db.complete_job(job_id, dict(result or {}), scan_id=scan_id)

    def fail(self, job_id: str, error: str) -> None:
        """Mark a job failed (the store requeues it while attempts remain)."""
        self.db.fail_job(job_id, error)

    def cancel(self, job_id: str) -> bool:
        """Cancel a queued or running job."""
        return bool(self.db.cancel_job(job_id))

    def stats(self) -> dict[str, Any]:
        """Queue and schedule counters for ``dnscope monitor status``."""
        monitors = self.list_monitors()
        schedules = self.list_schedules()
        return {
            "jobs": self.db.job_stats(),
            "monitors": len(monitors),
            "monitors_enabled": sum(1 for item in monitors if item.enabled),
            "monitors_due": len(self.due_monitors()),
            "schedules": len(schedules),
            "schedules_due": len(self.due_schedules()),
            "min_interval_seconds": MIN_MONITOR_INTERVAL,
        }

    def describe(self) -> dict[str, Any]:
        """Full inventory for ``dnscope monitor list --json``."""
        return {
            "monitors": [item.model_dump(mode="json") for item in self.list_monitors()],
            "schedules": [item.model_dump(mode="json") for item in self.list_schedules()],
            "stats": self.stats(),
        }


__all__ = [
    "FAILURE_BACKOFF",
    "INTERVAL_PRESETS",
    "ScheduleCheck",
    "Scheduler",
    "next_run_after",
    "validate_interval",
]

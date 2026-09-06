"""Validation and de-duplication for discovered hostnames.

Discovery sources are noisy: they return wildcard artifacts, uppercase
duplicates, names that belong to other organizations and outright garbage. This
module is the filter that keeps the rest of DNScope honest.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from dnscope.core.scope import Scope
from dnscope.utils.domains import (
    is_ip_literal,
    normalize_hostname,
    registered_domain,
    valid_hostname,
)

#: Labels that are almost always artifacts.
_ARTIFACT_LABELS = re.compile(
    r"^(?:\*|_|wpad|localhost|test\d*|asdf|random\w*|dnscope-wc-\d+-[0-9a-f]+)$",
    re.IGNORECASE,
)


class ValidationResult(BaseModel):
    """Outcome of validating one candidate hostname."""

    hostname: str = ""
    valid: bool = False
    reason: str = ""
    normalized: str = ""
    in_scope: bool = False
    is_artifact: bool = False
    is_wildcard: bool = False


class ValidationSummary(BaseModel):
    """Aggregate counters for a validation pass."""

    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    invalid: int = 0
    out_of_scope: int = 0
    artifacts: int = 0
    wildcard_matches: int = 0
    reasons: dict[str, int] = Field(default_factory=dict)

    def record(self, result: ValidationResult, *, duplicate: bool = False) -> None:
        """Count one validation outcome."""
        self.received += 1
        if duplicate:
            self.duplicates += 1
        if not result.valid:
            if not result.in_scope:
                self.out_of_scope += 1
            elif result.is_artifact:
                self.artifacts += 1
            else:
                self.invalid += 1
            key = result.reason or "unknown"
            self.reasons[key] = self.reasons.get(key, 0) + 1
            return
        self.accepted += 1

    def record_invalid_overflow(self, count: int) -> None:
        """Record candidates dropped because the result cap was reached."""
        if count <= 0:
            return
        self.received += count
        self.invalid += count
        key = "result limit reached"
        self.reasons[key] = self.reasons.get(key, 0) + count

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready summary."""
        return {
            "received": self.received,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "invalid": self.invalid,
            "out_of_scope": self.out_of_scope,
            "artifacts": self.artifacts,
            "wildcard_matches": self.wildcard_matches,
            "reasons": dict(sorted(self.reasons.items(), key=lambda item: -item[1])),
        }


class HostValidator:
    """Validates, normalizes and de-duplicates discovered hostnames."""

    def __init__(
        self,
        scope: Scope | None = None,
        *,
        allow_ip: bool = False,
        max_length: int = 253,
        wildcard_addresses: Iterable[str] = (),
    ) -> None:
        self.scope = scope
        self.allow_ip = allow_ip
        self.max_length = max_length
        self.wildcard_addresses = {str(item) for item in wildcard_addresses}
        self.seen: set[str] = set()
        self.summary = ValidationSummary()

    # ------------------------------------------------------------------ public

    def validate(self, candidate: str) -> ValidationResult:
        """Validate one candidate hostname."""
        result = ValidationResult()
        raw = (candidate or "").strip()
        if not raw:
            result.reason = "empty hostname"
            return result
        is_wildcard = raw.startswith("*.")
        result.is_wildcard = is_wildcard
        normalized = normalize_hostname(raw[2:] if is_wildcard else raw)
        result.normalized = normalized
        result.hostname = raw

        if not normalized:
            result.reason = "empty after normalization"
            return result
        if len(normalized) > self.max_length:
            result.reason = "hostname too long"
            return result
        if is_ip_literal(normalized):
            if not self.allow_ip:
                result.reason = "IP literal is not a hostname"
                return result
            result.valid = True
            result.in_scope = True
            return result
        if not valid_hostname(normalized):
            result.reason = "invalid hostname syntax"
            return result
        if self._is_artifact(normalized):
            result.is_artifact = True
            result.reason = "wildcard/probe artifact"
            return result
        if not registered_domain(normalized):
            result.reason = "no registrable domain"
            return result
        if self.scope is not None:
            decision = self.scope.check(normalized, record=False)
            result.in_scope = decision.in_scope
            if not decision.in_scope:
                result.reason = f"out of scope ({decision.reason})"
                return result
        result.valid = True
        result.in_scope = True
        return result

    def process(self, candidates: Iterable[str]) -> list[str]:
        """Validate and de-duplicate a batch, returning accepted hostnames."""
        accepted: list[str] = []
        for candidate in candidates:
            result = self.validate(candidate)
            duplicate = result.valid and result.normalized in self.seen
            self.summary.record(result, duplicate=duplicate)
            if result.valid and not duplicate:
                self.seen.add(result.normalized)
                accepted.append(result.normalized)
        return accepted

    def filter_wildcard_matches(self, hostnames: Iterable[str], resolved: dict[str, set[str]]) -> list[str]:
        """Drop hosts whose addresses exactly match the zone's wildcard set."""
        if not self.wildcard_addresses:
            return list(hostnames)
        kept: list[str] = []
        for hostname in hostnames:
            addresses = resolved.get(hostname, set())
            if addresses and addresses == self.wildcard_addresses:
                self.summary.wildcard_matches += 1
                continue
            kept.append(hostname)
        return kept

    def reset(self) -> None:
        """Clear de-duplication state (new scan)."""
        self.seen.clear()
        self.summary = ValidationSummary()

    # ---------------------------------------------------------------- internals

    def _is_artifact(self, hostname: str) -> bool:
        """Detect probe/wildcard artifacts in the first label."""
        first = hostname.split(".", 1)[0]
        return bool(_ARTIFACT_LABELS.match(first))


__all__ = ["HostValidator", "ValidationResult", "ValidationSummary"]

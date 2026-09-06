"""Subdomain state machine.

A discovered hostname moves through observable states. Transitions are recorded
with timestamps so history queries can show *when* a host went from resolving to
NXDOMAIN - which is exactly the moment a dangling record appears.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from dnscope.utils.time_utils import utc_now_iso


class SubdomainState:
    """Subdomain lifecycle states."""

    DISCOVERED = "DISCOVERED"
    RESOLVING = "RESOLVING"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    NXDOMAIN = "NXDOMAIN"
    CNAME_ONLY = "CNAME_ONLY"
    POSSIBLE_DANGLING = "POSSIBLE_DANGLING"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"

    ALL = (
        DISCOVERED,
        RESOLVING,
        ACTIVE,
        INACTIVE,
        NXDOMAIN,
        CNAME_ONLY,
        POSSIBLE_DANGLING,
        RETIRED,
        UNKNOWN,
    )

    #: States that mean "this host currently serves something".
    LIVE = (RESOLVING, ACTIVE, CNAME_ONLY)

    #: States worth alerting on.
    ALERTABLE = (POSSIBLE_DANGLING, NXDOMAIN, RETIRED)


@dataclass
class StateTransition:
    """One recorded state change."""

    hostname: str
    from_state: str
    to_state: str
    observed_at: str = field(default_factory=utc_now_iso)
    reason: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return {
            "hostname": self.hostname,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "observed_at": self.observed_at,
            "reason": self.reason,
            "evidence": self.evidence,
        }

    def describe(self) -> str:
        """Human readable transition."""
        return f"{self.hostname}: {self.from_state} -> {self.to_state} ({self.reason})"


class SubdomainStateMachine:
    """Validates and records subdomain state transitions."""

    #: Allowed transitions. Anything else is refused (and reported) so a bug in
    #: the discovery pipeline cannot silently corrupt the historical record.
    TRANSITIONS: dict[str, tuple[str, ...]] = {
        SubdomainState.DISCOVERED: (
            SubdomainState.RESOLVING,
            SubdomainState.ACTIVE,
            SubdomainState.INACTIVE,
            SubdomainState.NXDOMAIN,
            SubdomainState.CNAME_ONLY,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.RESOLVING: (
            SubdomainState.ACTIVE,
            SubdomainState.INACTIVE,
            SubdomainState.NXDOMAIN,
            SubdomainState.CNAME_ONLY,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.ACTIVE: (
            SubdomainState.INACTIVE,
            SubdomainState.NXDOMAIN,
            SubdomainState.CNAME_ONLY,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.RETIRED,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.INACTIVE: (
            SubdomainState.ACTIVE,
            SubdomainState.RESOLVING,
            SubdomainState.NXDOMAIN,
            SubdomainState.RETIRED,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.NXDOMAIN: (
            SubdomainState.ACTIVE,
            SubdomainState.RESOLVING,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.RETIRED,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.CNAME_ONLY: (
            SubdomainState.ACTIVE,
            SubdomainState.POSSIBLE_DANGLING,
            SubdomainState.NXDOMAIN,
            SubdomainState.RETIRED,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.POSSIBLE_DANGLING: (
            SubdomainState.ACTIVE,
            SubdomainState.NXDOMAIN,
            SubdomainState.RETIRED,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.RETIRED: (
            SubdomainState.DISCOVERED,
            SubdomainState.ACTIVE,
            SubdomainState.UNKNOWN,
        ),
        SubdomainState.UNKNOWN: SubdomainState.ALL,
    }

    def __init__(self) -> None:
        self.history: list[StateTransition] = []

    def can_transition(self, from_state: str, to_state: str) -> bool:
        """Return whether a transition is allowed."""
        if from_state == to_state:
            return True
        return to_state in self.TRANSITIONS.get(from_state, ())

    def transition(
        self,
        hostname: str,
        from_state: str,
        to_state: str,
        *,
        reason: str = "",
        evidence: str = "",
        observed_at: str | None = None,
    ) -> StateTransition | None:
        """Record a transition, or return ``None`` when it is not allowed."""
        if from_state == to_state:
            return None
        if not self.can_transition(from_state, to_state):
            return None
        record = StateTransition(
            hostname=hostname,
            from_state=from_state,
            to_state=to_state,
            observed_at=observed_at or utc_now_iso(),
            reason=reason,
            evidence=evidence,
        )
        self.history.append(record)
        return record

    def classify(
        self,
        *,
        nxdomain: bool = False,
        has_addresses: bool = False,
        has_cname: bool = False,
        cname_unresolved: bool = False,
        timeout: bool = False,
        dangling: bool = False,
    ) -> str:
        """Derive a state from DNS observations.

        The precedence matters: NXDOMAIN beats everything, then a dangling CNAME,
        then "resolves to an address".
        """
        if nxdomain:
            return SubdomainState.NXDOMAIN
        if dangling or (has_cname and cname_unresolved):
            return SubdomainState.POSSIBLE_DANGLING
        if has_addresses and has_cname:
            return SubdomainState.ACTIVE
        if has_addresses:
            return SubdomainState.ACTIVE
        if has_cname:
            return SubdomainState.CNAME_ONLY
        if timeout:
            return SubdomainState.UNKNOWN
        return SubdomainState.INACTIVE

    def for_host(self, hostname: str) -> list[StateTransition]:
        """Transition history for one host."""
        return [item for item in self.history if item.hostname == hostname]

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready history."""
        return {
            "transitions": [item.to_dict() for item in self.history],
            "count": len(self.history),
            "hosts": sorted({item.hostname for item in self.history}),
        }


class HostState(BaseModel):
    """Persisted state of one host (stored in the database)."""

    hostname: str
    state: str = SubdomainState.DISCOVERED
    previous_state: str = ""
    first_seen: str = ""
    last_seen: str = Field(default_factory=utc_now_iso)
    state_changed_at: str = Field(default_factory=utc_now_iso)
    transitions: int = 0
    evidence: str = ""

    def is_live(self) -> bool:
        """``True`` when the host currently resolves in some way."""
        return self.state in SubdomainState.LIVE

    def needs_attention(self) -> bool:
        """``True`` when the state is worth alerting on."""
        return self.state in SubdomainState.ALERTABLE


__all__ = [
    "HostState",
    "StateTransition",
    "SubdomainState",
    "SubdomainStateMachine",
]

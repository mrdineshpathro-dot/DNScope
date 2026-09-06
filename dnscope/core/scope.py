"""Scope engine.

Nothing discovered by DNScope is processed unless it passes scope validation.
Scope is never expanded automatically: a discovered third-party host is tagged
``OUT_OF_SCOPE`` and left alone rather than followed, because following it would
mean scanning an organization the operator did not authorize.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from pydantic import BaseModel, Field, PrivateAttr

from dnscope.exceptions import ScopeError
from dnscope.models.common import SchemaVersioned, ScopeStatus
from dnscope.utils.domains import (
    is_ip_literal,
    normalize_hostname,
    registered_domain,
    valid_hostname,
    wildcard_strip,
)


@dataclass
class ScopeDecision:
    """Outcome of validating one host against the scope."""

    host: str
    status: ScopeStatus
    reason: str = ""
    matched_rule: str = ""
    #: ``True`` when the host is a third-party asset reached from an in-scope host.
    third_party: bool = False

    @property
    def in_scope(self) -> bool:
        return self.status is ScopeStatus.IN_SCOPE

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready representation."""
        return {
            "host": self.host,
            "scope_status": self.status.value,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "third_party": self.third_party,
        }


class ScopeSummary(SchemaVersioned):
    """Aggregate scope decisions for a scan (used in reports)."""

    total: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    blocked: list[str] = Field(default_factory=list)
    allowed_rules: list[str] = Field(default_factory=list)
    excluded_rules: list[str] = Field(default_factory=list)
    enforced: bool = True

    def record(self, decision: ScopeDecision) -> None:
        """Count a decision and remember blocked hosts (bounded list)."""
        self.total += 1
        if decision.in_scope:
            self.in_scope += 1
        else:
            self.out_of_scope += 1
            if len(self.blocked) < 500 and decision.host not in self.blocked:
                self.blocked.append(decision.host)


class _Pattern:
    """A compiled scope pattern (``example.com`` or ``*.example.com``)."""

    __slots__ = ("exact", "raw", "suffix", "wildcard")

    def __init__(self, raw: str) -> None:
        self.raw = raw.strip().lower()
        self.wildcard = self.raw.startswith("*.") or self.raw == "*"
        cleaned = wildcard_strip(self.raw)
        self.exact = normalize_hostname(cleaned)
        self.suffix = f".{self.exact}" if self.exact else ""

    def matches(self, host: str, *, include_subdomains: bool = True) -> bool:
        """Return ``True`` when ``host`` is covered by this pattern."""
        if not self.exact:
            return False
        if host == self.exact:
            return True
        if self.wildcard or include_subdomains:
            return host.endswith(self.suffix)
        return False


class Scope(BaseModel):
    """Explicit allow/deny scope with validation.

    With no allow rules configured, scope defaults to "whatever target was
    requested" so the common ``dnscope scan example.com`` case still enforces a
    boundary (example.com and its subdomains) without extra configuration.
    """

    allowed: list[str] = Field(default_factory=list)
    excluded: list[str] = Field(default_factory=list)
    extra_hosts: list[str] = Field(default_factory=list)
    include_subdomains: bool = True
    allow_ip_targets: bool = True
    enforce: bool = True
    #: Root targets supplied on the command line; always in scope.
    roots: list[str] = Field(default_factory=list)
    summary: ScopeSummary = Field(default_factory=ScopeSummary)

    # Compiled pattern caches (invalidated whenever a rule changes).
    _allow_cache: list[_Pattern] | None = PrivateAttr(default=None)
    _deny_cache: list[_Pattern] | None = PrivateAttr(default=None)

    # ------------------------------------------------------------ construction

    @classmethod
    def from_config(cls, config: Any, *, roots: Iterable[str] = ()) -> "Scope":
        """Build a scope from a :class:`dnscope.core.config.ScopeConfig`."""
        scope_config = getattr(config, "scope", config)
        return cls(
            allowed=list(getattr(scope_config, "allowed_domains", []) or []),
            excluded=list(getattr(scope_config, "excluded_domains", []) or []),
            extra_hosts=list(getattr(scope_config, "extra_hosts", []) or []),
            include_subdomains=bool(getattr(scope_config, "include_subdomains", True)),
            allow_ip_targets=bool(getattr(scope_config, "allow_ip_targets", True)),
            enforce=bool(getattr(scope_config, "enforce", True)),
            roots=[normalize_hostname(root) for root in roots],
        )

    @classmethod
    def for_target(cls, target: Any, *, include_subdomains: bool = True) -> "Scope":
        """Scope limited to a single target and (optionally) its subdomains."""
        hostname = normalize_hostname(str(getattr(target, "hostname", target)))
        return cls(allowed=[hostname], include_subdomains=include_subdomains, roots=[hostname])

    # ---------------------------------------------------------------- helpers

    def add_root(self, host: str) -> None:
        """Register a command-line target as in-scope."""
        normalized = normalize_hostname(host)
        if normalized and normalized not in self.roots:
            self.roots.append(normalized)
        self._allow_cache = None

    def allow(self, pattern: str) -> None:
        """Add an allow rule (``example.com`` or ``*.example.com``)."""
        if pattern not in self.allowed:
            self.allowed.append(pattern)
        self._allow_cache = None

    def exclude(self, pattern: str) -> None:
        """Add a deny rule."""
        if pattern not in self.excluded:
            self.excluded.append(pattern)
        self._deny_cache = None

    @property
    def allow_patterns(self) -> list[_Pattern]:
        """Compiled allow patterns (cached)."""
        if self._allow_cache is None:
            compiled = [_Pattern(item) for item in self.allowed]
            compiled.extend(_Pattern(root) for root in self.roots)
            compiled.extend(_Pattern(item) for item in self.extra_hosts)
            self._allow_cache = compiled
        return self._allow_cache

    @property
    def deny_patterns(self) -> list[_Pattern]:
        """Compiled deny patterns (cached)."""
        if self._deny_cache is None:
            self._deny_cache = [_Pattern(item) for item in self.excluded]
        return self._deny_cache

    @property
    def is_unrestricted(self) -> bool:
        """``True`` when no allow rules exist (scope falls back to roots)."""
        return not self.allowed and not self.roots and not self.extra_hosts

    def effective_roots(self) -> list[str]:
        """All in-scope root names."""
        roots = {normalize_hostname(item) for item in (*self.allowed, *self.roots, *self.extra_hosts)}
        return sorted(root for root in roots if root)

    # ------------------------------------------------------------- validation

    def check(self, host: str, *, record: bool = True) -> ScopeDecision:
        """Validate ``host`` against the scope rules."""
        normalized = normalize_hostname(host)
        if not normalized:
            decision = ScopeDecision(host, ScopeStatus.OUT_OF_SCOPE, reason="empty host")
        elif is_ip_literal(normalized):
            decision = self._check_ip(normalized)
        elif not valid_hostname(normalized):
            decision = ScopeDecision(
                normalized, ScopeStatus.OUT_OF_SCOPE, reason="invalid hostname syntax"
            )
        else:
            decision = self._check_host(normalized)
        if record:
            self.summary.record(decision)
        return decision

    def _check_ip(self, address: str) -> ScopeDecision:
        """IP targets are only allowed when explicitly permitted."""
        if self.allow_ip_targets:
            return ScopeDecision(address, ScopeStatus.IN_SCOPE, reason="ip target allowed by policy", matched_rule="ip")
        return ScopeDecision(
            address,
            ScopeStatus.OUT_OF_SCOPE,
            reason="IP targets are disabled in scope configuration",
            matched_rule="ip",
        )

    def _check_host(self, host: str) -> ScopeDecision:
        """Domain validation: deny rules win, then allow rules."""
        for pattern in self.deny_patterns:
            if pattern.matches(host, include_subdomains=self.include_subdomains):
                return ScopeDecision(
                    host,
                    ScopeStatus.OUT_OF_SCOPE,
                    reason=f"matches excluded rule {pattern.raw}",
                    matched_rule=pattern.raw,
                )

        for pattern in self.allow_patterns:
            if pattern.matches(host, include_subdomains=self.include_subdomains):
                return ScopeDecision(
                    host, ScopeStatus.IN_SCOPE, reason="matches allowed scope", matched_rule=pattern.raw
                )

        if self.is_unrestricted:
            return ScopeDecision(
                host,
                ScopeStatus.IN_SCOPE,
                reason="no scope rules configured",
                matched_rule="*",
            )

        # Not matched: is it a third party discovered from an in-scope asset?
        base = registered_domain(host)
        for root in self.effective_roots():
            if registered_domain(root) == base:
                return ScopeDecision(
                    host,
                    ScopeStatus.OUT_OF_SCOPE,
                    reason=f"same registrable domain as {root} but not covered by an allow rule",
                    matched_rule="",
                    third_party=False,
                )
        return ScopeDecision(
            host,
            ScopeStatus.OUT_OF_SCOPE,
            reason="host belongs to a different organization than the authorized scope",
            matched_rule="",
            third_party=True,
        )

    def is_allowed(self, host: str) -> bool:
        """Convenience boolean check (does not record into the summary)."""
        return self.check(host, record=False).in_scope

    def filter(self, hosts: Iterable[str]) -> list[str]:
        """Return only the in-scope hosts, preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for host in hosts:
            normalized = normalize_hostname(host)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            if self.is_allowed(normalized):
                result.append(normalized)
        return result

    def assert_allowed(self, host: str) -> ScopeDecision:
        """Raise :class:`ScopeError` when ``host`` is out of scope."""
        decision = self.check(host)
        if self.enforce and not decision.in_scope:
            raise ScopeError(
                f"target {host} is out of scope: {decision.reason}",
                details=decision.to_dict(),
            )
        return decision

    # ------------------------------------------------------------------ output

    def describe(self) -> str:
        """Human readable description used by ``dnscope config`` and reports."""
        if self.is_unrestricted:
            return "unrestricted (no scope rules configured)"
        parts = [f"allowed={','.join(self.allowed or self.roots) or '-'}"]
        if self.excluded:
            parts.append(f"excluded={','.join(self.excluded)}")
        parts.append(f"subdomains={'yes' if self.include_subdomains else 'no'}")
        parts.append(f"enforced={'yes' if self.enforce else 'no'}")
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Canonical representation embedded in report payloads."""
        return {
            "allowed_domains": list(self.allowed),
            "excluded_domains": list(self.excluded),
            "roots": list(self.roots),
            "include_subdomains": self.include_subdomains,
            "allow_ip_targets": self.allow_ip_targets,
            "enforced": self.enforce,
            "summary": self.summary.to_dict(),
            "description": self.describe(),
        }


__all__ = ["Scope", "ScopeDecision", "ScopeSummary"]

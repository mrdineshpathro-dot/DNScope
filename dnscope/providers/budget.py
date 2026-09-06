"""Provider budget engine.

Tracks per-provider usage so DNScope can (a) report honest usage numbers,
(b) stop calling a provider that is failing, and (c) prefer cheap providers
when several can satisfy the same request.

Quota *values* are only reported when a provider actually supplies them; DNScope
never guesses a rate limit it has not been told.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from dnscope.models.providers import ProviderBudget
from dnscope.utils.time_utils import utc_now_iso


class BudgetTracker:
    """Thread-safe collection of :class:`ProviderBudget` records."""

    def __init__(self) -> None:
        self._budgets: dict[str, ProviderBudget] = {}
        self._lock = threading.RLock()
        #: Provider-supplied quota information (only what the API reports).
        self._quotas: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ record

    def budget(self, provider: str) -> ProviderBudget:
        """Return (creating if needed) the budget for ``provider``."""
        with self._lock:
            budget = self._budgets.get(provider)
            if budget is None:
                budget = ProviderBudget(provider=provider)
                self._budgets[provider] = budget
            return budget

    def record_request(
        self,
        provider: str,
        *,
        ok: bool = True,
        latency_ms: float = 0.0,
        size: int = 0,
        rate_limited: bool = False,
        timeout: bool = False,
        error: str = "",
    ) -> ProviderBudget:
        """Account for one provider call."""
        budget = self.budget(provider)
        with self._lock:
            if rate_limited:
                budget.record_rate_limited()
            elif ok:
                budget.record_success(latency_ms, size=size)
            elif timeout:
                budget.timeouts += 1
                budget.record_failure(error or "timeout", latency_ms=latency_ms)
            else:
                budget.record_failure(error, latency_ms=latency_ms)
        return budget

    def record_cache_hit(self, provider: str) -> None:
        """Account for a result served from cache (no provider request)."""
        self.budget(provider).record_cache_hit()

    def record_quota(
        self,
        provider: str,
        *,
        limit: int | None = None,
        remaining: int | None = None,
        reset_at: str | None = None,
    ) -> None:
        """Store quota information *only* when the provider supplied it."""
        if limit is None and remaining is None and reset_at is None:
            return
        with self._lock:
            self._quotas[provider] = {
                "limit": limit,
                "remaining": remaining,
                "reset_at": reset_at or utc_now_iso(),
            }

    def quota(self, provider: str) -> dict[str, Any]:
        """Return provider-supplied quota data (empty dict when unknown)."""
        with self._lock:
            return dict(self._quotas.get(provider, {}))

    def set_circuit(self, provider: str, *, open_: bool) -> None:
        """Reflect circuit-breaker state into the budget record."""
        budget = self.budget(provider)
        with self._lock:
            budget.circuit_open = open_
            budget.circuit_opened_at = utc_now_iso() if open_ else None

    # ------------------------------------------------------------------- query

    def all(self) -> dict[str, ProviderBudget]:
        """Snapshot of every tracked budget."""
        with self._lock:
            return {name: budget.model_copy(deep=True) for name, budget in self._budgets.items()}

    def total_requests(self, providers: Iterable[str] | None = None) -> int:
        """Total requests sent, optionally filtered by provider."""
        with self._lock:
            items = self._budgets.values()
            if providers is not None:
                allowed = {p.lower() for p in providers}
                items = [b for name, b in self._budgets.items() if name.lower() in allowed]
            return sum(budget.requests for budget in items)

    def summary(self) -> dict[str, Any]:
        """Aggregate view used by ``dnscope providers`` and ``/metrics``."""
        with self._lock:
            budgets = list(self._budgets.values())
        total = sum(budget.requests for budget in budgets)
        return {
            "providers_tracked": len(budgets),
            "total_requests": total,
            "total_failures": sum(budget.failures for budget in budgets),
            "total_rate_limited": sum(budget.rate_limited for budget in budgets),
            "total_cache_hits": sum(budget.cache_hits for budget in budgets),
            "bytes_received": sum(budget.bytes_received for budget in budgets),
            "average_latency_ms": round(sum(budget.total_latency_ms for budget in budgets) / total, 2)
            if total
            else 0.0,
            "open_circuits": [b.provider for b in budgets if b.circuit_open],
            "quotas": {name: dict(data) for name, data in self._quotas.items()},
        }

    def reset(self, provider: str | None = None) -> None:
        """Clear counters for one provider or all of them."""
        with self._lock:
            if provider is None:
                self._budgets.clear()
                self._quotas.clear()
            else:
                self._budgets.pop(provider, None)
                self._quotas.pop(provider, None)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready snapshot (for reports and the REST API)."""
        return {name: budget.to_dict() for name, budget in self.all().items()}


#: Process-wide default tracker, shared by the engine and the REST API.
DEFAULT_BUDGET = BudgetTracker()

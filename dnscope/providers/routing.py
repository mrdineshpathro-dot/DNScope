"""Smart API routing.

DNScope does not call every provider for every target. The router answers one
question: *which provider should serve this capability right now?* and orders
candidates by capability match, credential availability, health, prior failures
and cache state. Requests already served in this scan are never repeated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from dnscope.models.providers import ProviderQueryResult, ProviderStatus
from dnscope.providers.base import Provider, ProviderContext
from dnscope.providers.budget import BudgetTracker
from dnscope.providers.registry import ProviderRegistry
from dnscope.utils.logging import get_logger

_log = get_logger("providers.routing")

#: Preference order within a capability: keyless/cheap sources first so paid
#: quota is only spent when it adds something.
PREFERENCE: dict[str, tuple[str, ...]] = {
    "ct": ("crt.sh", "virustotal", "securitytrails"),
    "subdomains": ("crt.sh", "otx", "urlscan", "virustotal", "securitytrails", "hackertarget", "rdap"),
    "dns": ("rdap", "otx", "virustotal", "securitytrails", "crt.sh"),
    "ip": ("team-cymru", "virustotal", "shodan", "censys", "abuseipdb", "urlscan"),
    "asn": ("team-cymru", "rdap", "shodan", "censys"),
    "threat": ("abuseipdb", "greynoise", "virustotal", "otx", "shodan"),
    "history": ("securitytrails", "otx", "rdap", "virustotal"),
    "rdap": ("rdap",),
    "certificates": ("crt.sh", "virustotal"),
}


@dataclass
class RoutingDecision:
    """Which provider was chosen, and why."""

    capability: str
    target: str
    provider: str = ""
    reason: str = ""
    skipped: list[dict[str, str]] = field(default_factory=list)
    from_cache: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready representation for reports."""
        return {
            "capability": self.capability,
            "target": self.target,
            "provider": self.provider,
            "reason": self.reason,
            "skipped": self.skipped,
            "from_cache": self.from_cache,
        }


class ProviderRouter:
    """Selects providers for capability requests."""

    def __init__(
        self,
        registry: ProviderRegistry,
        *,
        budget: BudgetTracker | None = None,
        cache: Any = None,
        max_providers: int = 3,
        avoid_duplicate_requests: bool = True,
    ) -> None:
        self.registry = registry
        self.budget = budget or BudgetTracker()
        self.cache = cache
        self.max_providers = max(1, max_providers)
        self.avoid_duplicates = avoid_duplicate_requests
        #: ``(provider, capability, target)`` triples already served.
        self._served: set[tuple[str, str, str]] = set()
        self.decisions: list[RoutingDecision] = []

    # ----------------------------------------------------------------- ranking

    def candidates(self, capability: str) -> list[Provider]:
        """Providers implementing ``capability``, in preference order."""
        capable = self.registry.for_capability(capability)
        order = PREFERENCE.get(capability, ())
        rank = {name: index for index, name in enumerate(order)}
        return sorted(
            capable,
            key=lambda provider: (
                rank.get(provider.name, len(order)),
                provider.requires_credentials,  # keyless first
                provider.name,
            ),
        )

    def rank(self, capability: str, *, max_providers: int | None = None) -> list[tuple[Provider, str]]:
        """Return ``(provider, reason)`` pairs, best first, with skip reasons.

        Only providers that are enabled and configured are returned; the rest are
        excluded (and recorded in the decision) so reports explain why a paid
        provider was not used.
        """
        ranked: list[tuple[Provider, str]] = []
        for provider in self.candidates(capability):
            info = self.registry.get(provider.name)
            if info is None:
                continue
            if not self.registry.is_enabled(provider.name):
                continue
            if not provider.is_configured():
                continue
            budget = self.budget.budget(provider.name)
            if budget.circuit_open:
                continue
            if budget.failure_rate > 0.5 and budget.requests >= 3:
                continue
            ranked.append((provider, "eligible"))
        limit = max_providers or self.max_providers
        return ranked[:limit]

    def skipped_reasons(self, capability: str) -> list[dict[str, str]]:
        """Explain why each non-selected provider was skipped."""
        reasons: list[dict[str, str]] = []
        for provider in self.candidates(capability):
            if not self.registry.is_enabled(provider.name):
                reasons.append({"provider": provider.name, "reason": "disabled or offline"})
                continue
            if not provider.is_configured():
                reasons.append(
                    {"provider": provider.name, "reason": f"missing {', '.join(provider.env_vars) or 'credentials'}"}
                )
                continue
            budget = self.budget.budget(provider.name)
            if budget.circuit_open:
                reasons.append({"provider": provider.name, "reason": "circuit breaker open"})
        return reasons

    # ---------------------------------------------------------------- execution

    def select(self, capability: str, target: str, *, max_providers: int | None = None) -> RoutingDecision:
        """Choose the provider that should serve ``capability`` for ``target``."""
        decision = RoutingDecision(capability=capability, target=target)
        candidates = self.rank(capability, max_providers=max_providers)
        decision.skipped = self.skipped_reasons(capability)

        if self.cache is not None:
            cached = self._cache_get(capability, target)
            if cached is not None:
                decision.provider = cached.get("provider", "")
                decision.from_cache = True
                decision.reason = "served from cache"
                self.decisions.append(decision)
                return decision

        for provider, _ in candidates:
            key = (provider.name, capability, target.lower())
            if self.avoid_duplicates and key in self._served:
                continue
            decision.provider = provider.name
            decision.reason = (
                "keyless provider" if not provider.requires_credentials else "credentialed provider available"
            )
            self.decisions.append(decision)
            return decision

        decision.reason = "no eligible provider for this capability"
        self.decisions.append(decision)
        return decision

    def run(
        self,
        capability: str,
        target: str,
        context: ProviderContext,
        *,
        max_providers: int | None = None,
        options: dict[str, Any] | None = None,
        stop_on_first_success: bool = True,
    ) -> tuple[ProviderQueryResult | None, list[RoutingDecision]]:
        """Execute the capability across eligible providers.

        Returns the first successful result (or ``None``) plus every routing
        decision taken, so reports can show exactly which providers were tried
        and why others were skipped.
        """
        decisions: list[RoutingDecision] = []
        candidates = self.rank(capability, max_providers=max_providers)
        if not candidates:
            decision = RoutingDecision(
                capability=capability,
                target=target,
                reason="no eligible provider",
                skipped=self.skipped_reasons(capability),
            )
            decisions.append(decision)
            self.decisions.append(decision)
            return None, decisions

        last_result: ProviderQueryResult | None = None
        for provider, _reason in candidates:
            key = (provider.name, capability, target.lower())
            if self.avoid_duplicates and key in self._served:
                decision = RoutingDecision(
                    capability=capability,
                    target=target,
                    provider=provider.name,
                    reason="already queried in this run",
                )
                decisions.append(decision)
                continue

            cached = self._cache_get(capability, target, provider=provider.name) if self.cache else None
            if cached is not None:
                result = ProviderQueryResult.model_validate(cached)
                result.cached = True
                self.budget.record_cache_hit(provider.name)
                self._served.add(key)
                decision = RoutingDecision(
                    capability=capability,
                    target=target,
                    provider=provider.name,
                    reason="served from cache",
                    from_cache=True,
                )
                decisions.append(decision)
                self.decisions.append(decision)
                return result, decisions

            decision = RoutingDecision(capability=capability, target=target, provider=provider.name)
            provider_context = ProviderContext(
                http=context.http,
                cache=context.cache,
                settings=context.settings,
                offline=context.offline,
                privacy=context.privacy,
                workspace=context.workspace,
                api_key=provider.api_key,
                allow_external=context.allow_external,
                dns=context.dns,
                rate_budget=self.budget,
            )
            try:
                result = provider.query(target, provider_context, **(options or {}))
            except Exception as exc:  # noqa: BLE001 - provider failures must not abort a scan
                _log.warning("provider %s failed for %s: %s", provider.name, target, exc)
                self.budget.record_request(provider.name, ok=False, error=str(exc))
                decision.reason = f"failed: {exc}"
                decisions.append(decision)
                self.decisions.append(decision)
                continue

            self._served.add(key)
            self.budget.record_request(
                provider.name,
                ok=result.ok,
                latency_ms=result.latency_ms,
                error=result.error,
                rate_limited="429" in result.error,
            )
            if result.ok and result.observation_count > 0:
                decision.reason = f"returned {result.observation_count} observations"
                decisions.append(decision)
                self.decisions.append(decision)
                self._cache_put(capability, target, provider.name, result)
                return result, decisions

            decision.reason = result.error or "no observations returned"
            last_result = result
            decisions.append(decision)
            self.decisions.append(decision)
            if not stop_on_first_success:
                continue

        return last_result, decisions

    # ------------------------------------------------------------------- cache

    def _cache_key(self, capability: str, target: str, provider: str | None = None) -> str:
        suffix = f":{provider}" if provider else ""
        return f"provider:{capability}:{target.lower()}{suffix}"

    def _cache_get(self, capability: str, target: str, *, provider: str | None = None) -> dict[str, Any] | None:
        """Read a cached provider result (``None`` on miss)."""
        if self.cache is None:
            return None
        try:
            return self.cache.get(self._cache_key(capability, target, provider))
        except Exception:  # noqa: BLE001 - cache failures degrade to a miss
            return None

    def _cache_put(self, capability: str, target: str, provider: str, result: ProviderQueryResult) -> None:
        """Store a provider result for reuse."""
        if self.cache is None:
            return
        try:
            self.cache.set(
                self._cache_key(capability, target, provider),
                result.to_dict(),
                namespace="provider",
            )
        except Exception as exc:  # noqa: BLE001 - never fail a scan on cache write
            _log.debug("cache write failed: %s", exc)

    # ----------------------------------------------------------------- reporting

    def reset(self) -> None:
        """Forget served-request state (new scan)."""
        self._served.clear()
        self.decisions.clear()

    def served_count(self) -> int:
        """Number of distinct provider calls made in this run."""
        return len(self._served)

    def to_dict(self) -> dict[str, Any]:
        """Routing summary for reports and ``/metrics``."""
        return {
            "requests": self.served_count(),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


def providers_for_capability(registry: ProviderRegistry, capability: str) -> list[str]:
    """Names of providers that implement ``capability`` (for CLI output)."""
    return [provider.name for provider in registry.for_capability(capability)]


def status_label(registry: ProviderRegistry, name: str) -> str:
    """Display status for one provider."""
    provider = registry.get(name)
    if provider is None:
        return ProviderStatus.UNKNOWN
    return registry.status_for(provider)[0]


__all__ = ["PREFERENCE", "ProviderRouter", "RoutingDecision", "providers_for_capability", "status_label"]

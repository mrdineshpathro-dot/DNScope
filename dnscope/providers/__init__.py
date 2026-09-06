"""Provider subsystem: capability abstraction, routing, budgets and APIs."""

from dnscope.providers.base import (
    DiscoveryProvider,
    Provider,
    ProviderContext,
    ThreatProvider,
)
from dnscope.providers.budget import DEFAULT_BUDGET, BudgetTracker
from dnscope.providers.http import (
    CircuitBreaker,
    CircuitOpenError,
    HttpResponse,
    SafeHTTPClient,
    client_from_settings,
)
from dnscope.providers.registry import ProviderRegistry, builtin_provider_classes
from dnscope.providers.routing import PREFERENCE, ProviderRouter, RoutingDecision

__all__ = [
    "DEFAULT_BUDGET",
    "PREFERENCE",
    "BudgetTracker",
    "CircuitBreaker",
    "CircuitOpenError",
    "DiscoveryProvider",
    "HttpResponse",
    "Provider",
    "ProviderContext",
    "ProviderRegistry",
    "ProviderRouter",
    "RoutingDecision",
    "SafeHTTPClient",
    "ThreatProvider",
    "builtin_provider_classes",
    "client_from_settings",
]

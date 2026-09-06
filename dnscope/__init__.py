"""DNScope - Advanced DNS Attack Surface Intelligence Platform.

DNScope is an evidence-first DNS intelligence platform. It performs authorized,
rate-limited, scope-enforced reconnaissance and turns raw DNS observations into
correlated assets, explainable risk findings, historical baselines and reports.

Design pillars
--------------
* **Evidence first** - every finding carries the observation that produced it.
* **Safe by default** - no exploitation, no takeover attempts, bounded fan-out.
* **Works offline** - core DNS analysis requires no API keys at all.
* **Privacy first** - no telemetry, optional enrichment, redacted secrets.

Public API::

    from dnscope import DNScopeEngine, Target, load_config

    engine = DNScopeEngine()
    result = engine.analyze(Target.parse("example.com"))

Heavy subsystems (DNS engine, HTTP client, storage) are imported lazily so that
``dnscope --help`` and the REST API import path stay fast.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dnscope.constants import (
    AUTHOR,
    BANNER,
    GITHUB_URL,
    PRODUCT_NAME,
    PRODUCT_TAGLINE,
    SCHEMA_VERSION,
    YOUTUBE_URL,
)
from dnscope.exceptions import DNScopeError

__version__ = "4.0.0"
__author__ = AUTHOR

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "DNScopeConfig": ("dnscope.core.config", "DNScopeConfig"),
    "load_config": ("dnscope.core.config", "load_config"),
    "DNScopeEngine": ("dnscope.core.engine", "DNScopeEngine"),
    "AnalysisResult": ("dnscope.core.engine", "AnalysisResult"),
    "Scope": ("dnscope.core.scope", "Scope"),
    "Target": ("dnscope.models.targets", "Target"),
    "Finding": ("dnscope.models.findings", "Finding"),
    "DNScopeDatabase": ("dnscope.storage.database", "DNScopeDatabase"),
    "ProviderRegistry": ("dnscope.providers.registry", "ProviderRegistry"),
}

__all__ = [
    "AUTHOR",
    "BANNER",
    "GITHUB_URL",
    "PRODUCT_NAME",
    "PRODUCT_TAGLINE",
    "SCHEMA_VERSION",
    "YOUTUBE_URL",
    "AnalysisResult",
    "DNScopeConfig",
    "DNScopeDatabase",
    "DNScopeEngine",
    "DNScopeError",
    "Finding",
    "ProviderRegistry",
    "Scope",
    "Target",
    "__author__",
    "__version__",
    "load_config",
]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from dnscope.core.config import DNScopeConfig, load_config
    from dnscope.core.engine import AnalysisResult, DNScopeEngine
    from dnscope.core.scope import Scope
    from dnscope.models.findings import Finding
    from dnscope.models.targets import Target
    from dnscope.providers.registry import ProviderRegistry
    from dnscope.storage.database import DNScopeDatabase


def __getattr__(name: str) -> Any:
    """Lazily import heavy subsystems on first attribute access."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'dnscope' has no attribute {name!r}")
    module_name, attribute = target
    from importlib import import_module

    module = import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))

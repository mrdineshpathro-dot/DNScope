"""Core subsystems: configuration, scope, orchestration, caching and audit."""

from dnscope.core.config import (
    PROFILES,
    DNScopeConfig,
    LimitsConfig,
    ResolverConfig,
    apply_profile,
    default_config,
    load_config,
    profile_names,
)
from dnscope.core.scope import Scope, ScopeDecision

__all__ = [
    "PROFILES",
    "DNScopeConfig",
    "LimitsConfig",
    "ResolverConfig",
    "Scope",
    "ScopeDecision",
    "apply_profile",
    "default_config",
    "load_config",
    "profile_names",
]

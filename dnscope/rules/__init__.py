"""Rule engine: declarative rules, registered logic checks and finding assembly."""

from dnscope.rules.context import RuleHit, ScanContext, build_context
from dnscope.rules.engine import (
    BUILTIN_RULES_DIR,
    CATEGORIES,
    RuleEngine,
    RuleLoadResult,
    RuleSpec,
    default_engine,
)
from dnscope.rules.logic import get_logic, register_logic, registered_logic

__all__ = [
    "BUILTIN_RULES_DIR",
    "CATEGORIES",
    "RuleEngine",
    "RuleHit",
    "RuleLoadResult",
    "RuleSpec",
    "ScanContext",
    "build_context",
    "default_engine",
    "get_logic",
    "register_logic",
    "registered_logic",
]

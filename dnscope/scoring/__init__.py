"""Scoring: risk aggregation and change significance classification."""

from dnscope.scoring.risk import AttackSurfaceSummary, RiskEngine, RiskScore
from dnscope.scoring.significance import (
    SignificanceEngine,
    SignificanceRule,
    classify_change,
)

__all__ = [
    "AttackSurfaceSummary",
    "RiskEngine",
    "RiskScore",
    "SignificanceEngine",
    "SignificanceRule",
    "classify_change",
]

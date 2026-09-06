"""Subdomain confidence scoring.

Confidence answers: *how sure are we that this hostname is a real, current part
of the target's infrastructure?* It combines source quality with whether the name
actually resolves.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from dnscope.models.common import Confidence

#: Base quality of each discovery source (0..1).
SOURCE_QUALITY: dict[str, float] = {
    "dns": 1.0,  # we resolved it ourselves
    "ct": 0.8,  # certificate logs are public but can lag
    "passive-dns": 0.75,
    "rdap": 0.7,
    "virustotal": 0.7,
    "securitytrails": 0.7,
    "otx": 0.6,
    "urlscan": 0.6,
    "hackertarget": 0.5,
    "wordlist": 0.55,
    "permutation": 0.35,
    "baseline": 0.9,
    "database": 0.85,
    "import": 0.6,
}


class ConfidenceFactors(BaseModel):
    """Inputs used to derive a confidence level."""

    source_count: int = 0
    best_source_quality: float = 0.0
    sources: list[str] = Field(default_factory=list)
    resolves: bool = False
    wildcard_match: bool = False
    out_of_scope: bool = False
    #: ``True`` when the name only has a CNAME and no address records.
    cname_only: bool = False
    nxdomain: bool = False

    @property
    def score(self) -> float:
        """Numeric confidence (0..1)."""
        if self.out_of_scope or self.wildcard_match:
            return 0.05
        base = self.best_source_quality
        if self.source_count > 1:
            base = min(1.0, base + 0.15 * (self.source_count - 1))
        if self.resolves:
            base = min(1.0, base + 0.15)
        if self.nxdomain:
            base = max(0.0, base - 0.35)
        if self.cname_only:
            base = max(0.0, base - 0.1)
        return round(max(0.0, min(1.0, base)), 3)


class ConfidenceScorer:
    """Derives a :class:`Confidence` level from discovery factors."""

    def __init__(self, source_quality: dict[str, float] | None = None) -> None:
        self.source_quality = dict(SOURCE_QUALITY)
        if source_quality:
            self.source_quality.update(source_quality)

    def quality_for(self, source: str) -> float:
        """Quality weight for one source name."""
        return self.source_quality.get(source.lower(), 0.5)

    def factors(
        self,
        sources: Iterable[str],
        *,
        resolves: bool = False,
        wildcard_match: bool = False,
        out_of_scope: bool = False,
        cname_only: bool = False,
        nxdomain: bool = False,
    ) -> ConfidenceFactors:
        """Build the factor set for a host."""
        names = sorted({str(item).lower() for item in sources if item})
        best = max((self.quality_for(name) for name in names), default=0.0)
        return ConfidenceFactors(
            source_count=len(names),
            best_source_quality=best,
            sources=names,
            resolves=resolves,
            wildcard_match=wildcard_match,
            out_of_scope=out_of_scope,
            cname_only=cname_only,
            nxdomain=nxdomain,
        )

    def score(
        self,
        sources: Iterable[str],
        *,
        resolves: bool = False,
        wildcard_match: bool = False,
        out_of_scope: bool = False,
        cname_only: bool = False,
        nxdomain: bool = False,
    ) -> Confidence:
        """Return the confidence level for a discovered host."""
        factors = self.factors(
            sources,
            resolves=resolves,
            wildcard_match=wildcard_match,
            out_of_scope=out_of_scope,
            cname_only=cname_only,
            nxdomain=nxdomain,
        )
        return self.level(factors)

    def level(self, factors: ConfidenceFactors) -> Confidence:
        """Map a numeric score onto HIGH/MEDIUM/LOW."""
        value = factors.score
        if value >= 0.8:
            return Confidence.HIGH
        if value >= 0.5:
            return Confidence.MEDIUM
        return Confidence.LOW

    def explain(self, factors: ConfidenceFactors) -> str:
        """Human explanation of a confidence decision."""
        parts = [
            f"sources={','.join(factors.sources) or 'none'}",
            f"best_quality={factors.best_source_quality:.2f}",
            f"resolves={'yes' if factors.resolves else 'no'}",
        ]
        if factors.nxdomain:
            parts.append("nxdomain=yes")
        if factors.cname_only:
            parts.append("cname_only=yes")
        if factors.wildcard_match:
            parts.append("wildcard_match=yes (treated as artifact)")
        if factors.out_of_scope:
            parts.append("out_of_scope=yes")
        parts.append(f"score={factors.score:.2f}")
        return " ".join(parts)

    def describe(self, sources: Iterable[str], **kwargs: Any) -> dict[str, Any]:
        """Full description used in reports."""
        factors = self.factors(sources, **kwargs)
        return {
            "confidence": self.level(factors).value,
            "score": factors.score,
            "factors": factors.model_dump(),
            "explanation": self.explain(factors),
        }


__all__ = ["SOURCE_QUALITY", "ConfidenceFactors", "ConfidenceScorer"]

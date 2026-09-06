"""Threat intelligence enrichment.

This module is a *consumer* of third-party reputation data, and it is written to
fail honestly:

* If no threat provider is configured, the report says so and no verdict is
  produced. DNScope never invents a reputation.
* Every indicator keeps the provider name, the raw value the provider returned
  and the observation time, so a reader can tell *whose* opinion this is and how
  old it is.
* Reputation is reported as ``quality=CORRELATED`` / ``confidence`` from the
  provider, never as an observed fact about the target.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import Field

from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.providers.base import Provider, ProviderContext
from dnscope.providers.http import default_client
from dnscope.providers.registry import ProviderRegistry
from dnscope.security.validators import coerce_str, coerce_str_list
from dnscope.utils.domains import is_ip_literal, normalize_hostname
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import now_utc, utc_now_iso

_log = get_logger("intelligence.threat")

#: Score (0-100) at or above which a provider's verdict is treated as hostile.
MALICIOUS_THRESHOLD = 50
#: Score at or above which the address deserves a closer look.
SUSPICIOUS_THRESHOLD = 20

#: Provider field aliases for a numeric reputation score.
SCORE_KEYS = (
    "malicious",
    "abuse_confidence_score",
    "confidence_score",
    "score",
    "malicious_score",
    "reputation",
)
#: Provider field aliases for a textual verdict.
VERDICT_KEYS = ("verdict", "classification", "riot", "noise", "harmless")
#: Provider field aliases for categorisation.
TAG_KEYS = ("tags", "categories", "tags_verbose", "vulns")


class ThreatIndicator(SchemaVersioned):
    """One provider's opinion about one subject."""

    subject: str
    provider: str
    #: Numeric reputation where the provider supplies one (0-100 scale).
    score: float | None = None
    score_scale: str = ""
    verdict: str = ""
    tags: list[str] = Field(default_factory=list)
    #: ``hostile`` | ``suspicious`` | ``benign`` | ``unknown``.
    assessment: str = "unknown"
    #: Provider-reported detail kept verbatim for the report.
    detail: dict[str, Any] = Field(default_factory=dict)
    source: SourceRecord = Field(default_factory=SourceRecord)
    error: str = ""
    observed_at: str = Field(default_factory=utc_now_iso)

    @property
    def is_hostile(self) -> bool:
        """``True`` when the provider's data crosses the hostile threshold."""
        return self.assessment == "hostile"

    @property
    def is_suspicious(self) -> bool:
        """``True`` when the provider's data is elevated but not hostile."""
        return self.assessment == "suspicious"

    def summary(self) -> str:
        """One-line human summary."""
        parts = [self.provider, self.subject, self.assessment]
        if self.score is not None:
            parts.append(f"score={self.score:g}{self.score_scale}")
        if self.verdict:
            parts.append(f"verdict={self.verdict}")
        if self.tags:
            parts.append(f"tags={','.join(self.tags[:4])}")
        return " ".join(parts)


class ThreatReport(SchemaVersioned):
    """Threat enrichment result for a set of subjects."""

    target: str = ""
    subjects: list[str] = Field(default_factory=list)
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    #: Providers actually consulted (configured and reachable).
    providers_used: list[str] = Field(default_factory=list)
    #: Providers skipped, with the reason.
    providers_skipped: dict[str, str] = Field(default_factory=dict)
    #: ``False`` when no provider could answer - no verdict is then available.
    available: bool = False
    #: Human explanation of why nothing was assessed, when applicable.
    note: str = ""
    errors: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    observed_at: str = Field(default_factory=utc_now_iso)

    def for_subject(self, subject: str) -> list[ThreatIndicator]:
        """All indicators for one subject."""
        needle = subject.lower()
        return [item for item in self.indicators if item.subject == needle]

    def hostile(self) -> list[ThreatIndicator]:
        """Indicators assessed as hostile."""
        return [item for item in self.indicators if item.is_hostile]

    def suspicious(self) -> list[ThreatIndicator]:
        """Indicators assessed as suspicious."""
        return [item for item in self.indicators if item.is_suspicious]

    def clean(self) -> list[str]:
        """Subjects every consulted provider assessed as benign."""
        assessed = {item.subject for item in self.indicators if item.assessment in ("hostile", "suspicious")}
        return sorted(subject for subject in self.subjects if subject not in assessed)

    def summary(self) -> str:
        """One-line human summary."""
        if not self.available:
            return f"no threat intelligence available ({self.note or 'no provider responded'})"
        return (
            f"{len(self.indicators)} indicator(s) from {', '.join(self.providers_used) or 'none'}; "
            f"{len(self.hostile())} hostile, {len(self.suspicious())} suspicious"
        )

    def observations(self) -> list[dict[str, Any]]:
        """Evidence-backed observations for the rule engine.

        Only provider-reported data becomes an observation, and the wording always
        attributes it to the provider rather than asserting it as fact.
        """
        found: list[dict[str, Any]] = []
        for indicator in self.hostile():
            found.append(
                {
                    "id": "THREAT-HOSTILE",
                    "severity": "HIGH",
                    "target": indicator.subject,
                    "detail": f"{indicator.provider} reports this subject as hostile",
                    "evidence": indicator.summary(),
                    "quality": EvidenceQuality.CORRELATED.value,
                }
            )
        for indicator in self.suspicious():
            found.append(
                {
                    "id": "THREAT-SUSPICIOUS",
                    "severity": "MEDIUM",
                    "target": indicator.subject,
                    "detail": f"{indicator.provider} reports elevated reputation for this subject",
                    "evidence": indicator.summary(),
                    "quality": EvidenceQuality.CORRELATED.value,
                }
            )
        return found


class ThreatIntelligence:
    """Queries configured threat providers and normalizes their verdicts."""

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        *,
        http: Any = None,
        providers: Sequence[str] = (),
        allow_external: bool = True,
        offline: bool = False,
        privacy: bool = False,
    ) -> None:
        self.registry = registry or ProviderRegistry()
        self.http = http
        self.preferred = [str(item).lower() for item in providers if item]
        self.allow_external = allow_external
        self.offline = offline
        self.privacy = privacy

    # ------------------------------------------------------------------ public

    def enrich(self, subjects: Iterable[str], *, target: str = "") -> ThreatReport:
        """Query every usable provider for each subject."""
        import time

        started = time.monotonic()
        report = ThreatReport(target=target)
        report.subjects = sorted(
            {
                (str(item) if is_ip_literal(str(item)) else normalize_hostname(str(item)))
                for item in subjects
                if str(item).strip()
            }
        )
        if not report.subjects:
            report.note = "no subjects supplied"
            return report
        if self.offline:
            report.note = "offline mode: no external reputation lookups were performed"
            return report
        if self.privacy:
            report.note = "privacy mode: target names are not sent to third-party services"
            return report

        usable = self._usable_providers(report)
        if not usable:
            report.note = "no threat provider is configured (set the relevant API key to enable)"
            return report

        for provider in usable:
            context = self._context(provider)
            for subject in report.subjects:
                indicator = self._query(provider, subject, context)
                if indicator.error and not indicator.tags and indicator.score is None:
                    report.errors.append(f"{provider.name}/{subject}: {indicator.error}")
                    continue
                report.indicators.append(indicator)
            if provider.name not in report.providers_used:
                report.providers_used.append(provider.name)

        report.available = bool(report.indicators)
        if not report.available:
            report.note = "consulted providers returned no data for these subjects"
        report.duration_ms = (time.monotonic() - started) * 1000.0
        return report

    def describe(self) -> dict[str, Any]:
        """Provider readiness summary (for ``dnscope doctor``)."""
        candidates = self._candidates()
        return {
            "available": any(provider.is_configured() for provider in candidates),
            "candidates": [
                {
                    "provider": provider.name,
                    "configured": provider.is_configured(),
                    "missing": list(provider.env_vars) if not provider.is_configured() else [],
                }
                for provider in candidates
            ],
            "offline": self.offline,
            "privacy": self.privacy,
        }

    # --------------------------------------------------------------- internals

    def _candidates(self) -> list[Provider]:
        """Providers that can supply threat data."""
        return self.registry.for_capability("threat")

    def _usable_providers(self, report: ThreatReport) -> list[Provider]:
        """Filter to configured, enabled providers and record why others were skipped."""
        usable: list[Provider] = []
        for provider in self._candidates():
            if not provider.is_configured():
                report.providers_skipped[provider.name] = (
                    f"missing credentials ({', '.join(provider.env_vars) or 'none declared'})"
                )
                continue
            if not self.registry.is_enabled(provider.name):
                report.providers_skipped[provider.name] = "disabled by configuration"
                continue
            usable.append(provider)
        if self.preferred:
            order = {name: index for index, name in enumerate(self.preferred)}
            usable.sort(key=lambda item: order.get(item.name, len(order)))
        return usable

    def _context(self, provider: Provider) -> ProviderContext:
        """Provider context for a threat query."""
        return ProviderContext(
            http=self.http or default_client(self.registry),
            offline=self.offline,
            privacy=self.privacy,
            allow_external=self.allow_external,
        )

    def _query(self, provider: Provider, subject: str, context: ProviderContext) -> ThreatIndicator:
        """Query one provider for one subject and normalize the answer."""
        indicator = ThreatIndicator(
            subject=subject,
            provider=provider.name,
            source=SourceRecord(
                provider=provider.name,
                source=provider.name,
                observed_at=now_utc(),
                confidence=Confidence.MEDIUM,
                quality=EvidenceQuality.CORRELATED,
            ),
        )
        if not context.may_call_network:
            indicator.error = "external calls disabled"
            return indicator
        try:
            result = provider.query(subject, context)
        except Exception as exc:
            indicator.error = f"{type(exc).__name__}: {exc}"
            return indicator
        indicator.source = SourceRecord(
            provider=result.source.provider or provider.name,
            source=result.source.source or provider.name,
            observed_at=result.source.observed_at or now_utc(),
            confidence=result.confidence,
            quality=EvidenceQuality.CORRELATED,
        )
        if not result.ok:
            indicator.error = result.error or "provider request failed"
            return indicator
        raw = next(
            (
                item
                for item in result.threat_indicators
                if str(item.get("target", subject)).lower() == subject.lower()
            ),
            result.threat_indicators[0] if result.threat_indicators else None,
        )
        if raw is None:
            indicator.error = "provider returned no indicator for this subject"
            return indicator
        self._apply(indicator, raw)
        return indicator

    def _apply(self, indicator: ThreatIndicator, raw: dict[str, Any]) -> None:
        """Normalize a provider-specific indicator onto the common model."""
        score = _first_number(raw, SCORE_KEYS)
        if score is not None:
            indicator.score = float(score)
            indicator.score_scale = "0-100"
        indicator.verdict = coerce_str(_first_text(raw, VERDICT_KEYS), maximum=64)
        indicator.tags = coerce_str_list(_first_list(raw, TAG_KEYS), maximum=40, item_length=64)
        indicator.detail = {key: value for key, value in raw.items() if key not in ("provider", "target")}
        indicator.assessment = self._assess(indicator)

    def _assess(self, indicator: ThreatIndicator) -> str:
        """Map a normalized indicator onto hostile/suspicious/benign/unknown."""
        verdict = indicator.verdict.lower()
        if verdict in ("malicious", "hostile", "true", "blacklist"):
            return "hostile"
        if verdict in ("benign", "harmless", "false", "riot"):
            return "benign"
        if verdict in ("suspicious", "unknown", "grey"):
            # An explicit "suspicious" beats a missing score.
            return "suspicious" if verdict == "suspicious" else "unknown"
        if indicator.score is None:
            return "unknown"
        if indicator.score >= MALICIOUS_THRESHOLD:
            return "hostile"
        if indicator.score >= SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "benign"


def _first_number(raw: dict[str, Any], keys: Sequence[str]) -> float | None:
    """First numeric value found under any of ``keys``."""
    for key in keys:
        if key in raw:
            value = raw[key]
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value.strip())
                except ValueError:
                    continue
    return None


def _first_text(raw: dict[str, Any], keys: Sequence[str]) -> str:
    """First non-empty string found under any of ``keys``."""
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _first_list(raw: dict[str, Any], keys: Sequence[str]) -> list[Any]:
    """First non-empty list found under any of ``keys``."""
    for key in keys:
        value = raw.get(key)
        if isinstance(value, (list, tuple)) and value:
            return list(value)
        if isinstance(value, dict) and value:
            return [str(item) for item in value]
    return []


__all__ = [
    "MALICIOUS_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "ThreatIndicator",
    "ThreatIntelligence",
    "ThreatReport",
]

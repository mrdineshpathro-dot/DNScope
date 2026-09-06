"""Passive cloud, CDN, WAF and DNS-provider detection.

Detection is purely passive and always records *which* fingerprint matched, so a
report can show ``AWS - evidence: CNAME into amazonaws.com`` rather than an
unexplained label. Nothing here infers ownership: shared infrastructure is
reported as shared infrastructure.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from dnscope.models.assets import AssetKind, CloudProvider
from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned, SourceRecord
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("analyzers.cloud")

#: Default fingerprint directory (shipped with the package).
DEFAULT_FINGERPRINT_DIR = Path(__file__).resolve().parent.parent.parent / "fingerprints"

#: Where a match was observed.
CNAME = "cname"
NS = "ns"
PTR = "ptr"
ASN = "asn"
ORGANIZATION = "organization"
IP_RANGE = "ip_range"
TLS = "tls"
SERVER_HEADER = "server_header"
HEADER = "header"
HTTP = "http"


class FingerprintPattern(BaseModel):
    """One matchable pattern."""

    type: str
    value: str
    confidence: str = "medium"
    evidence: str = ""
    category: str = ""

    def matches(self, candidate: str) -> bool:
        """Return ``True`` when ``candidate`` matches this pattern."""
        text = (candidate or "").strip().lower()
        if not text:
            return False
        needle = self.value.lower()
        if self.type in (ASN,):
            return text == needle or text.upper() == needle.upper()
        if "*" in needle or "?" in needle:
            return fnmatch.fnmatch(text, needle)
        if needle.startswith("."):
            return text.endswith(needle) or text == needle[1:]
        return text.endswith(needle) or needle in text


class ProviderFingerprint(BaseModel):
    """A provider and the patterns that identify it."""

    name: str
    display_name: str = ""
    category: str = "cloud"
    homepage: str = ""
    note: str = ""
    patterns: list[FingerprintPattern] = Field(default_factory=list)


class CloudMatch(SchemaVersioned):
    """A detection result with its evidence."""

    provider: str
    display_name: str = ""
    category: str = "cloud"
    evidence_type: str = CNAME
    evidence: str = ""
    match: str = ""
    confidence: str = Confidence.MEDIUM.value
    quality: str = EvidenceQuality.INFERRED.value
    observed_at: str = Field(default_factory=utc_now_iso)
    source: str = "fingerprint"
    note: str = ""
    #: The hostname/IP the detection applies to.
    subject: str = ""

    def to_asset(self) -> CloudProvider:
        """Convert to a :class:`CloudProvider` asset for the graph."""
        return CloudProvider(
            value=self.provider,
            provider=self.provider,
            category=self.category,
            evidence=[self.evidence],
            evidence_type=self.evidence_type,
            confidence=Confidence.coerce(self.confidence),
            quality=EvidenceQuality.coerce(self.quality),
            match=self.match,
            label=self.display_name or self.provider,
            attributes={"subject": self.subject, "note": self.note},
        )


class FingerprintStore:
    """Loads and caches YAML fingerprint files."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory) if directory else DEFAULT_FINGERPRINT_DIR
        self._cache: dict[str, Any] = {}

    def load(self, filename: str) -> dict[str, Any]:
        """Load a fingerprint file (cached)."""
        if filename in self._cache:
            return self._cache[filename]
        path = self.directory / filename
        data: dict[str, Any] = {}
        if path.is_file():
            try:
                loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            except yaml.YAMLError as exc:
                _log.warning("invalid fingerprint file %s: %s", path, exc)
        else:
            _log.warning("fingerprint file not found: %s", path)
        self._cache[filename] = data
        return data

    def providers(self, filename: str = "cloud.yaml") -> list[ProviderFingerprint]:
        """Provider fingerprints from ``filename``."""
        data = self.load(filename)
        raw = data.get("providers") or []
        return [_to_fingerprint(item) for item in raw if isinstance(item, dict)]

    def sections(self, filename: str, section: str) -> list[ProviderFingerprint]:
        """Fingerprints from a named section of ``filename``."""
        data = self.load(filename)
        raw = data.get(section) or []
        return [_to_fingerprint(item) for item in raw if isinstance(item, dict)]

    def indicators(self, filename: str = "takeover.yaml") -> list[dict[str, Any]]:
        """Dangling-DNS indicator definitions."""
        data = self.load(filename)
        return [item for item in (data.get("indicators") or []) if isinstance(item, dict)]

    def clear(self) -> None:
        """Drop cached files (used after ``dnscope plugins`` updates)."""
        self._cache.clear()


def _to_fingerprint(raw: dict[str, Any]) -> ProviderFingerprint:
    """Build a :class:`ProviderFingerprint` from raw YAML."""
    patterns: list[FingerprintPattern] = []
    for item in raw.get("patterns") or []:
        if not isinstance(item, dict):
            continue
        patterns.append(
            FingerprintPattern(
                type=str(item.get("type", "")).lower(),
                value=str(item.get("value", "")),
                confidence=str(item.get("confidence", "medium")).lower(),
                evidence=str(item.get("evidence", "")),
                category=str(item.get("category", "")),
            )
        )
    return ProviderFingerprint(
        name=str(raw.get("name", "")),
        display_name=str(raw.get("display_name") or raw.get("name", "")),
        category=str(raw.get("category", "cloud")),
        homepage=str(raw.get("homepage", "")),
        note=str(raw.get("note", "")),
        patterns=patterns,
    )


class _Evidence:
    """Bundle of passive observations for one subject."""

    def __init__(
        self,
        subject: str,
        *,
        cnames: Iterable[str] = (),
        nameservers: Iterable[str] = (),
        ptrs: Iterable[str] = (),
        asns: Iterable[str] = (),
        organizations: Iterable[str] = (),
        headers: dict[str, str] | None = None,
        tls_issuers: Iterable[str] = (),
    ) -> None:
        self.subject = subject
        self.cnames = [normalize_hostname(c) for c in cnames if c]
        self.nameservers = [normalize_hostname(n) for n in nameservers if n]
        self.ptrs = [normalize_hostname(p) for p in ptrs if p]
        self.asns = [str(a).upper() for a in asns if a]
        self.organizations = [str(o).lower() for o in organizations if o]
        self.headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
        self.tls_issuers = [normalize_hostname(i) for i in tls_issuers if i]


class CloudDetector:
    """Matches passive observations against provider fingerprints."""

    def __init__(self, store: FingerprintStore | None = None) -> None:
        self.store = store or FingerprintStore()

    # ------------------------------------------------------------------ public

    def detect_cloud(self, evidence: _Evidence | dict[str, Any]) -> list[CloudMatch]:
        """Detect cloud/hosting providers from passive evidence."""
        bundle = self._coerce(evidence)
        fingerprints = self.store.providers("cloud.yaml")
        return self._match(fingerprints, bundle, default_category="cloud")

    def detect_cdn(self, evidence: _Evidence | dict[str, Any]) -> list[CloudMatch]:
        """Detect CDN providers."""
        bundle = self._coerce(evidence)
        return self._match(self.store.sections("infrastructure.yaml", "cdn"), bundle, "cdn")

    def detect_waf(self, evidence: _Evidence | dict[str, Any]) -> list[CloudMatch]:
        """Detect likely WAF/reverse-proxy products (inferred, never tested)."""
        bundle = self._coerce(evidence)
        return self._match(self.store.sections("infrastructure.yaml", "waf"), bundle, "waf")

    def detect_dns_provider(self, evidence: _Evidence | dict[str, Any]) -> list[CloudMatch]:
        """Detect the DNS hosting provider from authoritative nameservers."""
        bundle = self._coerce(evidence)
        return self._match(
            self.store.sections("infrastructure.yaml", "dns_provider"), bundle, "dns"
        )

    def detect_all(self, evidence: _Evidence | dict[str, Any]) -> dict[str, list[CloudMatch]]:
        """Run every detector and return results grouped by category."""
        return {
            "cloud": self.detect_cloud(evidence),
            "cdn": self.detect_cdn(evidence),
            "waf": self.detect_waf(evidence),
            "dns": self.detect_dns_provider(evidence),
        }

    def summarize(self, evidence: _Evidence | dict[str, Any]) -> dict[str, Any]:
        """Canonical summary used in reports and the asset graph."""
        results = self.detect_all(evidence)
        providers: list[dict[str, Any]] = []
        seen: set[str] = set()
        for category, matches in results.items():
            for match in matches:
                key = f"{category}:{match.provider}"
                if key in seen:
                    continue
                seen.add(key)
                providers.append(match.to_dict())
        return {
            "providers": providers,
            "cloud": [m.to_dict() for m in results["cloud"]],
            "cdn": [m.to_dict() for m in results["cdn"]],
            "waf": [m.to_dict() for m in results["waf"]],
            "dns_provider": [m.to_dict() for m in results["dns"]],
            "primary_provider": providers[0]["provider"] if providers else "",
            "primary_category": providers[0]["category"] if providers else "",
            "confidence": providers[0]["confidence"] if providers else Confidence.UNKNOWN.value,
            "quality": EvidenceQuality.INFERRED.value,
        }

    # ----------------------------------------------------------------- internals

    def _match(
        self,
        fingerprints: list[ProviderFingerprint],
        bundle: _Evidence,
        default_category: str,
    ) -> list[CloudMatch]:
        """Return the best match per provider."""
        matches: dict[str, CloudMatch] = {}
        for fingerprint in fingerprints:
            for pattern in fingerprint.patterns:
                observed = self._observed_value(pattern.type, bundle)
                hit = next((value for value in observed if pattern.matches(value)), None)
                if hit is None:
                    continue
                confidence = pattern.confidence or "medium"
                if pattern.type in (ORGANIZATION, SERVER_HEADER, HEADER, TLS):
                    # Textual heuristics are weaker than structural matches.
                    confidence = _weaken(confidence)
                existing = matches.get(fingerprint.name)
                if existing is not None and _rank(existing.confidence) >= _rank(confidence):
                    continue
                matches[fingerprint.name] = CloudMatch(
                    provider=fingerprint.name,
                    display_name=fingerprint.display_name,
                    category=pattern.category or fingerprint.category or default_category,
                    evidence_type=pattern.type,
                    evidence=pattern.evidence or f"{pattern.type} matched {pattern.value}",
                    match=hit,
                    confidence=confidence,
                    quality=EvidenceQuality.INFERRED.value,
                    source="fingerprint",
                    subject=bundle.subject,
                    note=fingerprint.note,
                )
        return sorted(matches.values(), key=lambda item: (-_rank(item.confidence), item.provider))

    def _observed_value(self, pattern_type: str, bundle: _Evidence) -> list[str]:
        """Values to test for a given pattern type."""
        return {
            CNAME: bundle.cnames,
            NS: bundle.nameservers,
            PTR: bundle.ptrs,
            ASN: bundle.asns,
            ORGANIZATION: bundle.organizations,
            SERVER_HEADER: [bundle.headers.get("server", "")],
            HEADER: [
                f"{key}={value}" for key, value in bundle.headers.items()
            ],
            TLS: bundle.tls_issuers,
            HTTP: [],
        }.get(pattern_type, [])

    def _coerce(self, evidence: _Evidence | dict[str, Any]) -> _Evidence:
        """Accept either an :class:`_Evidence` bundle or a plain mapping."""
        if isinstance(evidence, _Evidence):
            return evidence
        data = evidence or {}
        return _Evidence(
            str(data.get("subject", "")),
            cnames=data.get("cnames", []) or [],
            nameservers=data.get("nameservers", []) or [],
            ptrs=data.get("ptrs", []) or [],
            asns=data.get("asns", []) or [],
            organizations=data.get("organizations", []) or [],
            headers=data.get("headers") or {},
            tls_issuers=data.get("tls_issuers", []) or [],
        )


def _rank(confidence: str) -> int:
    """Numeric rank so the strongest match wins."""
    return {"high": 3, "medium": 2, "low": 1}.get(str(confidence).lower(), 0)


def _weaken(confidence: str) -> str:
    """Drop a confidence level for weaker evidence types."""
    return {"high": "medium", "medium": "low", "low": "low"}.get(str(confidence).lower(), "low")


def evidence_bundle(
    subject: str,
    *,
    cnames: Iterable[str] = (),
    nameservers: Iterable[str] = (),
    ptrs: Iterable[str] = (),
    asns: Iterable[str] = (),
    organizations: Iterable[str] = (),
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the plain-mapping form accepted by :class:`CloudDetector`."""
    return {
        "subject": subject,
        "cnames": list(cnames),
        "nameservers": list(nameservers),
        "ptrs": list(ptrs),
        "asns": list(asns),
        "organizations": list(organizations),
        "headers": headers or {},
    }


def source_record(provider: str = "fingerprint", detail: str = "") -> SourceRecord:
    """Attribution record for fingerprint-based detections."""
    return SourceRecord(
        provider=provider,
        source=detail or "fingerprints/cloud.yaml",
        confidence=Confidence.MEDIUM,
        quality=EvidenceQuality.INFERRED,
    )


__all__ = [
    "ASN",
    "CNAME",
    "DEFAULT_FINGERPRINT_DIR",
    "HEADER",
    "HTTP",
    "IP_RANGE",
    "NS",
    "ORGANIZATION",
    "PTR",
    "SERVER_HEADER",
    "TLS",
    "CloudDetector",
    "CloudMatch",
    "FingerprintPattern",
    "FingerprintStore",
    "ProviderFingerprint",
    "evidence_bundle",
    "source_record",
]

#: Re-exported so callers can build bundles without importing the private class.
Evidence = _Evidence
AssetKind  # noqa: B018 - re-export for callers importing from this module

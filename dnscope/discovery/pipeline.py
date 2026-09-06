"""Discovery pipeline.

Orchestrates sources, validation, DNS confirmation, state assignment and
confidence scoring. Everything is bounded: sources run with limited concurrency,
the candidate list is capped, and DNS confirmation reuses the engine's rate
limiter so a large domain cannot turn into a flood of queries.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import BaseModel, Field

from dnscope.analyzers.takeover import TakeoverAnalyzer
from dnscope.core.scope import Scope
from dnscope.discovery.confidence import ConfidenceScorer
from dnscope.discovery.sources import DiscoverySource, SourceStatus
from dnscope.discovery.state_machine import SubdomainState, SubdomainStateMachine
from dnscope.discovery.validation import HostValidator
from dnscope.dns.engine import DNSEngine
from dnscope.models.common import Confidence, SchemaVersioned
from dnscope.utils.async_utils import BoundedGatherer, GatherError, run_async
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("discovery.pipeline")


class DiscoveredHost(BaseModel):
    """One validated discovery result."""

    hostname: str
    sources: list[str] = Field(default_factory=list)
    state: str = SubdomainState.DISCOVERED
    confidence: str = Confidence.LOW.value
    confidence_score: float = 0.0
    ips: list[str] = Field(default_factory=list)
    cname_target: str = ""
    rcode: str = ""
    ttl: int | None = None
    wildcard_match: bool = False
    out_of_scope: bool = False
    dangling_candidate: bool = False
    dangling_provider: str = ""
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)
    notes: list[str] = Field(default_factory=list)

    @property
    def is_active(self) -> bool:
        """``True`` when the host currently resolves."""
        return self.state in SubdomainState.LIVE

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return self.model_dump(mode="json")


class DiscoveryResult(SchemaVersioned):
    """Aggregate discovery output."""

    target: str
    hosts: list[DiscoveredHost] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    validation: dict[str, Any] = Field(default_factory=dict)
    wildcard: dict[str, Any] = Field(default_factory=dict)
    total_candidates: int = 0
    accepted: int = 0
    active: int = 0
    dangling: int = 0
    duration_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)

    def hostnames(self) -> list[str]:
        """All accepted hostnames."""
        return [host.hostname for host in self.hosts]

    def active_hostnames(self) -> list[str]:
        """Hostnames that currently resolve."""
        return [host.hostname for host in self.hosts if host.is_active]

    def by_confidence(self, level: str) -> list[DiscoveredHost]:
        """Hosts at a given confidence level."""
        return [host for host in self.hosts if host.confidence == level.upper()]

    def summary(self) -> str:
        """One-line summary."""
        return (
            f"{self.accepted} host(s) discovered for {self.target} "
            f"({self.active} active, {self.dangling} dangling candidate(s)) "
            f"in {self.duration_ms / 1000:.2f}s"
        )


class DiscoveryPipeline:
    """Runs discovery sources and produces validated results."""

    def __init__(
        self,
        engine: DNSEngine | None,
        sources: Sequence[DiscoverySource],
        *,
        scope: Scope | None = None,
        validate_dns: bool = True,
        filter_wildcards: bool = True,
        max_results: int = 5_000,
        concurrency: int = 8,
        rate_limit: float = 0.0,
        takeover: TakeoverAnalyzer | None = None,
        check_takeover: bool = True,
    ) -> None:
        self.engine = engine
        self.sources = list(sources)
        self.scope = scope
        self.validate_dns = validate_dns
        self.filter_wildcards = filter_wildcards
        self.max_results = max(1, max_results)
        self.concurrency = max(1, concurrency)
        self.rate_limit = rate_limit
        self.takeover = takeover
        self.check_takeover = check_takeover
        self.scorer = ConfidenceScorer()
        self.state_machine = SubdomainStateMachine()

    # -------------------------------------------------------------------- run

    def run(self, domain: str) -> DiscoveryResult:
        """Execute the full discovery pipeline for ``domain``."""
        started = time.monotonic()
        result = DiscoveryResult(target=domain)
        if not self.sources:
            result.errors.append("no discovery sources configured")
            return result

        # 1. collect candidates from every source
        candidates, statuses = self._collect(domain)
        result.sources = [status.to_dict() for status in statuses]
        result.total_candidates = len(candidates)
        result.errors.extend(status.error for status in statuses if status.error)

        # 2. detect wildcard responses so artifacts can be filtered
        wildcard_addresses: set[str] = set()
        if self.filter_wildcards and self.engine is not None:
            info = self.engine.detect_wildcard(domain)
            wildcard_addresses = set(info.addresses) if info.wildcard else set()
            result.wildcard = {
                "wildcard": info.wildcard,
                "addresses": info.addresses,
                "confidence": info.confidence,
                "evidence": info.evidence,
                "probes": info.probe_names,
            }

        # 3. validate, normalize, scope-filter and de-duplicate
        validator = HostValidator(self.scope, wildcard_addresses=wildcard_addresses, allow_ip=False)
        accepted = validator.process(candidates)[: self.max_results]
        if len(accepted) < len(candidates):
            validator.summary.record_invalid_overflow(len(candidates) - len(accepted))
        result.validation = validator.summary.to_dict()

        # 4. merge source attribution per host
        provenance = self._merge_provenance(candidates, statuses)

        # 5. confirm by DNS (bounded) and assign state + confidence
        resolved = self._resolve(accepted) if self.validate_dns else {}
        result.hosts = self._build_hosts(accepted, provenance, resolved, wildcard_addresses)
        result.accepted = len(result.hosts)
        result.active = sum(1 for host in result.hosts if host.is_active)
        result.dangling = sum(1 for host in result.hosts if host.dangling_candidate)
        result.duration_ms = (time.monotonic() - started) * 1000.0
        return result

    # ---------------------------------------------------------------- internals

    def _collect(self, domain: str) -> tuple[list[str], list[SourceStatus]]:
        """Run every source concurrently and merge raw candidates."""
        enabled = [source for source in self.sources if source.enabled]
        disabled = [source for source in self.sources if not source.enabled]
        statuses: list[SourceStatus] = []

        gatherer = BoundedGatherer(concurrency=min(self.concurrency, max(1, len(enabled))), name="discovery")
        if enabled:
            # map() calls its function with a single argument, so the domain has
            # to be bound here rather than passed as a second parameter.
            outcomes = run_async(gatherer.map(lambda source: self._run_source(source, domain), enabled))
            for outcome in outcomes:
                if isinstance(outcome, GatherError):
                    statuses.append(
                        SourceStatus(source="unknown", ok=False, error=f"source crashed: {outcome.message}")
                    )
                else:
                    statuses.append(outcome)
        for source in disabled:
            status = source.discover(domain)
            statuses.append(status)

        candidates: list[str] = []
        seen: set[str] = set()
        for status in statuses:
            for hostname in status.hostnames:
                normalized = normalize_hostname(hostname)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    candidates.append(normalized)
        return candidates, statuses

    def _run_source(self, source: DiscoverySource, domain: str) -> SourceStatus:
        """Run one source, converting crashes into a failure status."""
        try:
            return source.discover(domain)
        except Exception as exc:
            _log.warning("discovery source %s failed: %s", source.name, exc)
            status = SourceStatus(source=source.name, kind=source.kind, ok=False, error=str(exc))
            return status

    def _merge_provenance(
        self, candidates: Iterable[str], statuses: Sequence[SourceStatus]
    ) -> dict[str, list[str]]:
        """Map each candidate hostname to the sources that reported it."""
        provenance: dict[str, list[str]] = {}
        for status in statuses:
            for hostname in status.hostnames:
                normalized = normalize_hostname(hostname)
                if not normalized:
                    continue
                provenance.setdefault(normalized, [])
                if status.source not in provenance[normalized]:
                    provenance[normalized].append(status.source)
        return provenance

    def _resolve(self, hostnames: Sequence[str]) -> dict[str, dict[str, Any]]:
        """Resolve hostnames with bounded concurrency."""
        engine = self.engine
        if engine is None:
            return {}
        gatherer = BoundedGatherer(concurrency=self.concurrency, rate=self.rate_limit, name="discovery-dns")

        def _work(hostname: str) -> tuple[str, dict[str, Any]]:
            a_result = engine.query(hostname, "A")
            cname_result = engine.query(hostname, "CNAME") if not a_result.answer_count else None
            info: dict[str, Any] = {
                "status": a_result.status,
                "ips": sorted(a_result.rdata_set()),
                "ttl": a_result.min_ttl(),
                "cname": "",
                "nxdomain": a_result.nxdomain,
                "timeout": a_result.status == "TIMEOUT",
            }
            if cname_result is not None and cname_result.ok and cname_result.records:
                info["cname"] = str((cname_result.records[0].parsed or {}).get("target", ""))
            elif a_result.cname_chain:
                info["cname"] = a_result.cname_chain[-1]
            return hostname, info

        outcomes = run_async(gatherer.map(_work, hostnames))
        resolved: dict[str, dict[str, Any]] = {}
        for outcome in outcomes:
            if isinstance(outcome, GatherError):
                _log.debug("discovery resolution failure: %s", outcome.message)
                continue
            hostname, info = outcome
            resolved[hostname] = info
        return resolved

    def _build_hosts(
        self,
        hostnames: Sequence[str],
        provenance: dict[str, list[str]],
        resolved: dict[str, dict[str, Any]],
        wildcard_addresses: set[str],
    ) -> list[DiscoveredHost]:
        """Attach state, confidence and takeover indicators to each host."""
        hosts: list[DiscoveredHost] = []
        for hostname in hostnames:
            sources = provenance.get(hostname, [])
            info = resolved.get(hostname, {})
            ips = list(info.get("ips") or [])
            cname = str(info.get("cname") or "")
            nxdomain = bool(info.get("nxdomain"))
            timeout = bool(info.get("timeout"))
            wildcard_match = bool(ips and wildcard_addresses and set(ips) == wildcard_addresses)

            cname_unresolved = False
            dangling_provider = ""
            if cname and not ips and self.check_takeover and self.takeover is not None:
                indicator = self.takeover.analyze(hostname, cname)
                if indicator.is_dangling:
                    cname_unresolved = True
                    dangling_provider = indicator.provider

            state = self.state_machine.classify(
                nxdomain=nxdomain,
                has_addresses=bool(ips),
                has_cname=bool(cname),
                cname_unresolved=cname_unresolved,
                timeout=timeout,
                dangling=bool(dangling_provider),
            )
            source_list = list(sources)
            if self.validate_dns and ips and "dns" not in source_list:
                source_list.append("dns")
            factors = self.scorer.factors(
                source_list,
                resolves=bool(ips),
                wildcard_match=wildcard_match,
                cname_only=bool(cname and not ips),
                nxdomain=nxdomain,
            )
            confidence = self.scorer.level(factors)
            host = DiscoveredHost(
                hostname=hostname,
                sources=source_list,
                state=state,
                confidence=confidence.value,
                confidence_score=factors.score,
                ips=ips,
                cname_target=cname,
                rcode=str(info.get("status") or ""),
                ttl=info.get("ttl"),
                wildcard_match=wildcard_match,
                dangling_candidate=bool(dangling_provider),
                dangling_provider=dangling_provider,
            )
            if wildcard_match:
                host.notes.append("addresses match the zone wildcard; treated as an artifact")
            if not sources:
                host.notes.append("confirmed by DNS only (no passive source reported it)")
            hosts.append(host)
        hosts.sort(key=lambda item: (not item.is_active, item.hostname))
        return hosts


__all__ = [
    "DiscoveredHost",
    "DiscoveryPipeline",
    "DiscoveryResult",
    "DiscoverySource",
    "SourceStatus",
]

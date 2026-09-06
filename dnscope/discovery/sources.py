"""Pluggable subdomain discovery sources.

Every source returns raw candidate hostnames plus a status; validation, scope
filtering and confidence scoring happen later in the pipeline so a new source
only has to answer one question: *which names have you seen?*
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field

from dnscope.dns.engine import DNSEngine
from dnscope.models.common import SchemaVersioned
from dnscope.providers.base import ProviderContext
from dnscope.providers.registry import ProviderRegistry
from dnscope.security.validators import coerce_str_list
from dnscope.utils.domains import normalize_hostname
from dnscope.utils.logging import get_logger

_log = get_logger("discovery.sources")

#: Source kinds.
PASSIVE = "passive"
ACTIVE = "active"

#: Built-in wordlist used by ``--wordlist`` without an external file. Kept small
#: and boring on purpose: DNScope is not a brute-forcing tool, and large
#: wordlists are the operator's choice, not the default.
BUILTIN_WORDLIST: tuple[str, ...] = (
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "ftp",
    "api",
    "dev",
    "test",
    "staging",
    "stage",
    "uat",
    "qa",
    "beta",
    "admin",
    "portal",
    "intranet",
    "extranet",
    "vpn",
    "remote",
    "auth",
    "sso",
    "login",
    "id",
    "identity",
    "app",
    "apps",
    "assets",
    "static",
    "cdn",
    "media",
    "images",
    "docs",
    "help",
    "support",
    "status",
    "blog",
    "shop",
    "store",
    "pay",
    "payment",
    "checkout",
    "billing",
    "account",
    "dashboard",
    "console",
    "monitor",
    "metrics",
    "grafana",
    "kibana",
    "jenkins",
    "git",
    "gitlab",
    "github",
    "ci",
    "build",
    "deploy",
    "registry",
    "docker",
    "k8s",
    "kube",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "elastic",
    "search",
    "cache",
    "queue",
    "backup",
    "old",
    "new",
    "legacy",
    "v1",
    "v2",
    "ns1",
    "ns2",
    "mx",
    "mx1",
    "mx2",
    "spf",
    "dmarc",
)

#: Prefixes/suffixes used by the bounded permutation source.
PERMUTATION_PREFIXES = ("dev-", "test-", "stage-", "staging-", "qa-", "beta-", "pre-", "int-", "uat-")
PERMUTATION_SUFFIXES = ("-dev", "-test", "-staging", "-qa", "-beta", "-int", "-uat", "1", "2")


class SourceStatus(SchemaVersioned):
    """Outcome of running one discovery source."""

    source: str
    kind: str = PASSIVE
    ok: bool = True
    enabled: bool = True
    hostnames: list[str] = Field(default_factory=list)
    count: int = 0
    duration_ms: float = 0.0
    error: str = ""
    skipped_reason: str = ""
    notes: list[str] = Field(default_factory=list)

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        """JSON-ready summary (hostnames excluded to keep reports small)."""
        return {
            "source": self.source,
            "kind": self.kind,
            "ok": self.ok,
            "enabled": self.enabled,
            "count": self.count,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "skipped_reason": self.skipped_reason,
            "notes": self.notes,
        }


class DiscoverySource(abc.ABC):
    """Base class for discovery sources."""

    name: str = "source"
    kind: str = PASSIVE
    #: ``True`` when the source requires credentials or explicit enablement.
    requires_credentials: bool = False

    def __init__(self, *, enabled: bool = True, limit: int = 2_000) -> None:
        self.enabled = enabled
        self.limit = max(1, limit)

    @abc.abstractmethod
    def discover(self, domain: str) -> SourceStatus:
        """Return candidate hostnames for ``domain``."""

    def _status(self) -> SourceStatus:
        """Create an empty status object."""
        return SourceStatus(source=self.name, kind=self.kind, enabled=self.enabled)

    def _finalize(self, status: SourceStatus, hostnames: Iterable[str]) -> SourceStatus:
        """Normalize and cap the hostname list."""
        unique: list[str] = []
        seen: set[str] = set()
        for hostname in hostnames:
            normalized = normalize_hostname(hostname)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            unique.append(normalized)
            if len(unique) >= self.limit:
                status.notes.append(f"result capped at {self.limit} hostnames")
                break
        status.hostnames = unique
        status.count = len(unique)
        return status


class CertificateTransparencySource(DiscoverySource):
    """Hostname discovery from Certificate Transparency logs via crt.sh."""

    name = "ct"
    kind = PASSIVE

    def __init__(self, registry: ProviderRegistry | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.registry = registry or ProviderRegistry()

    def discover(self, domain: str) -> SourceStatus:
        """Query crt.sh for certificates covering ``domain``."""
        status = self._status()
        provider = self.registry.get("crt.sh")
        if provider is None:
            status.ok = False
            status.error = "crt.sh provider is not registered"
            return status
        if not self.registry.is_enabled(provider.name):
            status.skipped_reason = "provider disabled or offline mode active"
            return status

        import time

        started = time.monotonic()
        context = ProviderContext(http=_default_client(self.registry), offline=False)
        try:
            result = provider.query(domain, context)
        except Exception as exc:
            status.ok = False
            status.error = str(exc)
            status.duration_ms = (time.monotonic() - started) * 1000.0
            return status
        status.duration_ms = (time.monotonic() - started) * 1000.0
        if not result.ok:
            status.ok = False
            status.error = result.error
        status.notes.append(f"{result.raw_count} certificate rows received")
        return self._finalize(status, result.hostnames)


class ProviderDiscoverySource(DiscoverySource):
    """Generic source backed by any provider with the ``subdomains`` capability."""

    kind = PASSIVE
    requires_credentials = True

    def __init__(
        self,
        provider_name: str,
        registry: ProviderRegistry | None = None,
        *,
        http: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.provider_name = provider_name
        self.name = provider_name
        self.registry = registry or ProviderRegistry()
        self.http = http

    def discover(self, domain: str) -> SourceStatus:
        """Query the wrapped provider."""
        status = self._status()
        provider = self.registry.get(self.provider_name)
        if provider is None:
            status.ok = False
            status.error = f"provider {self.provider_name} is not registered"
            return status
        if not provider.is_configured():
            status.enabled = False
            status.skipped_reason = f"missing credentials ({', '.join(provider.env_vars)})"
            return status
        if not self.registry.is_enabled(provider.name):
            status.skipped_reason = "provider disabled or offline mode active"
            return status

        import time

        started = time.monotonic()
        context = ProviderContext(http=self.http or _default_client(self.registry))
        try:
            result = provider.query(domain, context)
        except Exception as exc:
            status.ok = False
            status.error = str(exc)
            status.duration_ms = (time.monotonic() - started) * 1000.0
            return status
        status.duration_ms = (time.monotonic() - started) * 1000.0
        if not result.ok:
            status.ok = False
            status.error = result.error
        return self._finalize(status, result.hostnames)


class PassiveDNSSource(DiscoverySource):
    """Passive DNS hostnames from a credentialed provider (OTX by default)."""

    name = "passive-dns"
    kind = PASSIVE
    requires_credentials = True

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        *,
        provider_name: str = "otx",
        http: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.provider_name = provider_name
        self.registry = registry or ProviderRegistry()
        self.http = http

    def discover(self, domain: str) -> SourceStatus:
        """Query the passive-DNS provider."""
        status = self._status()
        provider = self.registry.get(self.provider_name)
        if provider is None:
            status.ok = False
            status.error = f"provider {self.provider_name} is not registered"
            return status
        if not provider.is_configured():
            status.enabled = False
            status.skipped_reason = f"missing credentials ({', '.join(provider.env_vars)})"
            return status

        context = ProviderContext(http=self.http or _default_client(self.registry))
        try:
            result = provider.query(domain, context)
        except Exception as exc:
            status.ok = False
            status.error = str(exc)
            return status
        if not result.ok:
            status.ok = False
            status.error = result.error
        names = list(result.hostnames)
        for entry in result.history:
            hostname = str(entry.get("hostname", ""))
            if hostname:
                names.append(hostname)
        return self._finalize(status, names)


class WordlistSource(DiscoverySource):
    """Candidate generation from a wordlist file (or the built-in list)."""

    name = "wordlist"
    kind = ACTIVE

    def __init__(self, path: str | Path | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.path = Path(path).expanduser() if path else None

    def discover(self, domain: str) -> SourceStatus:
        """Generate ``label.domain`` candidates."""
        status = self._status()
        words = self._load_words(status)
        return self._finalize(status, (f"{word}.{domain}" for word in words))

    def _load_words(self, status: SourceStatus) -> list[str]:
        """Read the wordlist, falling back to the built-in list."""
        if self.path is None:
            status.notes.append("using the built-in wordlist")
            return list(BUILTIN_WORDLIST)[: self.limit]
        if not self.path.is_file():
            status.ok = False
            status.error = f"wordlist not found: {self.path}"
            return []
        words: list[str] = []
        try:
            with open(self.path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    words.append(normalize_hostname(text.split(".")[0]))
                    if len(words) >= self.limit:
                        status.notes.append(f"wordlist truncated at {self.limit} entries")
                        break
        except OSError as exc:
            status.ok = False
            status.error = f"cannot read wordlist: {exc}"
        return [word for word in words if word]


class DNSBruteforceSource(DiscoverySource):
    """Resolve a bounded wordlist against the live resolver.

    This is an *active* source: it sends DNS queries. It is disabled unless the
    operator asks for it, and the query count is bounded by ``limit`` and the
    engine's rate limiter.
    """

    name = "dns"
    kind = ACTIVE

    def __init__(
        self, engine: DNSEngine | None, *, labels: Sequence[str] | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.engine = engine
        self.labels = list(labels or BUILTIN_WORDLIST)

    def discover(self, domain: str) -> SourceStatus:
        """Resolve each candidate and keep those that answer."""
        status = self._status()
        if self.engine is None:
            status.ok = False
            status.error = "no DNS engine available"
            return status

        import time

        started = time.monotonic()
        candidates = [f"{label}.{domain}" for label in self.labels[: self.limit]]
        resolved: list[str] = []
        for candidate in candidates:
            result = self.engine.query(candidate, "A")
            if (result.ok and result.answer_count) or (result.ok and result.cname_chain):
                resolved.append(candidate)
            elif not result.ok and result.status not in ("NXDOMAIN", "ERROR", "TIMEOUT"):
                status.notes.append(f"{candidate}: {result.status}")
        status.duration_ms = (time.monotonic() - started) * 1000.0
        status.notes.append(f"resolved {len(resolved)}/{len(candidates)} candidates")
        return self._finalize(status, resolved)


class PermutationSource(DiscoverySource):
    """Bounded name permutations (prefixes/suffixes of known labels)."""

    name = "permutation"
    kind = ACTIVE

    def discover(self, domain: str) -> SourceStatus:
        """Generate permutations of the apex label."""
        status = self._status()
        base = domain.split(".", 1)[0]
        candidates: set[str] = set()
        for prefix in PERMUTATION_PREFIXES:
            candidates.add(f"{prefix}{base}.{domain}")
        for suffix in PERMUTATION_SUFFIXES:
            candidates.add(f"{base}{suffix}.{domain}")
        status.notes.append(f"{len(candidates)} permutations generated")
        return self._finalize(status, sorted(candidates))


def _default_client(registry: ProviderRegistry) -> Any:
    """Build the shared HTTP client used by provider-backed sources."""
    from dnscope.providers.http import default_client

    return default_client(registry)


def default_sources(
    engine: DNSEngine | None,
    registry: ProviderRegistry,
    *,
    names: Iterable[str],
    limit: int = 2_000,
    wordlist_path: str | None = None,
    http: Any = None,
) -> list[DiscoverySource]:
    """Instantiate the sources requested by name.

    Unknown names are ignored (and reported by the pipeline) so a typo in a
    profile cannot silently disable discovery.
    """
    wanted = {str(name).lower() for name in names}
    sources: list[DiscoverySource] = []
    if "ct" in wanted:
        sources.append(CertificateTransparencySource(registry, limit=limit))
    if "rdap" in wanted:
        sources.append(ProviderDiscoverySource("rdap", registry, http=http, limit=limit))
    if "passive-dns" in wanted or "otx" in wanted:
        sources.append(PassiveDNSSource(registry, http=http, limit=limit))
    if "virustotal" in wanted:
        sources.append(ProviderDiscoverySource("virustotal", registry, http=http, limit=limit))
    if "securitytrails" in wanted:
        sources.append(ProviderDiscoverySource("securitytrails", registry, http=http, limit=limit))
    if "urlscan" in wanted:
        sources.append(ProviderDiscoverySource("urlscan", registry, http=http, limit=limit))
    if "hackertarget" in wanted:
        sources.append(ProviderDiscoverySource("hackertarget", registry, http=http, limit=limit))
    if "wordlist" in wanted:
        sources.append(WordlistSource(wordlist_path, limit=limit))
    if "dns" in wanted:
        sources.append(DNSBruteforceSource(engine, limit=limit))
    if "permutation" in wanted:
        sources.append(PermutationSource(limit=limit))
    return sources


__all__ = [
    "ACTIVE",
    "BUILTIN_WORDLIST",
    "PASSIVE",
    "CertificateTransparencySource",
    "DNSBruteforceSource",
    "DiscoverySource",
    "PassiveDNSSource",
    "PermutationSource",
    "ProviderDiscoverySource",
    "SourceStatus",
    "WordlistSource",
    "coerce_str_list",
    "default_sources",
]

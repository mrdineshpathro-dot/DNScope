"""Provider registry: discovery, credential resolution and capability matrix."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from dnscope.models.providers import ProviderHealth, ProviderInfo, ProviderStatus
from dnscope.providers.base import Provider
from dnscope.providers.ct_crtsh import CrtShProvider
from dnscope.providers.discovery_api import OTXProvider, SecurityTrailsProvider, URLScanProvider
from dnscope.providers.keyless import CymruASNProvider, HackerTargetProvider, RdapProvider
from dnscope.providers.threat import (
    AbuseIPDBProvider,
    CensysProvider,
    GreyNoiseProvider,
    ShodanProvider,
    VirusTotalProvider,
)
from dnscope.security.secrets import SecretStore
from dnscope.utils.logging import get_logger

_log = get_logger("providers.registry")


def builtin_provider_classes() -> list[type[Provider]]:
    """Every provider DNScope ships with."""
    return [
        CrtShProvider,
        RdapProvider,
        CymruASNProvider,
        HackerTargetProvider,
        VirusTotalProvider,
        SecurityTrailsProvider,
        OTXProvider,
        URLScanProvider,
        ShodanProvider,
        CensysProvider,
        AbuseIPDBProvider,
        GreyNoiseProvider,
    ]


class ProviderRegistry:
    """Instantiates providers and resolves their credentials.

    Credentials come from the environment or the configured secret store and are
    never stored in the configuration object, so ``config validate`` and reports
    cannot leak them.
    """

    def __init__(
        self,
        *,
        settings: Any = None,
        secrets: SecretStore | None = None,
        offline: bool = False,
        enabled_only: bool = False,
    ) -> None:
        self.settings = settings
        self.secrets = secrets or SecretStore()
        self.offline = offline
        self._providers: dict[str, Provider] = {}
        self._plugins: list[Provider] = []
        self._load_builtins()
        if enabled_only:
            self._apply_filters()

    # ------------------------------------------------------------------ setup

    def _load_builtins(self) -> None:
        for cls in builtin_provider_classes():
            provider = self._instantiate(cls)
            self._providers[provider.name.lower()] = provider

    def _instantiate(self, cls: type[Provider]) -> Provider:
        """Create a provider, injecting credentials from the secret store."""
        kwargs: dict[str, Any] = {"settings": self.settings}
        env_names = list(getattr(cls, "env_vars", ()))
        if cls.__name__ == "CensysProvider":
            kwargs["api_key"] = self.secrets.get("CENSYS_API_ID")
            kwargs["api_secret"] = self.secrets.get("CENSYS_API_SECRET")
        elif env_names:
            kwargs["api_key"] = self.secrets.get(env_names[0])
        else:
            kwargs["api_key"] = ""
        return cls(**kwargs)

    def register(self, provider: Provider, *, source: str = "plugin") -> None:
        """Register an externally supplied provider (plugin framework)."""
        provider.log = get_logger(f"providers.{provider.name}")
        self._providers[provider.name.lower()] = provider
        self._plugins.append(provider)
        _log.info("registered %s provider %s", source, provider.name)

    def _apply_filters(self) -> None:
        """Honour ``providers.only`` / ``providers.disabled`` from the config."""
        only = {name.lower() for name in getattr(self.settings, "only", []) or []}
        disabled = {name.lower() for name in getattr(self.settings, "disabled", []) or []}
        if not only and not disabled:
            return
        for name, provider in self._providers.items():
            keep = (not only or name in only) and name not in disabled
            if not keep:
                self._providers[name] = provider  # kept, marked disabled in info()
        self._only = only
        self._disabled = disabled

    # ------------------------------------------------------------------ query

    def get(self, name: str) -> Provider | None:
        """Return a provider by name (case-insensitive)."""
        return self._providers.get(name.lower())

    def all(self) -> list[Provider]:
        """All registered providers, built-ins first."""
        return list(self._providers.values())

    def names(self) -> list[str]:
        """Registered provider names."""
        return sorted(self._providers)

    def for_capability(self, capability: str) -> list[Provider]:
        """Providers that implement ``capability``."""
        return [p for p in self._providers.values() if p.supports(capability)]

    def configured(self) -> list[Provider]:
        """Providers whose credentials are present."""
        return [p for p in self._providers.values() if p.is_configured()]

    def usable(self) -> list[Provider]:
        """Providers that can run right now (configured, enabled, not offline)."""
        return [p for p in self.configured() if self.is_enabled(p.name)]

    def is_enabled(self, name: str) -> bool:
        """``False`` when the provider is disabled by config or offline mode."""
        lowered = name.lower()
        if lowered in {n.lower() for n in getattr(self.settings, "disabled", []) or []}:
            return False
        only = [n.lower() for n in getattr(self.settings, "only", []) or []]
        if only and lowered not in only:
            return False
        if self.offline:
            # Keyless DNS-based providers still work offline (no HTTP egress).
            provider = self.get(lowered)
            return provider is not None and provider.name == "team-cymru"
        return getattr(self.settings, "enabled", True) is not False

    def infos(self) -> list[ProviderInfo]:
        """Static info + runtime status for every provider."""
        rows: list[ProviderInfo] = []
        for provider in self._providers.values():
            info = provider.info()
            info.status, info.status_reason = self.status_for(provider)
            info.enabled = self.is_enabled(provider.name)
            rows.append(info)
        return rows

    def status_for(self, provider: Provider) -> tuple[str, str]:
        """Compute the display status for ``provider``."""
        if not self.is_enabled(provider.name):
            if self.offline:
                return ProviderStatus.OFFLINE_MODE, "offline mode: external providers disabled"
            return ProviderStatus.DISABLED, "disabled in configuration"
        if provider.requires_credentials and not provider.is_configured():
            missing = ", ".join(provider.env_vars) or "credentials"
            return ProviderStatus.NOT_CONFIGURED, f"missing {missing}"
        return ProviderStatus.READY, "ready"

    def health_checks(self) -> dict[str, ProviderHealth]:
        """Run :meth:`Provider.health_check` for every provider."""
        return {
            name: provider.health_check()
            for name, provider in sorted(self._providers.items())
        }

    def capability_matrix(self) -> list[dict[str, str]]:
        """Rows for the ``dnscope providers`` table.

        Capabilities come from each provider's declared flags, so the matrix can
        never claim something a provider does not implement.
        """
        rows: list[dict[str, str]] = []
        for info in self.infos():
            capabilities = info.capabilities
            rows.append(
                {
                    "provider": info.name,
                    "dns": "yes" if capabilities.dns else "-",
                    "ip": "yes" if capabilities.ip else "-",
                    "ct": "yes" if capabilities.ct else "-",
                    "threat": "yes" if capabilities.threat else "-",
                    "history": "yes" if capabilities.history else "-",
                    "subdomains": "yes" if capabilities.subdomains else "-",
                    "credentials": "required" if info.requires_credentials else "none",
                    "status": info.status,
                    "detail": info.status_reason,
                }
            )
        return rows

    def missing_credentials(self) -> list[str]:
        """Environment variables that would enable more providers."""
        missing: list[str] = []
        for provider in self._providers.values():
            if not provider.requires_credentials or provider.is_configured():
                continue
            for name in provider.env_vars:
                if name not in missing:
                    missing.append(name)
        return missing

    def select(self, names: Iterable[str]) -> list[Provider]:
        """Return providers matching ``names`` (unknown names are ignored)."""
        selected: list[Provider] = []
        for name in names:
            provider = self.get(name)
            if provider is not None:
                selected.append(provider)
        return selected

    def describe(self) -> dict[str, Any]:
        """JSON summary used by the REST API ``/providers`` endpoint."""
        infos = self.infos()
        return {
            "total": len(infos),
            "ready": sum(1 for info in infos if info.status == ProviderStatus.READY),
            "configured": sum(1 for info in infos if info.status == ProviderStatus.READY),
            "missing_credentials": self.missing_credentials(),
            "offline": self.offline,
            "providers": [info.to_dict() for info in infos],
        }

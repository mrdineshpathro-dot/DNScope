"""Credentialed discovery providers: OTX, URLScan and SecurityTrails."""

from __future__ import annotations

from typing import Any

from dnscope.exceptions import ProviderResponseError
from dnscope.models.common import Confidence, EvidenceQuality, SourceRecord
from dnscope.models.providers import ProviderCapabilities, ProviderQueryResult
from dnscope.providers.base import DiscoveryProvider, ProviderContext
from dnscope.security.validators import (
    coerce_str,
    coerce_str_list,
    ensure_bounded,
    mapping_field,
)
from dnscope.utils.domains import normalize_hostname, valid_hostname


class OTXProvider(DiscoveryProvider):
    """AlienVault OTX passive DNS and pulses (free API key)."""

    name = "otx"
    category = "subdomains"
    description = "AlienVault OTX passive DNS hostnames and reputation pulses."
    homepage = "https://otx.alienvault.com"
    base_url = "https://otx.alienvault.com/api/v1/"
    capabilities = ProviderCapabilities(subdomains=True, threat=True, history=True, ip=True, dns=True)
    requires_credentials = True
    commercial = False
    rate_limit_per_minute = 60.0
    env_vars = ("OTX_API_KEY",)

    def headers(self) -> dict[str, str]:
        """Authentication headers for OTX."""
        return {"X-OTX-API-KEY": self.api_key}

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Fetch passive DNS hostnames and (optionally) general info."""
        client = context.http
        if client is None:
            raise ProviderResponseError("otx requires an HTTP client in the context")
        payload: dict[str, Any] = {
            "passive_dns": client.get_json(
                f"{self.base_url}indicators/domain/{target}/passive_dns", headers=self.headers()
            )
        }
        if options.get("general", True):
            payload["general"] = client.get_json(
                f"{self.base_url}indicators/domain/{target}/general", headers=self.headers()
            )
        return payload

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert OTX passive DNS into hostnames plus history observations."""
        result = self._base()
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected OTX response shape"
            return result

        passive = mapping_field(raw, "passive_dns")
        hostnames: set[str] = set()
        history: list[dict[str, Any]] = []
        for entry in ensure_bounded(passive.get("passive_dns"), maximum=2_000, name="otx.passive_dns"):
            if not isinstance(entry, dict):
                continue
            host = normalize_hostname(coerce_str(entry.get("hostname"), maximum=255))
            if host and valid_hostname(host):
                hostnames.add(host)
            history.append(
                {
                    "hostname": host,
                    "address": coerce_str(entry.get("address"), maximum=64),
                    "record_type": coerce_str(entry.get("record_type"), maximum=16).upper(),
                    "first_seen": coerce_str(entry.get("first"), maximum=64),
                    "last_seen": coerce_str(entry.get("last"), maximum=64),
                    "source": self.name,
                }
            )

        general = mapping_field(raw, "general")
        if general:
            for section in ("other", "subdomains"):
                for item in coerce_str_list(general.get(section), maximum=2_000, item_length=255):
                    host = normalize_hostname(item)
                    if host and valid_hostname(host):
                        hostnames.add(host)
            result.threat_indicators.append(
                {
                    "provider": self.name,
                    "target": coerce_str(general.get("indicator"), maximum=255),
                    "pulse_count": general.get("pulse_info", {}).get("count")
                    if isinstance(general.get("pulse_info"), dict)
                    else None,
                    "alexa_rank": general.get("alexa"),
                    "whois_registrar": coerce_str(general.get("whois"), maximum=255),
                }
            )

        result.hostnames = sorted(hostnames)
        result.history = history
        result.raw_count = len(history)
        return result

    def _base(self) -> ProviderQueryResult:
        return ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(
                provider=self.name,
                source=self.base_url,
                confidence=Confidence.MEDIUM,
                quality=EvidenceQuality.OBSERVED,
            ),
            confidence=Confidence.MEDIUM,
        )


class URLScanProvider(DiscoveryProvider):
    """urlscan.io domain search (free API key)."""

    name = "urlscan"
    category = "subdomains"
    description = "urlscan.io search results: domains, pages and IP observations."
    homepage = "https://urlscan.io"
    base_url = "https://urlscan.io/api/v1/"
    capabilities = ProviderCapabilities(subdomains=True, threat=True, ip=True)
    requires_credentials = True
    commercial = False
    rate_limit_per_minute = 60.0
    env_vars = ("URLSCAN_API_KEY",)

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Search urlscan for ``target``."""
        client = context.http
        if client is None:
            raise ProviderResponseError("urlscan requires an HTTP client in the context")
        size = min(int(options.get("limit", 100)), 1000)
        return client.get_json(
            f"{self.base_url}search/",
            headers={"API-Key": self.api_key},
            params={"q": f'domain:"{target}"', "size": size},
        )

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert urlscan search results."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(provider=self.name, source=self.base_url, confidence=Confidence.MEDIUM),
            confidence=Confidence.MEDIUM,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected urlscan response shape"
            return result
        results = ensure_bounded(raw.get("results"), maximum=2_000, name="urlscan.results")
        result.raw_count = int(raw.get("total") or len(results))

        hostnames: set[str] = set()
        ip_records: list[dict[str, Any]] = []
        for entry in results:
            if not isinstance(entry, dict):
                continue
            page = mapping_field(entry, "page")
            task = mapping_field(entry, "task")
            host = normalize_hostname(coerce_str(page.get("domain"), maximum=255))
            if host and valid_hostname(host):
                hostnames.add(host)
            ip = coerce_str(page.get("ip"), maximum=64)
            if ip:
                ip_records.append(
                    {
                        "hostname": host,
                        "ip": ip,
                        "asn": coerce_str(page.get("asn"), maximum=32),
                        "organization": coerce_str(page.get("asnname"), maximum=255),
                        "country": coerce_str(page.get("country"), maximum=2),
                        "server": coerce_str(page.get("server"), maximum=255),
                        "observed_at": coerce_str(task.get("time"), maximum=64),
                        "source": self.name,
                    }
                )
        result.hostnames = sorted(hostnames)
        result.ip_records = ip_records
        return result


class SecurityTrailsProvider(DiscoveryProvider):
    """SecurityTrails subdomains and DNS history (paid API key)."""

    name = "securitytrails"
    category = "subdomains"
    description = "Subdomain enumeration and historical DNS records."
    homepage = "https://securitytrails.com"
    base_url = "https://api.securitytrails.com/v1/"
    capabilities = ProviderCapabilities(subdomains=True, dns=True, history=True, ip=True)
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 12.0
    env_vars = ("SECURITYTRAILS_API_KEY",)

    def headers(self) -> dict[str, str]:
        """Authentication headers for SecurityTrails."""
        return {"APIKEY": self.api_key}

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Fetch subdomains and (optionally) DNS history."""
        client = context.http
        if client is None:
            raise ProviderResponseError("securitytrails requires an HTTP client in the context")
        payload: dict[str, Any] = {
            "subdomains": client.get_json(
                f"{self.base_url}domain/{target}/subdomains",
                headers=self.headers(),
                params={"children_only": 0},
            )
        }
        if options.get("history", False):
            record_type = str(options.get("record_type", "a")).lower()
            payload["history"] = client.get_json(
                f"{self.base_url}history/{target}/dns/{record_type}", headers=self.headers()
            )
        return payload

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert SecurityTrails responses."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(provider=self.name, source=self.base_url, confidence=Confidence.MEDIUM),
            confidence=Confidence.MEDIUM,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected SecurityTrails response shape"
            return result

        hostnames: set[str] = set()
        subdomains = mapping_field(raw, "subdomains")
        if subdomains.get("success") is False:
            result.ok = False
            result.error = coerce_str(subdomains.get("message"), maximum=200) or "SecurityTrails error"
            return result

        base = normalize_hostname(coerce_str(subdomains.get("domain"), maximum=255))
        for sub in coerce_str_list(subdomains.get("subdomains"), maximum=10_000, item_length=255):
            host = normalize_hostname(sub)
            if not host:
                continue
            if base and "." not in host:
                host = f"{host}.{base}"
            if valid_hostname(host):
                hostnames.add(host)

        history = mapping_field(raw, "history")
        history_entries: list[dict[str, Any]] = []
        for entry in ensure_bounded(history.get("records"), maximum=1_000, name="st.history"):
            if not isinstance(entry, dict):
                continue
            values = entry.get("values")
            history_entries.append(
                {
                    "record_type": coerce_str(entry.get("type"), maximum=16).upper(),
                    "values": coerce_str_list(values, maximum=200, item_length=255),
                    "first_seen": coerce_str(entry.get("first_seen"), maximum=64),
                    "last_seen": coerce_str(entry.get("last_seen"), maximum=64),
                    "source": self.name,
                }
            )

        result.hostnames = sorted(hostnames)
        result.history = history_entries
        return result

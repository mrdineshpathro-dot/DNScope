"""Threat-intelligence providers that require an API key.

Every provider here follows the same contract:

1. ``is_configured`` checks the credential without spending quota
2. ``query`` performs the HTTP call through :class:`SafeHTTPClient`
3. ``normalize`` converts the provider-specific JSON into DNScope's canonical
   :class:`ProviderQueryResult`

No provider invents data: when a response does not contain a field, the
canonical result simply omits it.
"""

from __future__ import annotations

from typing import Any

from dnscope.exceptions import ProviderResponseError
from dnscope.models.common import Confidence, EvidenceQuality, SourceRecord
from dnscope.models.providers import ProviderCapabilities, ProviderQueryResult
from dnscope.providers.base import DiscoveryProvider, ProviderContext, ThreatProvider
from dnscope.security.validators import coerce_str, coerce_str_list, ensure_bounded
from dnscope.utils.domains import normalize_hostname, valid_hostname


class VirusTotalProvider(ThreatProvider, DiscoveryProvider):
    """VirusTotal v3: domain/IP reputation plus passive DNS and certificates."""

    name = "virustotal"
    category = "threat"
    description = "Domain/IP reputation, passive DNS subdomains and certificate data."
    homepage = "https://www.virustotal.com"
    base_url = "https://www.virustotal.com/api/v3/"
    capabilities = ProviderCapabilities(
        threat=True, ip=True, ct=True, subdomains=True, certificates=True
    )
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 4.0  # public tier: 4 requests/minute
    env_vars = ("VIRUSTOTAL_API_KEY",)

    def headers(self) -> dict[str, str]:
        """Authentication headers for the VT v3 API."""
        return {"x-apikey": self.api_key}

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Fetch the domain report and (optionally) subdomains."""
        client = self._client(context)
        payload: dict[str, Any] = {"domain": client.get_json(
            f"{self.base_url}domains/{target}", headers=self.headers()
        )}
        if options.get("subdomains", True):
            payload["subdomains"] = client.get_json(
                f"{self.base_url}domains/{target}/subdomains",
                headers=self.headers(),
                params={"limit": min(int(options.get("limit", 40)), 40)},
            )
        if options.get("certificates", False):
            payload["certificates"] = client.get_json(
                f"{self.base_url}domains/{target}/certificates",
                headers=self.headers(),
                params={"limit": min(int(options.get("cert_limit", 40)), 40)},
            )
        return payload

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert VT v3 payloads into canonical observations."""
        result = self._base_result()
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected VirusTotal response shape"
            return result

        report = raw.get("domain") if isinstance(raw.get("domain"), dict) else raw
        data = report.get("data") if isinstance(report, dict) else None
        if isinstance(data, dict):
            attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
            result.threat_indicators.append(_vt_indicator(data, attributes))
            for record in ensure_bounded(attributes.get("last_dns_records"), maximum=500, name="dns_records"):
                if isinstance(record, dict) and str(record.get("type", "")).upper() == "CNAME":
                    value = normalize_hostname(coerce_str(record.get("value"), maximum=255))
                    if value:
                        result.hostnames.append(value)

        subdomains = raw.get("subdomains") if isinstance(raw.get("subdomains"), dict) else None
        for entry in ensure_bounded((subdomains or {}).get("data"), maximum=1_000, name="subdomains"):
            if not isinstance(entry, dict):
                continue
            attrs = entry.get("attributes") if isinstance(entry.get("attributes"), dict) else {}
            host = normalize_hostname(coerce_str(attrs.get("id") or entry.get("id"), maximum=255))
            if host and valid_hostname(host):
                result.hostnames.append(host)

        certificates = raw.get("certificates") if isinstance(raw.get("certificates"), dict) else None
        for entry in ensure_bounded((certificates or {}).get("data"), maximum=200, name="certificates"):
            if not isinstance(entry, dict):
                continue
            attrs = entry.get("attributes") if isinstance(entry.get("attributes"), dict) else {}
            result.certificates.append(
                {
                    "serial_number": coerce_str(attrs.get("serial_number"), maximum=128),
                    "fingerprint_sha256": coerce_str(attrs.get("sha256"), maximum=128).lower(),
                    "subject_cn": normalize_hostname(coerce_str(attrs.get("subject"), maximum=255)),
                    "subject_alternative_names": coerce_str_list(
                        attrs.get("extensions", {}).get("subject_alternative_names")
                        if isinstance(attrs.get("extensions"), dict)
                        else None,
                        maximum=500,
                        item_length=255,
                    ),
                    "issuer_cn": normalize_hostname(coerce_str(attrs.get("issuer"), maximum=255)),
                    "not_before": _epoch_ms(attrs.get("not_before")),
                    "not_after": _epoch_ms(attrs.get("not_after")),
                    "source": self.name,
                }
            )

        result.hostnames = sorted({h for h in result.hostnames if h})
        return result

    def _client(self, context: ProviderContext):  # noqa: ANN201 - typed by SafeHTTPClient
        client = context.http
        if client is None:
            raise ProviderResponseError("virustotal requires an HTTP client in the context")
        return client

    def _base_result(self) -> ProviderQueryResult:
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


def _vt_indicator(data: dict[str, Any], attributes: dict[str, Any]) -> dict[str, Any]:
    """Build a canonical threat indicator from a VT domain object."""
    stats = attributes.get("last_analysis_stats") if isinstance(
        attributes.get("last_analysis_stats"), dict
    ) else {}
    return {
        "provider": "virustotal",
        "target": coerce_str(data.get("id"), maximum=255),
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "categories": coerce_str_list(
            list((attributes.get("categories") or {}).values()) if isinstance(
                attributes.get("categories"), dict
            ) else None,
            maximum=32,
            item_length=64,
        ),
        "registrar": coerce_str(attributes.get("registrar"), maximum=255),
        "creation_date": _epoch_seconds(attributes.get("creation_date")),
        "last_dns_records_count": len(
            ensure_bounded(attributes.get("last_dns_records"), maximum=1_000, name="records")
        ),
        "popularity": attributes.get("popularity_ranks"),
    }


class ShodanProvider(ThreatProvider):
    """Shodan host intelligence (ports, services, hostnames)."""

    name = "shodan"
    category = "threat"
    description = "Internet-wide scan data: open ports, services and host metadata."
    homepage = "https://www.shodan.io"
    base_url = "https://api.shodan.io/"
    capabilities = ProviderCapabilities(threat=True, ip=True, enrichment=True)
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 60.0
    env_vars = ("SHODAN_API_KEY",)

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Query the Shodan host endpoint."""
        client = context.http
        if client is None:
            raise ProviderResponseError("shodan requires an HTTP client in the context")
        return client.get_json(f"{self.base_url}shodan/host/{target}", params={"key": self.api_key})

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert a Shodan host document."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(
                provider=self.name, source=self.base_url, confidence=Confidence.MEDIUM
            ),
            confidence=Confidence.MEDIUM,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected Shodan response shape"
            return result
        if raw.get("error"):
            result.ok = False
            result.error = coerce_str(raw.get("error"), maximum=200)
            return result

        services: list[dict[str, Any]] = []
        for entry in ensure_bounded(raw.get("data"), maximum=100, name="shodan.data"):
            if not isinstance(entry, dict):
                continue
            services.append(
                {
                    "port": entry.get("port"),
                    "transport": coerce_str(entry.get("transport"), maximum=16),
                    "product": coerce_str(entry.get("product"), maximum=128),
                    "version": coerce_str(entry.get("version"), maximum=64),
                    "os": coerce_str(entry.get("os"), maximum=128),
                }
            )
        result.ip_records = [
            {
                "ip": coerce_str(raw.get("ip_str"), maximum=64),
                "asn": coerce_str(raw.get("asn"), maximum=32),
                "organization": coerce_str(raw.get("org"), maximum=255),
                "isp": coerce_str(raw.get("isp"), maximum=255),
                "country": coerce_str(raw.get("country_code"), maximum=2),
                "hostnames": coerce_str_list(raw.get("hostnames"), maximum=100, item_length=255),
                "ports": sorted({s["port"] for s in services if isinstance(s.get("port"), int)}),
                "services": services,
                "source": self.name,
            }
        ]
        result.hostnames = coerce_str_list(raw.get("hostnames"), maximum=100, item_length=255)
        result.threat_indicators = [
            {
                "provider": self.name,
                "target": coerce_str(raw.get("ip_str"), maximum=64),
                "vulns": coerce_str_list(raw.get("vulns"), maximum=200, item_length=64),
                "tags": coerce_str_list(raw.get("tags"), maximum=64, item_length=64),
            }
        ]
        return result


class CensysProvider(ThreatProvider):
    """Censys search API (basic auth with API id + secret)."""

    name = "censys"
    category = "threat"
    description = "Internet-wide scan data via the Censys search API."
    homepage = "https://search.censys.io"
    base_url = "https://search.censys.io/api/v2/"
    capabilities = ProviderCapabilities(threat=True, ip=True)
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 30.0
    env_vars = ("CENSYS_API_ID", "CENSYS_API_SECRET")

    def __init__(self, *, api_key: str = "", api_secret: str = "", settings: Any = None) -> None:
        super().__init__(api_key=api_key, settings=settings)
        self.api_secret = api_secret.strip() if api_secret else ""

    def is_configured(self) -> bool:
        """Both the API id and the secret are required."""
        return bool(self.api_key and self.api_secret)

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Query the Censys hosts endpoint."""
        client = context.http
        if client is None:
            raise ProviderResponseError("censys requires an HTTP client in the context")
        import base64

        token = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {token}"}
        return client.get_json(f"{self.base_url}hosts/{target}", headers=headers)

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert a Censys host document."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(provider=self.name, source=self.base_url, confidence=Confidence.MEDIUM),
            confidence=Confidence.MEDIUM,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected Censys response shape"
            return result
        payload = raw.get("result") if isinstance(raw.get("result"), dict) else {}
        if not payload:
            result.ok = False
            result.error = coerce_str(raw.get("error"), maximum=200) or "no Censys data returned"
            return result

        autonomous_system = payload.get("autonomous_system") if isinstance(
            payload.get("autonomous_system"), dict
        ) else {}
        location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
        services: list[dict[str, Any]] = []
        for service in ensure_bounded(payload.get("services"), maximum=100, name="censys.services"):
            if isinstance(service, dict):
                services.append(
                    {
                        "port": service.get("port"),
                        "transport": coerce_str(service.get("transport_protocol"), maximum=16),
                        "service": coerce_str(service.get("service_name"), maximum=128),
                    }
                )
        result.ip_records = [
            {
                "ip": coerce_str(payload.get("ip"), maximum=64),
                "asn": f"AS{autonomous_system.get('asn')}" if autonomous_system.get("asn") else "",
                "organization": coerce_str(autonomous_system.get("name"), maximum=255),
                "country": coerce_str(location.get("country_code"), maximum=2),
                "services": services,
                "source": self.name,
            }
        ]
        return result


class AbuseIPDBProvider(ThreatProvider):
    """AbuseIPDB IP reputation checks."""

    name = "abuseipdb"
    category = "threat"
    description = "Crowdsourced IP abuse reports and confidence scores."
    homepage = "https://www.abuseipdb.com"
    base_url = "https://api.abuseipdb.com/api/v2/"
    capabilities = ProviderCapabilities(threat=True, ip=True)
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 60.0
    env_vars = ("ABUSEIPDB_API_KEY",)

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Query the AbuseIPDB check endpoint."""
        client = context.http
        if client is None:
            raise ProviderResponseError("abuseipdb requires an HTTP client in the context")
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": target, "maxAgeInDays": int(options.get("max_age_days", 90))}
        return client.get_json(f"{self.base_url}check", headers=headers, params=params)

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert an AbuseIPDB check response."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(provider=self.name, source=self.base_url, confidence=Confidence.MEDIUM),
            confidence=Confidence.MEDIUM,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected AbuseIPDB response shape"
            return result
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        if not data:
            errors = raw.get("errors")
            if isinstance(errors, list) and errors:
                first = errors[0] if isinstance(errors[0], dict) else {}
                result.ok = False
                result.error = coerce_str(first.get("detail"), maximum=200)
            return result
        result.threat_indicators = [
            {
                "provider": self.name,
                "target": coerce_str(data.get("ipAddress"), maximum=64),
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": coerce_str(data.get("countryCode"), maximum=2),
                "isp": coerce_str(data.get("isp"), maximum=255),
                "usage_type": coerce_str(data.get("usageType"), maximum=64),
                "is_tor": bool(data.get("isTor")),
                "is_public": bool(data.get("isPublic")),
                "last_reported_at": coerce_str(data.get("lastReportedAt"), maximum=64),
            }
        ]
        result.ip_records = [
            {
                "ip": coerce_str(data.get("ipAddress"), maximum=64),
                "organization": coerce_str(data.get("isp"), maximum=255),
                "country": coerce_str(data.get("countryCode"), maximum=2),
                "asn": coerce_str(data.get("asn"), maximum=32),
                "source": self.name,
            }
        ]
        return result


class GreyNoiseProvider(ThreatProvider):
    """GreyNoise internet-noise classification."""

    name = "greynoise"
    category = "threat"
    description = "Classifies whether an IP is known internet background noise."
    homepage = "https://viz.greynoise.io"
    base_url = "https://api.greynoise.io/v3/community/"
    capabilities = ProviderCapabilities(threat=True, ip=True)
    requires_credentials = True
    commercial = True
    rate_limit_per_minute = 30.0
    env_vars = ("GREYNOISE_API_KEY",)

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Query the GreyNoise community endpoint."""
        client = context.http
        if client is None:
            raise ProviderResponseError("greynoise requires an HTTP client in the context")
        return client.get_json(f"{self.base_url}{target}", headers={"key": self.api_key})

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert a GreyNoise community response."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(provider=self.name, source=self.base_url, confidence=Confidence.LOW),
            confidence=Confidence.LOW,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected GreyNoise response shape"
            return result
        if raw.get("message") and not raw.get("ip"):
            result.ok = False
            result.error = coerce_str(raw.get("message"), maximum=200)
            return result
        result.threat_indicators = [
            {
                "provider": self.name,
                "target": coerce_str(raw.get("ip"), maximum=64),
                "classification": coerce_str(raw.get("classification"), maximum=64),
                "noise": bool(raw.get("noise")),
                "riot": bool(raw.get("riot")),
                "name": coerce_str(raw.get("name"), maximum=255),
                "last_seen": coerce_str(raw.get("last_seen"), maximum=64),
            }
        ]
        return result


def _epoch_seconds(value: Any) -> str:
    """Convert a UNIX timestamp (seconds) to an ISO-8601 UTC string."""
    from datetime import UTC, datetime

    try:
        number = int(value)
    except (TypeError, ValueError):
        return coerce_str(value, maximum=64)
    if number <= 0:
        return ""
    return datetime.fromtimestamp(number, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms(value: Any) -> str:
    """Convert a UNIX timestamp (milliseconds) to an ISO-8601 UTC string."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return coerce_str(value, maximum=64)
    if number <= 0:
        return ""
    if number > 10_000_000_000:  # milliseconds
        number //= 1000
    return _epoch_seconds(number)

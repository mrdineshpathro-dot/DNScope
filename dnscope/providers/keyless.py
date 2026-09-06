"""Keyless intelligence providers.

These need no API key and are the backbone of DNScope's "works out of the box"
guarantee:

* :class:`CymruASNProvider` - ASN/prefix/country via Team Cymru's DNS interface
* :class:`RdapProvider` - domain registration data via the RDAP bootstrap
* :class:`HackerTargetProvider` - optional passive host discovery (keyless HTTP)
"""

from __future__ import annotations

import ipaddress
from typing import Any

from dnscope.exceptions import ProviderResponseError
from dnscope.models.certificates import CertificateInfo  # noqa: F401 - re-exported for callers
from dnscope.models.common import Confidence, EvidenceQuality, SourceRecord
from dnscope.models.providers import (
    ProviderCapabilities,
    ProviderQueryResult,
)
from dnscope.providers.base import DiscoveryProvider, Provider, ProviderContext
from dnscope.security.validators import coerce_str, coerce_str_list
from dnscope.utils.domains import format_asn, normalize_hostname, valid_hostname
from dnscope.utils.logging import get_logger

_log = get_logger("providers.keyless")


class CymruASNProvider(Provider):
    """IP -> ASN/prefix/country via ``origin.asn.cymru.com`` DNS TXT records.

    This is a public, keyless service operated by Team Cymru. DNScope uses it
    because it requires no credentials and no HTTP egress, which keeps IP
    enrichment available in offline-friendly deployments.
    """

    name = "team-cymru"
    category = "asn"
    description = "IP to ASN/prefix/country mapping via DNS (keyless)."
    homepage = "https://team-cymru.com/community-services/ip-asn-mapping/"
    base_url = "dns://origin.asn.cymru.com"
    capabilities = ProviderCapabilities(asn=True, ip=True)
    requires_credentials = False
    commercial = False
    env_vars = ()

    #: Cache of recent answers so bulk scans do not repeat identical lookups.
    def __init__(self, *, api_key: str = "", settings: Any = None) -> None:
        super().__init__(api_key=api_key, settings=settings)
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_limit = 5_000

    # --------------------------------------------------------------- querying

    def query_name(self, ip: str) -> str | None:
        """Return the Cymru lookup name for ``ip`` (or ``None`` for literals)."""
        try:
            address = ipaddress.ip_address(ip.strip().strip("[]"))
        except ValueError:
            return None
        if address.version == 4:
            reversed_octets = ".".join(reversed(str(address).split(".")))
            return f"{reversed_octets}.origin.asn.cymru.com"
        nibbles = address.exploded.replace(":", "")[::-1]
        return ".".join(nibbles) + ".origin6.asn.cymru.com"

    def query(self, target: str, context: ProviderContext | None = None, **options: Any) -> ProviderQueryResult:
        """Look up ASN data for one IP address."""
        ctx = context or ProviderContext()
        result = self.empty_result(target)
        result.query = target
        name = self.query_name(target)
        if name is None:
            result.ok = False
            result.error = f"{target!r} is not an IP address"
            return result
        if not ctx.may_call_network:
            result.ok = False
            result.error = "external calls disabled (offline/privacy mode)"
            return result
        if name in self._cache:
            cached = self._cache[name]
            result.ip_records = [dict(cached)]
            result.cached = True
            return result

        resolver = getattr(ctx, "dns", None) or options.get("dns")
        if resolver is None:
            result.ok = False
            result.error = "no DNS resolver available in the provider context"
            return result

        try:
            records = resolver.txt(name)
        except Exception as exc:
            result.ok = False
            result.error = f"ASN lookup failed: {exc}"
            return result

        parsed = self._parse_txt(records)
        if not parsed:
            result.ok = True
            result.error = "no ASN data published for this address"
            return result

        parsed["source"] = self.name
        parsed["ip"] = target
        self._remember(name, parsed)
        result.ip_records = [parsed]
        return result

    def _remember(self, name: str, value: dict[str, Any]) -> None:
        """Store an answer, bounding cache growth."""
        if len(self._cache) >= self._cache_limit:
            self._cache.clear()
        self._cache[name] = value

    def _parse_txt(self, records: list[str]) -> dict[str, Any]:
        """Parse the ``ASN | prefix | country | RIR | date`` record format."""
        for record in records:
            text = record.strip().strip('"')
            parts = [part.strip() for part in text.split("|")]
            if len(parts) < 3:
                continue
            asn_raw = parts[0]
            if asn_raw.lower() in ("", "na"):
                continue
            return {
                "asn": format_asn(asn_raw),
                "prefix": parts[1] if len(parts) > 1 else "",
                "country": parts[2].upper() if len(parts) > 2 else "",
                "rir": parts[3] if len(parts) > 3 else "",
                "allocated": parts[4] if len(parts) > 4 else "",
                "confidence": Confidence.HIGH.value,
                "quality": EvidenceQuality.OBSERVED.value,
            }
        return {}

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Normalize already-parsed Cymru data."""
        result = self.empty_result("")
        if isinstance(raw, dict):
            result.ip_records = [raw]
        elif isinstance(raw, list):
            result.ip_records = [item for item in raw if isinstance(item, dict)]
        return result


class RdapProvider(Provider):
    """RDAP registration data through the IANA bootstrap (keyless).

    RDAP (RFC 9082/9083) is the modern replacement for WHOIS. DNScope resolves
    the authoritative RDAP server per TLD via ``rdap.org`` and normalizes the
    response into a single model regardless of registry quirks.
    """

    name = "rdap"
    category = "rdap"
    description = "Domain registration data (registrar, dates, nameservers) via RDAP."
    homepage = "https://rdap.org"
    base_url = "https://rdap.org/domain/"
    capabilities = ProviderCapabilities(rdap=True, dns=True, history=True)
    requires_credentials = False
    commercial = False
    env_vars = ()

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Fetch the RDAP document for ``target``."""
        client = context.http
        if client is None:
            raise ProviderResponseError("RDAP requires an HTTP client in the context")
        if _looks_like_ip(target):
            return client.get_json(f"https://rdap.org/ip/{target}")
        return client.get_json(f"{self.base_url}{target}")

    def query(self, target: str, context: ProviderContext | None = None, **options: Any) -> ProviderQueryResult:
        """Fetch and normalize RDAP data for a domain or IP."""
        ctx = context or ProviderContext()
        result = self.empty_result(target)
        result.query = target
        if not ctx.may_call_network:
            result.ok = False
            result.error = "external calls disabled (offline/privacy mode)"
            return result
        try:
            raw = self.fetch(target, ctx, **options)
        except ProviderResponseError as exc:
            result.ok = False
            result.error = str(exc)
            return result
        normalized = self.normalize(raw)
        normalized.query = target
        return normalized

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Map an RDAP document into DNScope's canonical shape."""
        result = self.empty_result("")
        result.source = SourceRecord(
            provider=self.name,
            source=self.base_url,
            confidence=Confidence.HIGH,
            quality=EvidenceQuality.OBSERVED,
        )
        if not isinstance(raw, dict):
            result.ok = False
            result.error = "unexpected RDAP response shape"
            return result

        events = raw.get("events") if isinstance(raw.get("events"), list) else []
        dates: dict[str, str] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            action = coerce_str(event.get("eventAction"), maximum=64).lower()
            value = coerce_str(event.get("eventDate"), maximum=64)
            if action and value:
                dates[action] = value

        nameservers: list[str] = []
        for entry in raw.get("nameservers") or []:
            if isinstance(entry, dict):
                name = normalize_hostname(coerce_str(entry.get("ldhName"), maximum=255))
                if name:
                    nameservers.append(name)
            elif isinstance(entry, str):
                name = normalize_hostname(entry)
                if name:
                    nameservers.append(name)

        registrar = ""
        for entity in raw.get("entities") or []:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles") or []
            if "registrar" not in [str(role).lower() for role in roles]:
                continue
            registrar = _entity_name(entity)
            if registrar:
                break

        status = coerce_str_list(raw.get("status"), maximum=32, item_length=64)
        handles = coerce_str_list(raw.get("handle"), maximum=4, item_length=128)

        result.generic = [
            {
                "kind": "rdap",
                "handle": handles[0] if handles else "",
                "registrar": registrar,
                "status": [item.lower() for item in status],
                "registration_date": dates.get("registration", ""),
                "expiration_date": dates.get("expiration", ""),
                "last_changed": dates.get("last changed", "") or dates.get("last update of rdap database", ""),
                "events": dates,
                "nameservers": nameservers,
                "secure_dns": raw.get("secureDNS") if isinstance(raw.get("secureDNS"), dict) else None,
                "source": self.name,
            }
        ]
        result.hostnames = sorted(set(nameservers))
        return result


class HackerTargetProvider(DiscoveryProvider):
    """Passive host discovery via the HackerTarget hostsearch API (keyless).

    Disabled by default: DNScope only enables it when the operator adds
    ``hackertarget`` to ``discovery.sources``.
    """

    name = "hackertarget"
    category = "subdomains"
    description = "Passive host/subdomain discovery (keyless, rate limited upstream)."
    homepage = "https://hackertarget.com/hostsearch/"
    base_url = "https://api.hackertarget.com/hostsearch/"
    capabilities = ProviderCapabilities(subdomains=True, dns=True)
    requires_credentials = False
    commercial = False
    rate_limit_per_minute = 1.0
    env_vars = ()

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Fetch the CSV host list for ``target``."""
        client = context.http
        if client is None:
            raise ProviderResponseError("hackertarget requires an HTTP client in the context")
        response = client.get(self.base_url, params={"q": target})
        return response.text

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Parse the ``host,ip`` CSV format into hostnames and IP records."""
        result = self.empty_result("")
        result.source = SourceRecord(
            provider=self.name,
            source=self.base_url,
            confidence=Confidence.MEDIUM,
            quality=EvidenceQuality.OBSERVED,
        )
        if not isinstance(raw, str):
            result.ok = False
            result.error = "unexpected hackertarget response"
            return result
        text = raw.strip()
        if not text:
            return result
        if text.lower().startswith(("error", "no results", "<html")):
            result.ok = False
            result.error = coerce_str(text, maximum=200)
            return result

        hostnames: list[str] = []
        ip_records: list[dict[str, Any]] = []
        for line in text.splitlines()[:5_000]:
            parts = [part.strip() for part in line.split(",")]
            if not parts or not parts[0]:
                continue
            host = normalize_hostname(parts[0])
            if not host or not valid_hostname(host):
                continue
            hostnames.append(host)
            if len(parts) > 1 and parts[1]:
                ip_records.append({"hostname": host, "ip": parts[1], "source": self.name})
        result.hostnames = sorted(set(hostnames))
        result.ip_records = ip_records
        result.raw_count = len(text.splitlines())
        return result


def _entity_name(entity: dict[str, Any]) -> str:
    """Extract a printable name from an RDAP entity object."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4 and str(field[0]).lower() == "fn":
                return coerce_str(field[3], maximum=255)
    return coerce_str(entity.get("handle"), maximum=255)


def _looks_like_ip(value: str) -> bool:
    """Return ``True`` when ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

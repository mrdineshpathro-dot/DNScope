"""crt.sh Certificate Transparency provider (no API key required).

crt.sh exposes CT log data as JSON. DNScope uses it for two things:

* hostname discovery (SAN values seen in public certificates)
* certificate history (issuer, validity window, SAN set)

The provider is defensive about the response: crt.sh occasionally returns an
HTML error page instead of JSON, and large domains can return very big
payloads, so both are handled explicitly.
"""

from __future__ import annotations

from typing import Any

from dnscope.exceptions import ProviderResponseError
from dnscope.models.certificates import CertificateInfo
from dnscope.models.common import Confidence, EvidenceQuality
from dnscope.models.providers import ProviderCapabilities, ProviderQueryResult, SourceRecord
from dnscope.providers.base import DiscoveryProvider, ProviderContext
from dnscope.security.validators import coerce_str, coerce_str_list
from dnscope.utils.domains import normalize_hostname, valid_hostname


class CrtShProvider(DiscoveryProvider):
    """Certificate discovery through the public crt.sh service."""

    name = "crt.sh"
    category = "ct"
    description = "Public Certificate Transparency log search (keyless)."
    homepage = "https://crt.sh"
    base_url = "https://crt.sh/"
    capabilities = ProviderCapabilities(ct=True, certificates=True, subdomains=True)
    requires_credentials = False
    commercial = False
    rate_limit_per_minute = 2.0  # conservative; crt.sh is a shared service
    env_vars = ()

    def fetch(self, target: str, context: ProviderContext, **options: Any) -> Any:
        """Query crt.sh for certificates covering ``target``."""
        client = context.http
        if client is None:
            raise ProviderResponseError("crt.sh requires an HTTP client in the context")
        wildcard = bool(options.get("wildcard", True))
        query = f"%.{target}" if wildcard else target
        params = {"q": query, "output": "json", "exclude": "expired"} if options.get(
            "exclude_expired"
        ) else {"q": query, "output": "json"}
        raw = client.get_json(self.base_url, params=params, max_body=10 * 1024 * 1024)
        if isinstance(raw, dict):
            # crt.sh returns a bare list on success; a dict usually means an error.
            if "error" in raw:
                raise ProviderResponseError(f"crt.sh error: {coerce_str(raw.get('error'))}")
            raw = [raw]
        return raw

    def normalize(self, raw: Any) -> ProviderQueryResult:
        """Convert crt.sh rows into canonical hostnames and certificates."""
        result = ProviderQueryResult(
            provider=self.name,
            query="",
            source=SourceRecord(
                provider=self.name,
                source=self.base_url,
                confidence=Confidence.HIGH,
                quality=EvidenceQuality.OBSERVED,
            ),
            confidence=Confidence.HIGH,
            quality=EvidenceQuality.OBSERVED,
        )
        if not isinstance(raw, list):
            result.error = "unexpected crt.sh response shape"
            return result

        result.raw_count = len(raw)
        hostnames: set[str] = set()
        seen_certs: dict[str, CertificateInfo] = {}

        for row in raw:
            if not isinstance(row, dict):
                continue
            names = set(coerce_str_list(row.get("name_value"), maximum=500, item_length=255))
            common_name = coerce_str(row.get("common_name"), maximum=255)
            if common_name:
                names.add(common_name)

            sans: list[str] = []
            for name in names:
                cleaned = normalize_hostname(name.strip())
                if not cleaned or not valid_hostname(cleaned):
                    continue
                sans.append(cleaned)
                hostnames.add(cleaned)

            serial = coerce_str(row.get("id") or row.get("min_cert_id"), maximum=64)
            fingerprint = coerce_str(row.get("fingerprint") or row.get("sha256"), maximum=128)
            identity = fingerprint or serial or common_name
            if not identity:
                continue
            key = identity.lower()
            if key in seen_certs:
                existing = seen_certs[key]
                existing.subject_alternative_names = sorted(
                    set(existing.subject_alternative_names) | set(sans)
                )
                continue
            seen_certs[key] = CertificateInfo(
                serial_number=serial,
                fingerprint_sha256=fingerprint.lower(),
                subject_cn=normalize_hostname(common_name),
                subject_alternative_names=sorted(set(sans)),
                issuer_cn=_issuer_cn(coerce_str(row.get("issuer_name"), maximum=512)),
                not_before=_parse_time(row.get("not_before")),
                not_after=_parse_time(row.get("not_after")),
                source="ct",
                source_detail=self.base_url,
                confidence=Confidence.HIGH,
                raw={"crtsh_id": serial},
            )

        result.hostnames = sorted(hostnames)
        result.certificates = [cert.to_dict() for cert in seen_certs.values()]
        return result

    def query(self, target: str, context: ProviderContext | None = None, **options: Any) -> ProviderQueryResult:
        """Query and normalize, tolerating provider outages."""
        ctx = context or ProviderContext()
        if not ctx.may_call_network:
            return self.empty_result(target, error="external calls disabled (offline/privacy mode)")
        try:
            raw = self.fetch(target, ctx, **options)
        except ProviderResponseError as exc:
            self.log.warning("crt.sh query failed for %s: %s", target, exc)
            return self.empty_result(target, error=str(exc))
        result = self.normalize(raw)
        result.query = target
        return result


def _issuer_cn(issuer_name: str) -> str:
    """Extract the CN component from an X.500 issuer string."""
    for part in issuer_name.split(","):
        text = part.strip()
        if text.upper().startswith("CN="):
            return text[3:].strip()
    return issuer_name.strip()


def _parse_time(value: Any) -> Any:
    """Parse crt.sh timestamps (``YYYY-MM-DDTHH:MM:SS`` without a zone)."""
    from dnscope.utils.time_utils import parse_timestamp

    if not value:
        return None
    text = coerce_str(value, maximum=64)
    if not text:
        return None
    try:
        return parse_timestamp(text)
    except Exception:  # noqa: BLE001 - malformed provider timestamp
        return None

"""Certificate models: CT observations, live TLS chains and change tracking."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import Confidence, SchemaVersioned
from dnscope.utils.time_utils import now_utc, parse_timestamp


class CertificateInfo(SchemaVersioned):
    """A normalized X.509 certificate observation.

    Populated either from Certificate Transparency logs (no connection to the
    host required) or from an explicitly authorized TLS handshake.
    """

    serial_number: str = ""
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    subject_cn: str = ""
    subject_alternative_names: list[str] = Field(default_factory=list)
    issuer_cn: str = ""
    issuer_organization: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_bits: int | None = None
    is_ca: bool = False
    version: int | None = None
    #: ``ct`` | ``tls`` | ``provider``.
    source: str = "ct"
    source_detail: str = ""
    observed_at: datetime | None = None
    confidence: Confidence = Confidence.MEDIUM
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("not_before", "not_after", "observed_at", mode="before")
    @classmethod
    def _parse_time(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @field_validator("subject_alternative_names", mode="before")
    @classmethod
    def _split_sans(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split("\n") if item.strip()]
        return value

    @property
    def identity(self) -> str:
        """Stable identity for de-duplication across sources."""
        return (self.fingerprint_sha256 or self.serial_number or self.subject_cn).lower()

    @property
    def dns_names(self) -> list[str]:
        """DNS SANs (``DNS:`` prefix stripped), lower-cased."""
        names: list[str] = []
        for san in self.subject_alternative_names:
            text = san.strip()
            if ":" in text and text.split(":", 1)[0].upper() in ("DNS", "IP", "EMAIL", "URI"):
                prefix, _, rest = text.partition(":")
                if prefix.upper() != "DNS":
                    continue
                text = rest
            if text:
                names.append(text.strip().lower())
        return sorted(set(names))

    @property
    def wildcard_names(self) -> list[str]:
        """Wildcard SANs, e.g. ``*.example.com``."""
        return sorted({name for name in self.dns_names if name.startswith("*.")})

    @property
    def base_domains(self) -> list[str]:
        """Registrable domains covered by this certificate."""
        from dnscope.utils.domains import registered_domain, wildcard_strip

        domains = {
            registered_domain(wildcard_strip(name))
            for name in self.dns_names
            if registered_domain(wildcard_strip(name))
        }
        return sorted(domains)

    def days_until_expiry(self, when: datetime | None = None) -> float | None:
        """Days remaining before expiry (negative when already expired)."""
        if self.not_after is None:
            return None
        return (self.not_after - (when or now_utc())).total_seconds() / 86400.0

    def is_expired(self, when: datetime | None = None) -> bool:
        """``True`` when ``not_after`` is in the past."""
        remaining = self.days_until_expiry(when)
        return remaining is not None and remaining < 0

    def covers(self, hostname: str) -> bool:
        """``True`` when a SAN matches ``hostname`` (wildcards honoured)."""
        host = hostname.strip().lower().rstrip(".")
        for name in self.dns_names:
            if name == host:
                return True
            if name.startswith("*."):
                suffix = name[1:]
                if host.endswith(suffix) and "." not in host[: -len(suffix)].rstrip("."):
                    return True
        return False


class CertificateSource(SchemaVersioned):
    """Where a certificate observation came from.

    CT observations and TLS observations have very different trust
    characteristics (a CT log entry may never have been deployed), so the
    source travels with the certificate into reports and the database.
    """

    provider: str = "ct"
    endpoint: str = ""
    log_name: str = ""
    query: str = ""
    observed_at: datetime | None = None
    entry_index: int | None = None
    confidence: Confidence = Confidence.MEDIUM
    #: ``ct`` | ``tls`` | ``provider``.
    kind: str = "ct"

    @field_validator("observed_at", mode="before")
    @classmethod
    def _parse_time(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @property
    def attribution(self) -> str:
        """Short attribution string for reports."""
        if self.log_name:
            return f"{self.provider} ({self.log_name})"
        return self.provider


class CertificateChain(SchemaVersioned):
    """A full certificate chain observed during TLS inspection."""

    host: str = ""
    certificates: list[CertificateInfo] = Field(default_factory=list)
    leaf: CertificateInfo | None = None
    root_issuer: str = ""
    verified: bool = False
    error: str = ""

    @property
    def depth(self) -> int:
        """Number of certificates in the chain."""
        return len(self.certificates)

    @property
    def issuers(self) -> list[str]:
        """Distinct issuer names, chain order preserved."""
        seen: list[str] = []
        for cert in self.certificates:
            if cert.issuer_cn and cert.issuer_cn not in seen:
                seen.append(cert.issuer_cn)
        return seen


class TLSHandshakeResult(SchemaVersioned):
    """Result of an explicitly authorized TLS inspection."""

    host: str
    port: int = 443
    server_name: str = ""
    ok: bool = False
    tls_version: str = ""
    cipher: str = ""
    cipher_bits: int | None = None
    alpn: list[str] = Field(default_factory=list)
    sni_sent: bool = True
    peer_certificate: CertificateInfo | None = None
    chain: list[CertificateInfo] = Field(default_factory=list)
    verified: bool = False
    verify_error: str = ""
    duration_ms: float = 0.0
    error: str = ""
    authorized: bool = False

    @property
    def chain_depth(self) -> int:
        return len(self.chain)

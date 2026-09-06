"""SSRF protection for every outbound HTTP request DNScope makes.

Providers and webhooks are configured by humans, and a webhook URL can also come
from a config file that lives in a repository. Without validation, ``file://``,
``http://169.254.169.254/`` (cloud metadata) or ``http://127.0.0.1:9200`` would
be reachable. DNScope therefore validates scheme, host and resolved addresses
before a connection is opened, and re-validates redirects.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dnscope.exceptions import SecurityPolicyViolation

#: Schemes DNScope will ever request.
ALLOWED_SCHEMES = ("https", "http")

#: Hosts that are always blocked (cloud metadata, local services).
ALWAYS_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "instance-data",
        "kubernetes.default",
        "kubernetes.default.svc",
        "169.254.169.254",
        "fd00:ec2::254",
    }
)

#: Domains that resolve to cloud metadata endpoints.
BLOCKED_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".localdomain",
    ".svc",
    ".cluster.local",
    ".compute.internal",
)

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class SSRFProtectionError(SecurityPolicyViolation):
    """Raised when a URL is rejected by the SSRF validator."""


@dataclass
class ValidationResult:
    """Outcome of validating one URL."""

    url: str
    ok: bool
    reason: str = ""
    scheme: str = ""
    host: str = ""
    port: int | None = None
    resolved_addresses: list[str] = field(default_factory=list)
    #: ``True`` when the host is an IP literal (no DNS lookup was needed).
    literal_ip: bool = False

    def to_dict(self) -> dict[str, object]:
        """JSON-ready summary (safe to log)."""
        return {
            "url": self.url,
            "ok": self.ok,
            "reason": self.reason,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "resolved": self.resolved_addresses,
        }


class SSRFValidator:
    """Validates URLs against DNScope's egress policy.

    Args:
        block_private: reject RFC1918/ULA/loopback/link-local destinations.
        allow_private: explicit opt-in that overrides ``block_private`` (lab use).
        allowed_schemes: schemes permitted (defaults to http/https).
        allowed_hosts: optional allowlist; when non-empty only these hosts pass.
        resolve: perform DNS resolution to catch rebinding/private A records.
        require_https: reject plain ``http`` (used for webhooks).
    """

    def __init__(
        self,
        *,
        block_private: bool = True,
        allow_private: bool = False,
        allowed_schemes: tuple[str, ...] = ALLOWED_SCHEMES,
        allowed_hosts: tuple[str, ...] = (),
        resolve: bool = True,
        require_https: bool = False,
        max_port: int = 65535,
    ) -> None:
        self.block_private = block_private and not allow_private
        self.allow_private = allow_private
        self.allowed_schemes = tuple(s.lower() for s in allowed_schemes)
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts)
        self.resolve = resolve
        self.require_https = require_https
        self.max_port = max_port

    # ------------------------------------------------------------------ public

    def validate(self, url: str) -> ValidationResult:
        """Validate ``url``; never raises, returns a :class:`ValidationResult`."""
        text = (url or "").strip()
        if not text:
            return ValidationResult(url, False, reason="empty URL")
        if len(text) > 2048:
            return ValidationResult(url, False, reason="URL too long")
        if any(char in text for char in (" ", "\t", "\n", "\r")):
            return ValidationResult(url, False, reason="URL contains whitespace")

        try:
            parts = urlsplit(text)
        except ValueError as exc:
            return ValidationResult(url, False, reason=f"unparsable URL: {exc}")

        scheme = (parts.scheme or "").lower()
        if not scheme:
            return ValidationResult(text, False, reason="URL has no scheme")
        if scheme not in self.allowed_schemes:
            return ValidationResult(text, False, reason=f"scheme {scheme!r} is not permitted", scheme=scheme)
        if self.require_https and scheme != "https":
            return ValidationResult(text, False, reason="HTTPS is required", scheme=scheme)

        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return ValidationResult(text, False, reason="URL has no host", scheme=scheme)
        if "%" in host:  # IPv6 zone identifier
            host = host.split("%", 1)[0]
        if len(host) > 253 or not _HOSTNAME_RE.match(host):
            return ValidationResult(text, False, reason=f"invalid host {host!r}", scheme=scheme, host=host)

        port = parts.port
        if port is not None and not 1 <= port <= self.max_port:
            return ValidationResult(text, False, reason=f"port {port} out of range", scheme=scheme, host=host)

        if host in ALWAYS_BLOCKED_HOSTS:
            return ValidationResult(text, False, reason=f"host {host!r} is blocked", scheme=scheme, host=host)
        for suffix in BLOCKED_SUFFIXES:
            if host.endswith(suffix):
                return ValidationResult(
                    text, False, reason=f"host suffix {suffix!r} is blocked", scheme=scheme, host=host
                )
        if self.allowed_hosts and host not in self.allowed_hosts:
            return ValidationResult(
                text, False, reason=f"host {host!r} is not in the allowlist", scheme=scheme, host=host
            )

        literal_ip = _is_ip(host)
        result = ValidationResult(text, True, scheme=scheme, host=host, port=port, literal_ip=literal_ip)

        if literal_ip:
            result.resolved_addresses = [host]
            if self._address_blocked(host):
                result.ok = False
                result.reason = f"destination address {host} is blocked"
            return result

        if not self.resolve:
            return result

        try:
            addresses = _resolve_host(host)
        except OSError as exc:
            result.ok = False
            result.reason = f"cannot resolve host: {exc}"
            return result
        if not addresses:
            result.ok = False
            result.reason = "host does not resolve to any address"
            return result
        result.resolved_addresses = addresses
        for address in addresses:
            if self._address_blocked(address):
                result.ok = False
                result.reason = f"host resolves to blocked address {address}"
                return result
        return result

    def validate_or_raise(self, url: str) -> ValidationResult:
        """Validate ``url`` and raise :class:`SSRFProtectionError` on failure."""
        result = self.validate(url)
        if not result.ok:
            raise SSRFProtectionError(
                f"blocked outbound request: {result.reason}",
                details=result.to_dict(),
            )
        return result

    # ----------------------------------------------------------------- private

    def _address_blocked(self, address: str) -> bool:
        """Return ``True`` when ``address`` must not be connected to."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return True
        if not self.block_private:
            return False
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
            or _is_ipv4_mapped_private(parsed)
        )


def _is_ipv4_mapped_private(address: object) -> bool:
    """Detect ``::ffff:127.0.0.1`` style bypasses."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        mapped = address.ipv4_mapped
        return mapped.is_private or mapped.is_loopback or mapped.is_link_local
    return False


def _is_ip(host: str) -> bool:
    """Return ``True`` when ``host`` is an IP literal."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _resolve_host(host: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve ``host`` to all of its addresses (A + AAAA)."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
    finally:
        socket.setdefaulttimeout(previous)
    return sorted({info[4][0] for info in infos})


#: Default validator instance matching DNScope's safe defaults.
DEFAULT_VALIDATOR = SSRFValidator()


def validate_url(
    url: str,
    *,
    block_private: bool = True,
    allow_private: bool = False,
    require_https: bool = False,
    allowed_hosts: tuple[str, ...] = (),
    resolve: bool = True,
) -> ValidationResult:
    """Convenience wrapper around :class:`SSRFValidator`."""
    validator = SSRFValidator(
        block_private=block_private,
        allow_private=allow_private,
        require_https=require_https,
        allowed_hosts=allowed_hosts,
        resolve=resolve,
    )
    return validator.validate(url)


def is_safe_webhook_url(url: str, *, allow_private: bool = False) -> ValidationResult:
    """Validate a webhook URL (HTTPS required, private ranges blocked)."""
    return validate_url(url, require_https=True, allow_private=allow_private)

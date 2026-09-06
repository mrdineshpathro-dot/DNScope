"""Target normalization engine.

Accepts everything a human pastes - bare domains, URLs with paths, ports,
wildcards, IDN names, IPv4/IPv6 literals - and produces one canonical
:class:`Target`. Normalization is deliberately conservative: anything that
cannot be interpreted as a hostname or IP is rejected instead of being
"best-effort" scanned, because scanning the wrong domain is worse than
refusing.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import Field, field_validator

from dnscope.exceptions import TargetError
from dnscope.models.common import SchemaVersioned
from dnscope.utils.domains import (
    is_ip_literal,
    normalize_hostname,
    parent_domain,
    registered_domain,
    valid_hostname,
)

#: Schemes DNScope is willing to interpret. Others are rejected because the
#: "hostname" would be meaningless to a DNS analyzer.
_ALLOWED_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "ftps", "dns", "udp", "tcp", ""})

_MAX_INPUT_LENGTH = 2048


class TargetKind:
    """Kinds of normalized target.

    Implemented as a string-constant holder rather than an ``Enum`` so it can be
    embedded in Pydantic models without serialization surprises, while still
    offering a ``values()`` helper for validation and docs.
    """

    DOMAIN: str = "DOMAIN"
    SUBDOMAIN: str = "SUBDOMAIN"
    WILDCARD: str = "WILDCARD"
    IPV4: str = "IPV4"
    IPV6: str = "IPV6"
    APEX: str = "APEX"

    @classmethod
    def values(cls) -> tuple[str, ...]:
        return (
            cls.APEX,
            cls.DOMAIN,
            cls.SUBDOMAIN,
            cls.WILDCARD,
            cls.IPV4,
            cls.IPV6,
        )


class Target(SchemaVersioned):
    """A normalized scan target."""

    #: Original, unmodified input (for reports and audit trails).
    raw_input: str
    kind: str = TargetKind.DOMAIN
    #: Canonical hostname (lower-case, no root dot, punycoded when IDN).
    hostname: str
    #: Registrable domain used for scope checks (``a.example.com`` -> ``example.com``).
    domain: str = ""
    #: Unicode representation of ``hostname`` when the input was an IDN.
    unicode_name: str = ""
    port: int | None = None
    scheme: str = ""
    path: str = ""
    is_ip: bool = False
    ip_version: int | None = None
    is_wildcard: bool = False
    #: Hostname with any leading ``*.`` removed.
    query_name: str = ""
    #: Parent of ``hostname`` (empty for apex/IP).
    parent: str = ""
    #: Where the value came from, for diagnostics.
    origin: str = "cli"

    model_config = SchemaVersioned.model_config

    @field_validator("hostname", "domain", "query_name", "parent", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value

    # ------------------------------------------------------------------ parse

    @classmethod
    def parse(cls, value: str, *, origin: str = "cli") -> "Target":
        """Normalize ``value`` into a :class:`Target`.

        Raises:
            TargetError: if the value cannot be interpreted as a DNS target.
        """
        result = cls.try_parse(value, origin=origin)
        if result.error:
            raise TargetError(result.error, details={"input": value})
        assert result.target is not None  # noqa: S101 - guaranteed by absence of error
        return result.target

    @classmethod
    def try_parse(cls, value: str, *, origin: str = "cli") -> "TargetParseResult":
        """Non-raising variant of :meth:`parse` used by bulk imports."""
        return cls._parse(value, origin=origin)

    @classmethod
    def _parse(cls, value: str, *, origin: str) -> "TargetParseResult":
        if value is None:
            return TargetParseResult(error="target must not be empty")
        text = str(value).strip()
        if not text:
            return TargetParseResult(error="target must not be empty")
        if len(text) > _MAX_INPUT_LENGTH:
            return TargetParseResult(error=f"target exceeds {_MAX_INPUT_LENGTH} characters")
        if text.startswith("-") or " " in text:
            return TargetParseResult(error=f"target contains invalid characters: {value!r}")

        unicode_name = ""
        scheme = ""
        port: int | None = None
        path = ""
        is_wildcard = False

        candidate = text

        # ---- scheme / URL -------------------------------------------------
        if "://" in candidate:
            scheme_part, _, rest = candidate.partition("://")
            scheme = scheme_part.lower()
            if scheme not in _ALLOWED_SCHEMES:
                return TargetParseResult(error=f"unsupported scheme {scheme!r} in target {value!r}")
            candidate = rest
            authority, _, tail = candidate.partition("/")
            if tail:
                path = "/" + tail.split("?", 1)[0].split("#", 1)[0]
            candidate = authority
        else:
            # ``example.com/path`` without a scheme.
            if "/" in candidate and not is_ip_literal(candidate.split("/", 1)[0]):
                authority, _, tail = candidate.partition("/")
                path = "/" + tail.split("?", 1)[0].split("#", 1)[0]
                candidate = authority

        candidate = unquote(candidate).strip()
        if candidate.startswith("@"):
            candidate = candidate[1:]

        # ---- userinfo / credentials --------------------------------------
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[1]

        # ---- wildcard -----------------------------------------------------
        if candidate.startswith("*."):
            is_wildcard = True
            candidate = candidate[2:]
        elif candidate == "*":
            return TargetParseResult(error="bare wildcard '*' is not a scannable target")

        # ---- IPv6 ---------------------------------------------------------
        if candidate.startswith("["):
            host_part, _, remainder = candidate.partition("]")
            host_part = host_part[1:]
            port_part = remainder[1:] if remainder.startswith(":") else ""
            port = _parse_port(port_part)
            if port is None and port_part:
                return TargetParseResult(error=f"invalid port in target {value!r}")
            candidate = host_part
            if not is_ip_literal(candidate):
                return TargetParseResult(error=f"invalid IPv6 target {value!r}")
            address = ipaddress.ip_address(candidate)
            return TargetParseResult(
                target=cls(
                    raw_input=value,
                    kind=TargetKind.IPV6,
                    hostname=str(address),
                    domain=str(address),
                    query_name=str(address),
                    port=port,
                    scheme=scheme,
                    path=path,
                    is_ip=True,
                    ip_version=6,
                    origin=origin,
                )
            )

        # ---- port ---------------------------------------------------------
        if ":" in candidate:
            host_part, _, port_part = candidate.rpartition(":")
            if not host_part:
                return TargetParseResult(error=f"invalid target {value!r}")
            parsed_port = _parse_port(port_part)
            if parsed_port is None:
                return TargetParseResult(error=f"invalid port {port_part!r} in target {value!r}")
            candidate = host_part
            port = parsed_port

        # ---- IP literal ---------------------------------------------------
        if is_ip_literal(candidate):
            address = ipaddress.ip_address(candidate)
            kind = TargetKind.IPV4 if address.version == 4 else TargetKind.IPV6
            return TargetParseResult(
                target=cls(
                    raw_input=value,
                    kind=kind,
                    hostname=str(address),
                    domain=str(address),
                    query_name=str(address),
                    port=port,
                    scheme=scheme,
                    path=path,
                    is_ip=True,
                    ip_version=address.version,
                    origin=origin,
                )
            )

        # ---- hostname -----------------------------------------------------
        hostname = normalize_hostname(candidate)
        if not hostname:
            return TargetParseResult(error=f"no hostname found in target {value!r}")

        try:
            ascii_name = hostname.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            ascii_name = hostname
        try:
            unicode_name = ascii_name.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            unicode_name = hostname

        if not valid_hostname(ascii_name):
            return TargetParseResult(error=f"invalid hostname in target {value!r}")

        base = registered_domain(ascii_name)
        parent = parent_domain(ascii_name)
        if is_wildcard:
            kind = TargetKind.WILDCARD
        elif ascii_name == base:
            kind = TargetKind.APEX
        else:
            kind = TargetKind.SUBDOMAIN if parent and parent != ascii_name else TargetKind.DOMAIN

        return TargetParseResult(
            target=cls(
                raw_input=value,
                kind=kind,
                hostname=ascii_name,
                domain=base,
                unicode_name=unicode_name if unicode_name != ascii_name else "",
                port=port,
                scheme=scheme,
                path=path,
                is_ip=False,
                is_wildcard=is_wildcard,
                query_name=ascii_name,
                parent=parent,
                origin=origin,
            )
        )

    # ----------------------------------------------------------------- helpers

    @property
    def display_name(self) -> str:
        """Human friendly representation used in tables."""
        prefix = "*." if self.is_wildcard else ""
        suffix = f":{self.port}" if self.port else ""
        name = self.unicode_name or self.hostname
        return f"{prefix}{name}{suffix}"

    @property
    def scope_root(self) -> str:
        """Name that scope rules are evaluated against."""
        return self.domain or self.hostname

    @property
    def supports_dns(self) -> bool:
        """``False`` for pure IP targets where name queries are meaningless."""
        return not self.is_ip

    def subdomain_of(self, domain: str) -> bool:
        """Return ``True`` when this target lives inside ``domain``."""
        from dnscope.utils.domains import is_subdomain_of

        return is_subdomain_of(self.hostname, domain)

    def with_hostname(self, hostname: str) -> "Target":
        """Derive a related target (e.g. a discovered subdomain)."""
        return Target.parse(hostname, origin=f"derived:{self.hostname}")

    def cache_key(self) -> str:
        """Stable key for caching analyses of this target."""
        return f"{self.kind}:{self.hostname}:{self.port or ''}"

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.display_name


def _parse_port(value: str) -> int | None:
    """Parse a port string, returning ``None`` when invalid."""
    if not value:
        return None
    if not value.isdigit():
        return None
    number = int(value)
    if not 0 <= number <= 65535:
        return None
    return number


class TargetParseResult(SchemaVersioned):
    """Outcome of :meth:`Target.try_parse` (never raises)."""

    target: Target | None = None
    error: str = ""
    input: str = ""  # noqa: A003 - mirrors the user's input for reports

    @property
    def ok(self) -> bool:
        return self.target is not None


class NormalizedTarget(SchemaVersioned):
    """Serializable summary of a target, used inside report payloads."""

    input: str
    hostname: str
    domain: str = ""
    kind: str = TargetKind.DOMAIN
    port: int | None = None
    scheme: str = ""
    path: str = ""
    is_ip: bool = False
    is_wildcard: bool = False

    @classmethod
    def from_target(cls, target: Target) -> "NormalizedTarget":
        """Build the summary form of ``target``."""
        return cls(
            input=target.raw_input,
            hostname=target.hostname,
            domain=target.domain,
            kind=target.kind,
            port=target.port,
            scheme=target.scheme,
            path=target.path,
            is_ip=target.is_ip,
            is_wildcard=target.is_wildcard,
        )


_WILDCARD_RE = re.compile(r"^\*\.(.+)$")


def parse_targets(values: list[str] | tuple[str, ...], *, origin: str = "cli") -> list[Target]:
    """Normalize a list of inputs, raising on the first invalid entry."""
    return [Target.parse(value, origin=origin) for value in values if str(value).strip()]


def parse_targets_lenient(
    values: list[str] | tuple[str, ...],
    *,
    origin: str = "bulk",
) -> tuple[list[Target], list[str]]:
    """Normalize a list, returning ``(targets, errors)`` instead of raising.

    Used by :mod:`dnscope.cli.commands.bulk` so one malformed line in a file of
    thousands cannot abort the run.
    """
    targets: list[Target] = []
    errors: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text.startswith("#"):
            continue
        result = Target.try_parse(text, origin=origin)
        if result.target is not None:
            targets.append(result.target)
        else:
            errors.append(f"{text}: {result.error}")
    return targets, errors


def wildcard_to_domain(value: str) -> str:
    """``*.example.com`` -> ``example.com`` (unchanged otherwise)."""
    match = _WILDCARD_RE.match(value.strip())
    return match.group(1) if match else value.strip()


def load_targets_file(path: str, *, max_targets: int = 10_000) -> tuple[list[Target], list[str]]:
    """Load targets from a text file (one per line, ``#`` comments allowed).

    The file is read line-by-line so very large lists do not need to be held in
    memory at once, and ``max_targets`` enforces the configured input limit.
    """
    from pathlib import Path

    from dnscope.exceptions import LimitsExceeded

    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise TargetError(f"target file not found: {path}")

    targets: list[Target] = []
    errors: list[str] = []
    with open(file_path, encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if len(targets) >= max_targets:
                raise LimitsExceeded(
                    f"target file contains more than {max_targets} targets",
                    details={"file": str(file_path), "limit": max_targets},
                )
            result = Target.try_parse(text, origin=f"file:{file_path.name}:{line_no}")
            if result.target is not None:
                targets.append(result.target)
            else:
                errors.append(f"line {line_no}: {result.error}")
    return targets, errors

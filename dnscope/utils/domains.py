"""Hostname and domain helpers.

Everything here is pure computation - no I/O - which keeps target handling fast
and easy to property-test.
"""

from __future__ import annotations

import ipaddress
import re

#: Conservative multi-part public suffixes. DNScope ships this short, explicit
#: list instead of a full PSL download so offline installs stay correct for the
#: overwhelmingly common cases; unknown TLDs fall back to a single label.
MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "net.uk",
        "sch.uk",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "ac.in",
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "edu.au",
        "id.au",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.mx",
        "org.mx",
        "gob.mx",
        "com.tr",
        "net.tr",
        "org.tr",
        "gov.tr",
        "com.ru",
        "net.ru",
        "org.ru",
        "com.sg",
        "net.sg",
        "org.sg",
        "edu.sg",
        "gov.sg",
        "com.hk",
        "org.hk",
        "net.hk",
        "gov.hk",
        "com.tw",
        "org.tw",
        "net.tw",
        "gov.tw",
        "com.ar",
        "co.za",
        "org.za",
        "web.za",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "com.my",
        "net.my",
        "org.my",
        "com.ph",
        "co.kr",
        "or.kr",
        "co.id",
        "or.id",
        "com.vn",
        "com.pl",
        "com.ua",
        "com.sa",
        "com.eg",
        "com.ng",
        "co.ke",
        "com.pe",
        "com.co",
        "com.ec",
        "com.uy",
        "com.py",
        "com.bo",
        "com.ve",
        "com.do",
        "com.gt",
        "com.pa",
        "com.cu",
        "co.il",
        "org.il",
        "net.il",
        "gov.il",
        "com.pt",
        "com.gr",
        "com.cy",
        "com.ro",
        "com.hr",
        "com.sk",
        "com.cz",
        "com.hu",
        "com.bg",
        "com.rs",
        "com.ba",
        "com.mk",
        "com.al",
        "com.ge",
        "com.am",
        "com.az",
        "com.kz",
        "com.uz",
        "com.pk",
        "com.bd",
        "com.lk",
        "com.np",
        "com.mm",
        "com.kh",
        "com.la",
    }
)

_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_IDNA_LABEL_RE = re.compile(r"^xn--[A-Za-z0-9-]{1,59}$")
MAX_HOSTNAME_LENGTH = 253


def valid_hostname(hostname: str) -> bool:
    """Return ``True`` when ``hostname`` is a syntactically valid DNS name.

    Accepts a trailing root dot, underscores (common for ``_dmarc`` style
    service labels) and IDN A-labels. Rejects empty labels and over-long names.
    """
    if not hostname:
        return False
    name = hostname.rstrip(".")
    if not name or len(name) > MAX_HOSTNAME_LENGTH:
        return False
    if name.startswith(".") or ".." in name:
        return False
    for label in name.split("."):
        if not label or len(label) > 63:
            return False
        if not (_LABEL_RE.match(label) or _IDNA_LABEL_RE.match(label)):
            return False
    return True


def normalize_hostname(value: str) -> str:
    """Lowercase, strip whitespace/root dot and normalize a hostname."""
    text = (value or "").strip().strip(".").lower()
    # Remove any accidental scheme or path that survived upstream normalization.
    if "://" in text:
        text = text.split("://", 1)[1]
    for sep in ("/", "?", "#", ":"):
        if sep in text:
            text = text.split(sep, 1)[0]
    return text.strip(".").lower()


def is_ip_literal(value: str) -> bool:
    """Return ``True`` for IPv4/IPv6 literals (bracketed form accepted)."""
    text = (value or "").strip().strip("[]")
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal, returning ``None`` when it is not an address."""
    text = (value or "").strip().strip("[]")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def public_suffix_len(hostname: str) -> int:
    """Number of labels in the public suffix of ``hostname``."""
    name = normalize_hostname(hostname)
    if not name:
        return 0
    labels = name.split(".")
    if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return 2
    return 1


def registered_domain(hostname: str) -> str:
    """Return the registrable domain (``api.a.example.co.uk`` -> ``example.co.uk``)."""
    name = normalize_hostname(hostname)
    if not name:
        return ""
    labels = name.split(".")
    suffix = public_suffix_len(name)
    if len(labels) <= suffix:
        return name
    return ".".join(labels[-(suffix + 1) :])


def parent_domain(hostname: str) -> str:
    """Return the parent name, e.g. ``a.b.example.com`` -> ``b.example.com``."""
    name = normalize_hostname(hostname)
    labels = name.split(".")
    if len(labels) <= 1:
        return ""
    return ".".join(labels[1:])


def domain_depth(hostname: str) -> int:
    """Number of labels below the registrable domain."""
    name = normalize_hostname(hostname)
    if not name:
        return 0
    base = registered_domain(name)
    if not base or name == base:
        return 0
    return max(0, len(name.split(".")) - len(base.split(".")))


def is_subdomain_of(hostname: str, domain: str, *, include_self: bool = True) -> bool:
    """Return ``True`` when ``hostname`` is within ``domain``."""
    host = normalize_hostname(hostname)
    parent = normalize_hostname(domain)
    if not host or not parent:
        return False
    if host == parent:
        return include_self
    return host.endswith(f".{parent}")


def wildcard_strip(hostname: str) -> str:
    """Remove a leading ``*.`` wildcard marker."""
    return hostname[2:] if hostname.startswith("*.") else hostname


def looks_like_wildcard_artifact(hostname: str) -> bool:
    """Detect obvious wildcard-response artifacts (e.g. ``*.example.com``)."""
    host = normalize_hostname(hostname)
    return "*" in host or (host.startswith("_") and not valid_hostname(host))


def labels(hostname: str) -> list[str]:
    """Split a normalized hostname into labels."""
    return normalize_hostname(hostname).split(".") if hostname else []


def is_private_ip(value: str) -> bool:
    """Return ``True`` for RFC1918/ULA/loopback/link-local addresses."""
    address = parse_ip(value)
    if address is None:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def reverse_pointer(ip: str) -> str | None:
    """Return the PTR name for an IP literal (``in-addr.arpa``/``ip6.arpa``)."""
    address = parse_ip(ip)
    if address is None:
        return None
    return address.reverse_pointer


#: Cymru's ASN information zone (``AS<number>.asn.cymru.com``).
ASN_ZONE = "asn.cymru.com"

#: ASNs that are not routable origins (bogon, documentation, AS_TRANS).
BOGON_ASNS = frozenset({"AS0", "AS23456", "AS64496", "AS65535", "AS65551", "AS65552", "AS131072"})


def format_asn(value: int | str | None) -> str:
    """Normalize an ASN to the ``AS12345`` form."""
    if value in (None, ""):
        return ""
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    text = text.strip()
    if not text.isdigit():
        return ""
    return f"AS{text}"

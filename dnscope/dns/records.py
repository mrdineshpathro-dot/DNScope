"""DNS record normalization.

dnspython gives us typed rdata objects; DNScope needs *stable, comparable*
representations so that change detection, fingerprinting and graph building all
operate on the same shape. This module is the single place that converts an
``dns.rdtypes`` object into plain Python data.
"""

from __future__ import annotations

from typing import Any

import dns.rdatatype
import dns.rdtypes.ANY.CAA
import dns.rdtypes.IN.A
import dns.rdtypes.mxbase

from dnscope.models.common import Confidence, EvidenceQuality, SourceRecord
from dnscope.models.dns import DNSRecord
from dnscope.utils.time_utils import utc_now_iso


def record_type_name(rdtype: Any) -> str:
    """Return the canonical name of a dnspython rdatatype."""
    if isinstance(rdtype, str):
        return rdtype.upper()
    try:
        return dns.rdatatype.to_text(rdtype).upper()
    except Exception:
        return f"TYPE{int(rdtype)}"


def normalize_rdata(rdtype_name: str, rdata: Any) -> tuple[list[str], dict[str, Any]]:
    """Convert one rdata object into ``(presentation strings, parsed fields)``.

    Never raises: an unparseable record degrades to its ``to_text()`` form so a
    single exotic RR cannot abort an entire scan.
    """
    handler = _PARSERS.get(rdtype_name)
    presentation = [str(rdata.to_text())]
    if handler is None:
        return presentation, {"raw": presentation[0]}
    try:
        parsed = handler(rdata)
    except Exception:
        return presentation, {"raw": presentation[0]}
    return presentation, parsed


# --------------------------------------------------------------- per-type logic


def _parse_a(rdata: Any) -> dict[str, Any]:
    return {"address": str(rdata.address), "version": 4}


def _parse_aaaa(rdata: Any) -> dict[str, Any]:
    return {"address": str(rdata.address), "version": 6}


def _parse_target(rdata: Any) -> dict[str, Any]:
    """CNAME / NS / PTR / DNAME share a single ``target`` field."""
    return {"target": str(rdata.target).rstrip(".").lower()}


def _parse_mx(rdata: Any) -> dict[str, Any]:
    return {
        "preference": int(rdata.preference),
        "exchange": str(rdata.exchange).rstrip(".").lower(),
    }


def _parse_txt(rdata: Any) -> dict[str, Any]:
    """TXT records are one or more character-strings; join them faithfully."""
    parts = []
    for chunk in getattr(rdata, "strings", []) or []:
        if isinstance(chunk, bytes):
            parts.append(chunk.decode("utf-8", errors="replace"))
        else:
            parts.append(str(chunk))
    text = "".join(parts)
    parsed: dict[str, Any] = {"text": text, "strings": parts, "count": len(parts)}
    lowered = text.lower().strip()
    if lowered.startswith("v=spf1"):
        parsed["kind"] = "spf"
    elif lowered.startswith("v=dmarc1"):
        parsed["kind"] = "dmarc"
    elif lowered.startswith("v=mta-sts"):
        parsed["kind"] = "mta-sts"
    elif lowered.startswith("v=tlsrpt"):
        parsed["kind"] = "tls-rpt"
    elif lowered.startswith("v=dkim1"):
        parsed["kind"] = "dkim"
    elif lowered.startswith("v=spf2"):
        parsed["kind"] = "sender-id"
    elif "google-site-verification" in lowered:
        parsed["kind"] = "site-verification"
    elif lowered.startswith("apple-domain-verification"):
        parsed["kind"] = "apple-verification"
    elif lowered.startswith("ms="):
        parsed["kind"] = "microsoft-verification"
    elif lowered.startswith("atlassian-domain-verification"):
        parsed["kind"] = "atlassian-verification"
    else:
        parsed["kind"] = "text"
    return parsed


def _parse_soa(rdata: Any) -> dict[str, Any]:
    return {
        "mname": str(rdata.mname).rstrip(".").lower(),
        "rname": str(rdata.rname).rstrip(".").lower(),
        "serial": int(rdata.serial),
        "refresh": int(rdata.refresh),
        "retry": int(rdata.retry),
        "expire": int(rdata.expire),
        "minimum": int(rdata.minimum),
    }


def _decode_text(value: Any) -> str:
    """Decode a dnspython ``bytes`` presentation field into text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _parse_caa(rdata: Any) -> dict[str, Any]:
    return {
        "flags": int(rdata.flags),
        "critical": bool(int(rdata.flags) & 0x80),
        # ``tag`` and ``value`` are bytes in dnspython: str(b"issue") would give
        # "b'issue'", so decode them explicitly.
        "tag": _decode_text(getattr(rdata, "tag", b"")).strip().lower(),
        "value": _decode_text(getattr(rdata, "value", b"")).strip().strip('"').lower(),
    }


def _parse_srv(rdata: Any) -> dict[str, Any]:
    return {
        "priority": int(rdata.priority),
        "weight": int(rdata.weight),
        "port": int(rdata.port),
        "target": str(rdata.target).rstrip(".").lower(),
    }


def _parse_naptr(rdata: Any) -> dict[str, Any]:
    def _decode(value: Any) -> str:
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)

    return {
        "order": int(rdata.order),
        "preference": int(rdata.preference),
        "flags": _decode(rdata.flags),
        "service": _decode(rdata.service),
        "regexp": _decode(rdata.regexp),
        "replacement": str(rdata.replacement).rstrip(".").lower(),
    }


def _parse_dnskey(rdata: Any) -> dict[str, Any]:
    flags = int(rdata.flags)
    key_b64 = rdata.key
    if isinstance(key_b64, bytes):
        key_b64 = key_b64.decode("ascii", errors="replace")
    return {
        "flags": flags,
        "zone_key": bool(flags & 0x0100),
        "secure_entry_point": bool(flags & 0x0001),
        "revoke": bool(flags & 0x0080),
        "protocol": int(rdata.protocol),
        "algorithm": int(rdata.algorithm),
        "algorithm_name": _dnssec_algorithm_name(int(rdata.algorithm)),
        "key_size_bits": _estimated_key_bits(key_b64, int(rdata.algorithm)),
    }


def _parse_ds(rdata: Any) -> dict[str, Any]:
    digest = getattr(rdata, "digest", b"")
    if isinstance(digest, bytes):
        digest = digest.hex()
    return {
        "key_tag": int(rdata.key_tag),
        "algorithm": int(rdata.algorithm),
        "algorithm_name": _dnssec_algorithm_name(int(rdata.algorithm)),
        "digest_type": int(rdata.digest_type),
        "digest": str(digest),
    }


def _parse_rrsig(rdata: Any) -> dict[str, Any]:
    signature = getattr(rdata, "signature", b"")
    if isinstance(signature, bytes):
        signature = signature.hex()
    return {
        "signature": str(signature)[:128],
        "type_covered": record_type_name(rdata.type_covered),
        "algorithm": int(rdata.algorithm),
        "algorithm_name": _dnssec_algorithm_name(int(rdata.algorithm)),
        "labels": int(rdata.labels),
        "original_ttl": int(rdata.original_ttl),
        "expiration": _dnssec_time(rdata.expiration),
        "inception": _dnssec_time(rdata.inception),
        "key_tag": int(rdata.key_tag),
        "signer": str(rdata.signer).rstrip(".").lower(),
    }


def _parse_nsec(rdata: Any) -> dict[str, Any]:
    return {
        "next": str(rdata.next).rstrip(".").lower(),
        "types": sorted({record_type_name(item) for item in getattr(rdata, "windows", [])}),
    }


def _parse_nsec3(rdata: Any) -> dict[str, Any]:
    salt = getattr(rdata, "salt", b"")
    if isinstance(salt, bytes):
        salt = salt.hex()
    return {
        "algorithm": int(rdata.algorithm),
        "flags": int(rdata.flags),
        "opt_out": bool(int(rdata.flags) & 0x01),
        "iterations": int(rdata.iterations),
        "salt": str(salt),
        "next": str(rdata.next),
    }


def _parse_tlsa(rdata: Any) -> dict[str, Any]:
    cert = getattr(rdata, "cert", b"")
    if isinstance(cert, bytes):
        cert = cert.hex()
    return {
        "usage": int(rdata.usage),
        "selector": int(rdata.selector),
        "matching_type": int(rdata.mtype),
        "certificate_association_data": str(cert),
    }


def _parse_sshfp(rdata: Any) -> dict[str, Any]:
    fingerprint = getattr(rdata, "fingerprint", b"")
    if isinstance(fingerprint, bytes):
        fingerprint = fingerprint.hex()
    return {
        "algorithm": int(rdata.algorithm),
        "fingerprint_type": int(rdata.fp_type),
        "fingerprint": str(fingerprint),
    }


def _parse_loc(rdata: Any) -> dict[str, Any]:
    return {"raw": str(rdata.to_text())}


def _parse_svcb(rdata: Any) -> dict[str, Any]:
    params: dict[str, str] = {}
    for key in getattr(rdata, "params", {}) or {}:
        try:
            params[str(key)] = str(rdata.params[key])
        except Exception:
            params[str(key)] = ""
    return {
        "priority": int(rdata.priority),
        "alias_mode": int(rdata.priority) == 0,
        "target": str(getattr(rdata, "target", "")).rstrip(".").lower(),
        "params": params,
    }


_PARSERS: dict[str, Any] = {
    "A": _parse_a,
    "AAAA": _parse_aaaa,
    "CNAME": _parse_target,
    "NS": _parse_target,
    "PTR": _parse_target,
    "DNAME": _parse_target,
    "MX": _parse_mx,
    "TXT": _parse_txt,
    "SPF": _parse_txt,
    "SOA": _parse_soa,
    "CAA": _parse_caa,
    "SRV": _parse_srv,
    "NAPTR": _parse_naptr,
    "DNSKEY": _parse_dnskey,
    "DS": _parse_ds,
    "RRSIG": _parse_rrsig,
    "NSEC": _parse_nsec,
    "NSEC3": _parse_nsec3,
    "TLSA": _parse_tlsa,
    "SSHFP": _parse_sshfp,
    "LOC": _parse_loc,
    "SVCB": _parse_svcb,
    "HTTPS": _parse_svcb,
}


def _dnssec_time(value: Any) -> str:
    """Convert a dnspython DNSSEC timestamp to ISO-8601."""
    from datetime import UTC, datetime

    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    if number <= 0:
        return ""
    return datetime.fromtimestamp(number, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dnssec_algorithm_name(algorithm: int) -> str:
    """Human-readable DNSSEC algorithm name (RFC 8624 registry)."""
    return {
        1: "RSA/MD5",
        3: "DSA/SHA1",
        5: "RSA/SHA-1",
        6: "DSA-NSEC3-SHA1",
        7: "RSASHA1-NSEC3-SHA1",
        8: "RSA/SHA-256",
        10: "RSA/SHA-512",
        12: "ECC-GOST",
        13: "ECDSA-P256-SHA256",
        14: "ECDSA-P384-SHA384",
        15: "ED25519",
        16: "ED448",
    }.get(algorithm, f"UNKNOWN({algorithm})")


def _estimated_key_bits(key_b64: str, algorithm: int) -> int | None:
    """Estimate the public-key size in bits from the base64 blob.

    RSA keys can be measured exactly (modulus length); EC algorithms have fixed
    sizes. The value is labelled an estimate in reports.
    """
    import base64

    if algorithm in (13,):
        return 256
    if algorithm in (14,):
        return 384
    if algorithm in (15,):
        return 256
    if algorithm in (16,):
        return 456
    if algorithm not in (1, 5, 7, 8, 10):
        return None
    try:
        raw = base64.b64decode(key_b64)
    except Exception:
        return None
    if len(raw) < 3:
        return None
    exponent_length = raw[0]
    if exponent_length == 0:
        return None
    if exponent_length > 127:  # two-byte length prefix
        modulus_length = len(raw) - 3
    else:
        modulus_length = len(raw) - 1 - exponent_length
    return max(0, modulus_length * 8)


# --------------------------------------------------------------- DNSRecord API


def to_dns_record(
    rrset_name: str,
    rtype: str,
    rdata: Any,
    *,
    ttl: int,
    resolver: str = "",
    provider: str = "dns",
    observed_at: str | None = None,
) -> DNSRecord:
    """Build a canonical :class:`DNSRecord` from a dnspython rdata object."""
    presentation, parsed = normalize_rdata(rtype, rdata)
    return DNSRecord(
        name=str(rrset_name).rstrip(".").lower(),
        rtype=rtype,
        ttl=int(ttl),
        rdata=presentation,
        parsed=parsed,
        source=SourceRecord(
            provider=provider,
            source=resolver,
            observed_at=_as_datetime(observed_at),
            confidence=Confidence.HIGH,
            quality=EvidenceQuality.OBSERVED,
        ),
    )


def _as_datetime(value: str | None) -> Any:
    """Parse an ISO timestamp string (or return the current time)."""
    from dnscope.utils.time_utils import parse_timestamp

    if not value:
        return parse_timestamp(utc_now_iso())
    return parse_timestamp(value) or parse_timestamp(utc_now_iso())


def extract_hostnames(record: DNSRecord) -> list[str]:
    """Return any hostnames referenced by ``record`` (for graph building)."""
    parsed = record.parsed or {}
    found: list[str] = []
    for key in ("target", "exchange", "replacement"):
        value = parsed.get(key)
        if isinstance(value, str) and value:
            found.append(value.strip(".").lower())
    if record.rtype == "PTR" and record.rdata:
        found.extend(item.strip(".").lower() for item in record.rdata if item)
    return [item for item in found if item]


def extract_addresses(record: DNSRecord) -> list[str]:
    """Return IP addresses contained in ``record``."""
    parsed = record.parsed or {}
    address = parsed.get("address")
    return [str(address)] if address else []


__all__ = [
    "extract_addresses",
    "extract_hostnames",
    "normalize_rdata",
    "record_type_name",
    "to_dns_record",
]

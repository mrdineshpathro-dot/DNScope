"""DNS data models: queries, answers, resolvers, fingerprints and delegation."""

from __future__ import annotations

import statistics
from typing import Any

from pydantic import Field, field_validator

from dnscope.models.common import Confidence, SchemaVersioned, SourceRecord
from dnscope.utils.time_utils import parse_timestamp


class RecordType:
    """Canonical DNS record types supported by the engine (RFC 8482 + extensions)."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    CAA = "CAA"
    PTR = "PTR"
    SRV = "SRV"
    NAPTR = "NAPTR"
    DNAME = "DNAME"
    DNSKEY = "DNSKEY"
    DS = "DS"
    RRSIG = "RRSIG"
    NSEC = "NSEC"
    NSEC3 = "NSEC3"
    TLSA = "TLSA"
    SSHFP = "SSHFP"
    LOC = "LOC"
    SVCB = "SVCB"
    HTTPS = "HTTPS"
    ANY = "ANY"

    ALL = (
        A,
        AAAA,
        CNAME,
        MX,
        NS,
        TXT,
        SOA,
        CAA,
        PTR,
        SRV,
        NAPTR,
        DNAME,
        DNSKEY,
        DS,
        RRSIG,
        NSEC,
        NSEC3,
        TLSA,
        SSHFP,
        LOC,
        SVCB,
        HTTPS,
    )

    DNSSEC = (DNSKEY, DS, RRSIG, NSEC, NSEC3)

    #: Types that yield hostnames (used for graph building).
    NAME_VALUED = (CNAME, NS, MX, PTR, DNAME, SRV, NAPTR)

    #: Types queried for mail-security analysis.
    EMAIL = (MX, TXT, CAA)

    @classmethod
    def normalize(cls, value: str) -> str:
        """Uppercase and validate a record type name."""
        text = str(value).strip().upper()
        if text == "AAAAA" or text == "A6":
            text = "AAAA"
        if text not in cls.ALL and text != cls.ANY:
            raise ValueError(f"unsupported record type: {value!r}")
        return text

    @classmethod
    def values(cls) -> tuple[str, ...]:
        return cls.ALL


class DNSTransport:
    """Query transports."""

    UDP = "UDP"
    TCP = "TCP"
    DOH = "DOH"
    DOT = "DOT"
    SYSTEM = "SYSTEM"

    ALL = (UDP, TCP, DOH, DOT, SYSTEM)

    #: Transports that send queries to a third party over an encrypted channel.
    ENCRYPTED = (DOH, DOT)


class DNSSECStatus:
    """Validation state derived from observable DNSSEC data.

    DNScope reports *configuration* state (signed, keys present, AD bit set by
    the resolver). It never claims that validation succeeded end to end.
    """

    SIGNED = "SIGNED"
    UNSIGNED = "UNSIGNED"
    PARTIAL = "PARTIAL"
    VALIDATED = "VALIDATED"
    UNKNOWN = "UNKNOWN"

    ALL = (SIGNED, UNSIGNED, PARTIAL, VALIDATED, UNKNOWN)


class DNSRecord(SchemaVersioned):
    """A single normalized resource record."""

    name: str
    rtype: str
    ttl: int = 0
    #: Presentation-format rdata strings (e.g. ``["10 mail.example.com."]``).
    rdata: list[str] = Field(default_factory=list)
    #: Normalized/typed extraction where DNScope understands the type.
    parsed: dict[str, Any] = Field(default_factory=dict)
    class_: str = "IN"
    source: SourceRecord = Field(default_factory=SourceRecord)

    @field_validator("rtype", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return str(value).upper() if isinstance(value, str) else value

    @property
    def rdata_text(self) -> str:
        """All rdata joined into one string."""
        return ", ".join(self.rdata)

    def matches(self, other: DNSRecord) -> bool:
        """Compare identity + rdata (TTL excluded) for change detection."""
        return (
            self.name.lower() == other.name.lower()
            and self.rtype == other.rtype
            and sorted(self.rdata) == sorted(other.rdata)
        )

    def to_zone_line(self) -> str:
        """Bind-zone style rendering."""
        return f"{self.name.rstrip('.')}. {self.ttl} IN {self.rtype} {self.rdata_text}"


class DNSResponseMeta(SchemaVersioned):
    """Response-level metadata including EDNS and timing information."""

    resolver: str = ""
    transport: str = DNSTransport.UDP
    rcode: int = 0
    rcode_name: str = "NOERROR"
    #: Message flags.
    authoritative: bool = False
    recursion_desired: bool = False
    recursion_available: bool = False
    truncated: bool = False
    authentic_data: bool = False
    checking_disabled: bool = False
    #: EDNS information (``None`` when the server did not use EDNS).
    edns_version: int | None = None
    edns_payload: int | None = None
    dnssec_ok: bool = False
    edns_cookies: bool = False
    edns_options: list[str] = Field(default_factory=list)
    message_size: int = 0
    question_count: int = 0
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    duration_ms: float = 0.0
    attempts: int = 1
    tcp_fallback: bool = False
    cached: bool = False
    error: str = ""

    @property
    def flags(self) -> dict[str, bool]:
        """Flag summary used in fingerprints and reports."""
        return {
            "aa": self.authoritative,
            "rd": self.recursion_desired,
            "ra": self.recursion_available,
            "tc": self.truncated,
            "ad": self.authentic_data,
            "cd": self.checking_disabled,
            "do": self.dnssec_ok,
        }

    def edns_summary(self) -> str:
        """Human readable EDNS description."""
        if self.edns_version is None:
            return "not used"
        parts = [f"v{self.edns_version}", f"payload={self.edns_payload}"]
        if self.dnssec_ok:
            parts.append("DO")
        if self.edns_cookies:
            parts.append("COOKIE")
        if self.edns_options:
            parts.append("opts=" + ",".join(self.edns_options))
        return " ".join(parts)


class DNSQueryResult(SchemaVersioned):
    """Result of one query for one record type at one name."""

    name: str
    rtype: str
    status: str = "NOERROR"
    ok: bool = True
    records: list[DNSRecord] = Field(default_factory=list)
    meta: DNSResponseMeta = Field(default_factory=DNSResponseMeta)
    authority: list[DNSRecord] = Field(default_factory=list)
    additional: list[DNSRecord] = Field(default_factory=list)
    error: str = ""
    queried_at: str = ""
    #: ``NODATA`` means NOERROR with no answer of the requested type.
    no_data: bool = False
    nxdomain: bool = False
    #: CNAME chain observed while answering (for depth limiting).
    cname_chain: list[str] = Field(default_factory=list)

    @field_validator("queried_at", mode="before")
    @classmethod
    def _empty_str(cls, value: Any) -> Any:
        return value if isinstance(value, str) else ""

    @property
    def data_records(self) -> list[DNSRecord]:
        """Records that carry the requested data (signatures excluded).

        With DO set, a signed answer returns RRSIG records alongside the real
        data. Those are evidence about the data, not data themselves: including
        them in ``values`` would make an NS set look like three records and put
        signature text into SPF strings.
        """
        return [record for record in self.records if record.rtype not in SIGNATURE_TYPES]

    @property
    def signature_records(self) -> list[DNSRecord]:
        """RRSIG/SIG records attached to this answer."""
        return [record for record in self.records if record.rtype in SIGNATURE_TYPES]

    @property
    def answer_count(self) -> int:
        """Number of data records in the answer (signatures excluded)."""
        return len(self.data_records)

    @property
    def values(self) -> list[str]:
        """Flattened rdata values (signatures excluded)."""
        return [value for record in self.data_records for value in record.rdata]

    def rdata_set(self) -> set[str]:
        """Unique rdata across all data records."""
        return {value for record in self.data_records for value in record.rdata}

    def min_ttl(self) -> int | None:
        """Lowest TTL among the data records."""
        return min((record.ttl for record in self.data_records), default=None)

    def to_dict(self, *, exclude_none: bool = True) -> dict[str, Any]:
        data = super().to_dict(exclude_none=exclude_none)
        return data


#: Record types that sign other records rather than carrying data themselves.
SIGNATURE_TYPES = ("RRSIG", "SIG")


class DNSAnswer(SchemaVersioned):
    """Grouped answers for one name across all requested record types."""

    name: str
    queries: list[DNSQueryResult] = Field(default_factory=list)
    resolver: str = ""
    observed_at: str = ""

    @field_validator("observed_at", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        if isinstance(value, str) and value:
            parsed = parse_timestamp(value)
            return parsed.isoformat() if parsed else ""
        return value or ""

    def by_type(self, rtype: str) -> DNSQueryResult | None:
        """Return the query result for ``rtype`` if present."""
        for query in self.queries:
            if query.rtype == rtype.upper():
                return query
        return None

    def values(self, rtype: str) -> list[str]:
        """Rdata values for ``rtype`` (empty list when absent)."""
        query = self.by_type(rtype)
        return query.values if query else []

    @property
    def record_count(self) -> int:
        return sum(q.answer_count for q in self.queries)

    @property
    def errors(self) -> list[str]:
        return [q.error for q in self.queries if q.error]


class ResolverInfo(SchemaVersioned):
    """Profile of a configured or discovered resolver."""

    address: str
    name: str = ""
    transport: str = DNSTransport.UDP
    port: int = 53
    available: bool = True
    latency_ms: float = 0.0
    latency_samples: list[float] = Field(default_factory=list)
    edns_supported: bool = False
    dnssec_validating: bool = False
    tcp_supported: bool = False
    cookies_supported: bool = False
    authoritative: bool = False
    errors: list[str] = Field(default_factory=list)
    queries: int = 0

    @property
    def median_latency_ms(self) -> float:
        if not self.latency_samples:
            return self.latency_ms
        return float(statistics.median(self.latency_samples))

    def record_latency(self, duration_ms: float) -> None:
        """Track a latency sample (bounded to the last 64 samples)."""
        self.latency_samples = ([*self.latency_samples, duration_ms])[-64:]
        self.latency_ms = self.median_latency_ms
        self.queries += 1


class Fingerprint(SchemaVersioned):
    """DNS response fingerprint used for change detection.

    The fingerprint deliberately excludes TTLs by default because TTL decay
    would produce constant noise; ``ttl_pattern`` captures the *shape* of TTLs
    (distinct values, min/max) instead.
    """

    name: str
    resolver: str = ""
    response_code: str = "NOERROR"
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0
    record_types: list[str] = Field(default_factory=list)
    #: Mapping of record type -> sorted rdata values.
    rdata: dict[str, list[str]] = Field(default_factory=dict)
    ttl_pattern: dict[str, Any] = Field(default_factory=dict)
    dnssec_flags: dict[str, bool] = Field(default_factory=dict)
    nameservers: list[str] = Field(default_factory=list)
    transport: str = DNSTransport.UDP
    hash: str = ""
    observed_at: str = ""

    def compute_hash(self) -> str:
        """Stable hash over the significant fields (excludes timing)."""
        from dnscope.utils.hashing import payload_hash

        payload = {
            "name": self.name.lower(),
            "resolver": self.resolver,
            "response_code": self.response_code,
            "rdata": {k: sorted(v) for k, v in sorted(self.rdata.items())},
            "record_types": sorted(self.record_types),
            "nameservers": sorted(self.nameservers),
            "dnssec": {k: v for k, v in sorted(self.dnssec_flags.items()) if k in ("ad", "do")},
        }
        self.hash = payload_hash(payload)
        return self.hash


class DelegationLevel(SchemaVersioned):
    """One level of the authoritative delegation chain."""

    level: str
    name: str
    nameservers: list[str] = Field(default_factory=list)
    glue: list[str] = Field(default_factory=list)
    ds_records: list[str] = Field(default_factory=list)
    rcode: str = "NOERROR"
    error: str = ""


class DelegationInfo(SchemaVersioned):
    """Root -> TLD -> delegation -> authoritative map for a domain."""

    domain: str
    levels: list[DelegationLevel] = Field(default_factory=list)
    authoritative_nameservers: list[str] = Field(default_factory=list)
    in_bailiwick: list[str] = Field(default_factory=list)
    out_of_bailiwick: list[str] = Field(default_factory=list)
    consistent: bool = True
    error: str = ""

    @property
    def depth(self) -> int:
        return len(self.levels)


class NameserverProfile(SchemaVersioned):
    """Per-nameserver availability, latency and infrastructure context."""

    nameserver: str
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    ptr: list[str] = Field(default_factory=list)
    asn: str = ""
    organization: str = ""
    provider: str = ""
    country: str = ""
    response_time_ms: float | None = None
    available: bool = False
    consistent: bool = True
    errors: list[str] = Field(default_factory=list)
    rcode_seen: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.LOW

    @property
    def addresses(self) -> list[str]:
        return [*self.ipv4, *self.ipv6]

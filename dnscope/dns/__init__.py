"""DNS subsystem: engine, transports, record normalization, health and DNSSEC."""

from dnscope.dns.engine import DNSEngine, WildcardInfo, fingerprint_from_answer
from dnscope.dns.records import (
    extract_addresses,
    extract_hostnames,
    normalize_rdata,
    record_type_name,
    to_dns_record,
)
from dnscope.dns.transport import DNSTransportLayer, TransportResult, transport_label

__all__ = [
    "DNSEngine",
    "DNSTransportLayer",
    "TransportResult",
    "WildcardInfo",
    "extract_addresses",
    "extract_hostnames",
    "fingerprint_from_answer",
    "normalize_rdata",
    "record_type_name",
    "to_dns_record",
    "transport_label",
]

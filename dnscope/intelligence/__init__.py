"""Intelligence layer: registration, IP/ASN, certificate and threat context.

Everything here is *passive observation*. The layer never authenticates to a
service, never sends data about the target to a third party beyond the documented
public APIs, and never presents an unverified inference as fact: every result
carries ``provider``, ``source``, ``observed_at``, ``confidence`` and
``quality``.

When a source cannot be reached - no credentials, offline mode, or a network
failure - the result says so. DNScope does not guess what a provider would have
said.
"""

from dnscope.intelligence.asn import ASNIntelligence, ASNIntelligenceEngine, ASNSummary
from dnscope.intelligence.certificates import (
    CertificateEngine,
    CertificateReport,
    CertificateSetChange,
)
from dnscope.intelligence.enricher import EnrichmentOptions, IntelligenceEngine, IntelligenceReport
from dnscope.intelligence.ip_intel import (
    AddressRisk,
    IPIntelligenceEngine,
    IPIntelligenceReport,
)
from dnscope.intelligence.registration import RDAPClient, RegistrationData
from dnscope.intelligence.threat import ThreatIntelligence, ThreatReport

__all__ = [
    "ASNIntelligence",
    "ASNIntelligenceEngine",
    "ASNSummary",
    "AddressRisk",
    "CertificateEngine",
    "CertificateReport",
    "CertificateSetChange",
    "EnrichmentOptions",
    "IPIntelligenceEngine",
    "IPIntelligenceReport",
    "IntelligenceEngine",
    "IntelligenceReport",
    "RDAPClient",
    "RegistrationData",
    "ThreatIntelligence",
    "ThreatReport",
]

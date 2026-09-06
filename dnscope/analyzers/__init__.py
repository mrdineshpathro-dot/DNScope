"""Analysis engines that turn DNS observations into explainable conclusions.

Each analyzer is pure logic plus (optionally) DNS lookups through
:class:`dnscope.dns.engine.DNSEngine`; none of them reach the network directly.
"""

from dnscope.analyzers.cloud import CloudDetector, CloudMatch
from dnscope.analyzers.correlation import CorrelationEngine, CorrelationResult
from dnscope.analyzers.email_security import (
    DKIMAnalyzer,
    DMARCParser,
    EmailSecurityAnalyzer,
    SPFParser,
)
from dnscope.analyzers.takeover import TakeoverAnalyzer, TakeoverIndicator

__all__ = [
    "CloudDetector",
    "CloudMatch",
    "CorrelationEngine",
    "CorrelationResult",
    "DKIMAnalyzer",
    "DMARCParser",
    "EmailSecurityAnalyzer",
    "SPFParser",
    "TakeoverAnalyzer",
    "TakeoverIndicator",
]

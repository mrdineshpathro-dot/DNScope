"""Change significance engine.

Not every DNS change deserves an alert. A TTL decrementing from 300 to 299 is
noise; the apex moving to a network the organization has never used is a signal.

Classification is rule-driven and configurable, and every classification records
*why* it landed where it did so operators can tune the rules instead of arguing
about them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from dnscope.models.changes import ChangeRecord, ChangeType
from dnscope.models.common import Significance

#: Signature of a rule predicate: ``(change, context) -> (significance, reason)``.
RulePredicate = Callable[[ChangeRecord, dict[str, Any]], tuple[str, str] | None]


@dataclass
class SignificanceRule:
    """A declarative significance rule."""

    rule_id: str
    change_types: tuple[str, ...]
    significance: str
    reason: str
    #: Optional predicate for context-dependent classification.
    predicate: RulePredicate | None = None
    #: Higher priority rules win.
    priority: int = 0
    enabled: bool = True

    def applies(self, change: ChangeRecord) -> bool:
        """``True`` when this rule covers the change type."""
        return not self.change_types or change.change_type in self.change_types


def _same_network(previous: Any, current: Any) -> bool:
    """Return ``True`` when two IP sets share a /24 (or IPv6 /48)."""
    import ipaddress

    def prefixes(values: Any) -> set[str]:
        found: set[str] = set()
        for value in _as_list(values):
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                continue
            bits = 24 if address.version == 4 else 48
            found.add(str(ipaddress.ip_network(f"{address}/{bits}", strict=False).network_address))
        return found

    return bool(prefixes(previous) & prefixes(current))


def _as_list(value: Any) -> list[Any]:
    """Normalize a change value into a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _added_removed(previous: Any, current: Any) -> tuple[set[str], set[str]]:
    """Compute added/removed values between two change states."""
    before = {str(item) for item in _as_list(previous)}
    after = {str(item) for item in _as_list(current)}
    return after - before, before - after


def _txt_kind_changed(previous: Any, current: Any) -> bool:
    """Detect when a *security-relevant* TXT record changed (SPF/DMARC/DKIM)."""
    markers = ("v=spf1", "v=dmarc1", "v=dkim1", "v=mta-sts", "v=tlsrpt")

    def kinds(values: Any) -> set[str]:
        found: set[str] = set()
        for value in _as_list(values):
            text = str(value).lower()
            for marker in markers:
                if marker in text:
                    found.add(marker)
        return found

    return kinds(previous) != kinds(current)


#: DMARC enforcement levels ordered weakest -> strongest.
_DMARC_ENFORCEMENT = ("", "none", "quarantine", "reject")


def _spf_all_qualifier(text: str) -> str:
    """Return the SPF ``all`` qualifier (``+``, ``-``, ``~``, ``?``, ``none``)."""
    lowered = text.lower()
    for qualifier, name in (("+all", "+"), ("-all", "-"), ("~all", "~"), ("?all", "?")):
        if qualifier in lowered:
            return name
    return "none"


#: MTA-STS modes ordered weakest -> strongest. ``none`` and ``""`` are treated
#: identically (no enforcement) because both are observed in the wild.
_MTA_STS_MODES = ("", "none", "testing", "enforce")


def _mta_sts_mode(text: str) -> str:
    """Return the MTA-STS ``mode=`` value (``testing``/``enforce``)."""
    import re

    match = re.search(r"\bmode\s*=\s*(none|testing|enforce)", text.lower())
    return match.group(1) if match else "none"


def _dmarc_policy(text: str) -> str:
    """Return the DMARC ``p=`` value (``none``/``quarantine``/``reject``)."""
    import re

    match = re.search(r"\bp\s*=\s*(none|quarantine|reject)", text.lower())
    return match.group(1) if match else "none"


def _security_txt_weakened(previous: Any, current: Any) -> str:
    """Describe a *weakening* of a security TXT record, or return ``""``.

    Only real regressions are reported: SPF ``all`` becoming more permissive, a
    DMARC policy dropping in enforcement, or an MTA-STS/TLS-RPT record being
    removed. Everything else returns empty so the caller can fall back to the
    generic TXT classification.
    """
    before = _as_list(previous)
    after = _as_list(current)
    before_text = " ".join(str(item).lower() for item in before)
    after_text = " ".join(str(item).lower() for item in after)

    if "v=spf1" in before_text:
        previous_qualifier = _spf_all_qualifier(before_text)
        current_qualifier = _spf_all_qualifier(after_text)
        if "v=spf1" not in after_text:
            return "SPF record was removed"
        rank = {"-": 0, "~": 1, "?": 2, "+": 3, "none": 4}
        if rank.get(current_qualifier, 0) > rank.get(previous_qualifier, 0):
            return f"SPF 'all' qualifier weakened ({previous_qualifier}all -> {current_qualifier}all)"
        if "include:" in before_text and "include:" not in after_text:
            return "SPF include chain removed (all senders now matched by the default)"

    if "v=dmarc1" in before_text:
        previous_policy = _dmarc_policy(before_text)
        current_policy = _dmarc_policy(after_text)
        if "v=dmarc1" not in after_text:
            return "DMARC record was removed"
        if _DMARC_ENFORCEMENT.index(current_policy) < _DMARC_ENFORCEMENT.index(previous_policy):
            return f"DMARC enforcement weakened (p={previous_policy} -> p={current_policy})"
        if "pct=" not in before_text and "pct=" in after_text:
            return "DMARC percentage coverage reduced (pct added)"

    if "v=mta-sts" in before_text:
        if "v=mta-sts" not in after_text:
            return "MTA-STS policy record was removed"
        previous_mode = _mta_sts_mode(before_text)
        current_mode = _mta_sts_mode(after_text)
        if _MTA_STS_MODES.index(current_mode) < _MTA_STS_MODES.index(previous_mode):
            return f"MTA-STS enforcement weakened (mode={previous_mode} -> mode={current_mode})"
    if "v=tlsrpt" in before_text and "v=tlsrpt" not in after_text:
        return "TLS-RPT record was removed"
    if "v=dkim1" in before_text and "v=dkim1" not in after_text:
        return "DKIM TXT record was removed"
    return ""


def _mx_provider_changed(previous: Any, current: Any) -> bool:
    """Detect a mail-provider change (different MX domain)."""
    from dnscope.utils.domains import registered_domain

    def providers(values: Any) -> set[str]:
        return {
            registered_domain(str(value).split()[-1].strip("."))
            for value in _as_list(values)
            if str(value).strip()
        }

    return providers(previous) != providers(current)


# ------------------------------------------------------------------ rule table


def _rule_a_record(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """A/AAAA changes: same network is boring, a new network is interesting."""
    if _same_network(change.previous, change.current):
        return Significance.TRIVIAL.value, "address changed within the same network block"
    added, removed = _added_removed(change.previous, change.current)
    if added and removed:
        return Significance.HIGH.value, "resolution moved to a different network"
    if added and not removed:
        return Significance.MEDIUM.value, "additional address added"
    if removed and not added:
        return Significance.MEDIUM.value, "address removed"
    return None


def _rule_ns(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """Nameserver set changes are always high-interest."""
    added, removed = _added_removed(change.previous, change.current)
    if not added and not removed:
        return Significance.TRIVIAL.value, "nameserver set unchanged"
    if removed and added:
        return Significance.HIGH.value, "authoritative nameserver set was replaced"
    return Significance.MEDIUM.value, "authoritative nameserver set changed"


def _rule_mx(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """MX changes: provider swaps matter, preference tweaks do not."""
    if _mx_provider_changed(change.previous, change.current):
        return Significance.HIGH.value, "mail provider changed"
    return Significance.LOW.value, "MX preference or record text changed"


def _rule_txt(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """TXT changes: only security-relevant records escalate.

    A *weakening* (SPF ``+all``, DMARC ``p=none``, MTA-STS removed) is critical;
    any other change to a security record is high; ordinary TXT edits are low.
    """
    weakened = _security_txt_weakened(change.previous, change.current)
    if weakened:
        return Significance.CRITICAL.value, weakened
    if _txt_kind_changed(change.previous, change.current):
        return Significance.HIGH.value, "security-relevant TXT record changed (SPF/DMARC/DKIM/MTA-STS)"
    return Significance.LOW.value, "non-security TXT record changed"


def _rule_cname(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """CNAME changes can move traffic to a different provider."""
    from dnscope.utils.domains import registered_domain

    before = registered_domain(str(_as_list(change.previous)[0])) if _as_list(change.previous) else ""
    after = registered_domain(str(_as_list(change.current)[0])) if _as_list(change.current) else ""
    if before and after and before != after:
        return Significance.HIGH.value, f"CNAME now points to a different domain ({before} -> {after})"
    return Significance.MEDIUM.value, "CNAME target changed"


def _rule_caa(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """CAA additions/removals change which CAs may issue."""
    added, removed = _added_removed(change.previous, change.current)
    if removed and not added:
        return Significance.HIGH.value, "CAA restriction removed"
    if added and not removed:
        return Significance.MEDIUM.value, "CAA restriction added"
    return Significance.MEDIUM.value, "CAA issuer list changed"


def _rule_dnssec(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """DNSSEC state transitions.

    Handles both explicit status words (``signed`` / ``unsigned``, emitted by the
    snapshot differ) and raw record material (emitted when a DNSKEY/DS/RRSIG set
    appears or disappears), so removal is detected either way.
    """
    before_raw = _as_list(change.previous)
    after_raw = _as_list(change.current)
    before = str(before_raw[0]).lower() if before_raw else ""
    after = str(after_raw[0]).lower() if after_raw else ""

    signed_before = before in ("signed", "validated", "valid") or (
        bool(before_raw) and before not in ("unsigned", "invalid", "bogus", "none", "")
    )
    signed_after = after in ("signed", "validated", "valid") or (
        bool(after_raw) and after not in ("unsigned", "invalid", "bogus", "none", "")
    )

    if signed_before and not signed_after:
        return Significance.HIGH.value, "DNSSEC signing was removed"
    if not signed_before and signed_after:
        return Significance.MEDIUM.value, "DNSSEC signing was enabled"
    return Significance.MEDIUM.value, "DNSSEC material changed"


def _rule_ttl(change: ChangeRecord, context: dict[str, Any]) -> tuple[str, str] | None:
    """TTL changes are informational unless they drop dramatically."""
    try:
        before = float(_as_list(change.previous)[0])
        after = float(_as_list(change.current)[0])
    except (ValueError, TypeError, IndexError):
        return Significance.TRIVIAL.value, "TTL changed"
    if before and after and after < before / 10:
        return Significance.LOW.value, f"TTL dropped sharply ({before:.0f}s -> {after:.0f}s)"
    return Significance.TRIVIAL.value, "TTL changed (normal cache behaviour)"


DEFAULT_RULES: tuple[SignificanceRule, ...] = (
    SignificanceRule(
        "SIG-A-001", (ChangeType.A_CHANGED, ChangeType.AAAA_CHANGED),
        Significance.MEDIUM.value, "address record changed", predicate=_rule_a_record, priority=10,
    ),
    SignificanceRule("SIG-NS-001", (ChangeType.NS_CHANGED,), Significance.HIGH.value,
                     "nameserver set changed", predicate=_rule_ns, priority=10),
    SignificanceRule("SIG-MX-001", (ChangeType.MX_CHANGED,), Significance.MEDIUM.value,
                     "MX records changed", predicate=_rule_mx, priority=10),
    SignificanceRule("SIG-TXT-001", (ChangeType.TXT_CHANGED,), Significance.LOW.value,
                     "TXT records changed", predicate=_rule_txt, priority=10),
    SignificanceRule("SIG-CNAME-001", (ChangeType.CNAME_CHANGED,), Significance.MEDIUM.value,
                     "CNAME changed", predicate=_rule_cname, priority=10),
    SignificanceRule("SIG-CAA-001", (ChangeType.CAA_CHANGED,), Significance.MEDIUM.value,
                     "CAA records changed", predicate=_rule_caa, priority=10),
    SignificanceRule("SIG-SOA-001", (ChangeType.SOA_CHANGED,), Significance.LOW.value,
                     "SOA record changed (serial bump is routine)", priority=1),
    SignificanceRule("SIG-DNSSEC-001", (ChangeType.DNSSEC_CHANGED,), Significance.MEDIUM.value,
                     "DNSSEC state changed", predicate=_rule_dnssec, priority=10),
    SignificanceRule("SIG-TTL-001", (ChangeType.TTL_CHANGED,), Significance.TRIVIAL.value,
                     "TTL changed", predicate=_rule_ttl, priority=10),
    SignificanceRule("SIG-CERT-EXPIRED-001", (ChangeType.CERTIFICATE_EXPIRED,),
                     Significance.HIGH.value, "certificate expired", priority=5),
    SignificanceRule("SIG-CERT-ADDED-001", (ChangeType.CERTIFICATE_ADDED,),
                     Significance.MEDIUM.value, "new certificate observed", priority=5),
    SignificanceRule("SIG-CERT-ISSUER-001", (ChangeType.CERTIFICATE_ISSUER_CHANGED,),
                     Significance.HIGH.value, "certificate issuer changed", priority=5),
    SignificanceRule("SIG-CERT-KEY-001", (ChangeType.KEY_ALGORITHM_CHANGED,),
                     Significance.MEDIUM.value, "certificate key algorithm changed", priority=5),
    SignificanceRule("SIG-SAN-001", (ChangeType.SAN_CHANGED,), Significance.LOW.value,
                     "certificate SAN set changed", priority=5),
    SignificanceRule("SIG-CERT-REMOVED-001", (ChangeType.CERTIFICATE_REMOVED,),
                     Significance.LOW.value, "certificate no longer observed", priority=5),
    SignificanceRule("SIG-DANGLING-001", (ChangeType.DANGLING_DETECTED,), Significance.HIGH.value,
                     "possible dangling DNS detected", priority=8),
    SignificanceRule("SIG-ASN-001", (ChangeType.ASN_CHANGED,), Significance.MEDIUM.value,
                     "hosting ASN changed", priority=5),
    SignificanceRule("SIG-CLOUD-001", (ChangeType.CLOUD_PROVIDER_CHANGED,), Significance.MEDIUM.value,
                     "cloud/CDN provider changed", priority=5),
    SignificanceRule("SIG-SUB-ADDED-001", (ChangeType.SUBDOMAIN_ADDED,), Significance.LOW.value,
                     "new subdomain discovered", priority=1),
    SignificanceRule("SIG-SUB-REMOVED-001", (ChangeType.SUBDOMAIN_REMOVED,), Significance.LOW.value,
                     "subdomain no longer observed", priority=1),
    SignificanceRule("SIG-SUB-STATE-001", (ChangeType.SUBDOMAIN_STATE_CHANGED,),
                     Significance.LOW.value, "subdomain state changed", priority=1),
    SignificanceRule("SIG-REGISTRAR-001", (ChangeType.REGISTRAR_CHANGED,), Significance.HIGH.value,
                     "domain registrar changed", priority=5),
    SignificanceRule("SIG-EXPIRY-001", (ChangeType.EXPIRATION_CHANGED,), Significance.MEDIUM.value,
                     "domain expiration date changed", priority=5),
    SignificanceRule("SIG-POLICY-001", (ChangeType.POLICY_CHANGED,), Significance.MEDIUM.value,
                     "DNS policy violation state changed", priority=5),
    SignificanceRule("SIG-HEALTH-001", (ChangeType.HEALTH_SCORE_CHANGED,), Significance.TRIVIAL.value,
                     "health score moved", priority=0),
)


class SignificanceEngine:
    """Classifies changes using configurable rules."""

    def __init__(self, rules: Iterable[SignificanceRule] | None = None, *, extra: Iterable[SignificanceRule] = ()) -> None:
        self.rules: list[SignificanceRule] = sorted(
            [*(rules or DEFAULT_RULES), *extra],
            key=lambda rule: -rule.priority,
        )

    def classify(self, change: ChangeRecord, context: dict[str, Any] | None = None) -> ChangeRecord:
        """Assign significance (and a reason) to ``change`` in place."""
        ctx = context or {}
        for rule in self.rules:
            if not rule.enabled or not rule.applies(change):
                continue
            if rule.predicate is not None:
                outcome = rule.predicate(change, ctx)
                if outcome is None:
                    continue
                significance, reason = outcome
                change.significance = significance
                change.reason = f"{rule.rule_id}: {reason}"
                return change
            change.significance = rule.significance
            change.reason = f"{rule.rule_id}: {rule.reason}"
            return change

        # First sightings are not "changes"; mark them trivially significant.
        if change.first_observation:
            change.significance = Significance.TRIVIAL.value
            change.reason = "first observation (no previous value to compare)"
        else:
            change.significance = Significance.LOW.value
            change.reason = "no significance rule matched; defaulting to LOW"
        return change

    def classify_many(self, changes: Iterable[ChangeRecord], context: dict[str, Any] | None = None) -> list[ChangeRecord]:
        """Classify a batch of changes."""
        return [self.classify(change, context) for change in changes]

    def significant(self, changes: Iterable[ChangeRecord], minimum: str = "MEDIUM") -> list[ChangeRecord]:
        """Filter to changes at or above ``minimum`` significance."""
        threshold = Significance.coerce(minimum)
        return [
            change
            for change in changes
            if Significance.coerce(change.significance).rank >= threshold.rank
        ]

    def add_rule(self, rule: SignificanceRule) -> None:
        """Register a custom rule and re-sort by priority."""
        self.rules.append(rule)
        self.rules.sort(key=lambda item: -item.priority)


def classify_change(change: ChangeRecord, *, context: dict[str, Any] | None = None) -> ChangeRecord:
    """Convenience wrapper using the default rule set."""
    return SignificanceEngine().classify(change, context)


__all__ = [
    "DEFAULT_RULES",
    "SignificanceEngine",
    "SignificanceRule",
    "classify_change",
]

"""Built-in rule logic.

Every check follows the same contract:

* read only from :class:`~dnscope.rules.context.ScanContext`
* return zero or more :class:`~dnscope.rules.context.RuleHit`, each carrying the
  observation that justifies it
* return ``None`` (no hit) when there is not enough evidence to conclude

The last point is the important one. "No SPF record found" is a finding; "we
could not resolve the zone" is not. Rules that cannot tell the difference produce
false positives, so ambiguity is always reported as ``needs_verification`` instead
of a confident claim.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from dnscope.rules.context import RuleHit, ScanContext
from dnscope.utils.domains import normalize_hostname, registered_domain

#: Registry of named checks. YAML rules reference these by name.
_LOGIC: dict[str, Callable[[ScanContext], list[RuleHit] | None]] = {}


def logic(
    name: str,
) -> Callable[[Callable[[ScanContext], list[RuleHit] | None]], Callable[[ScanContext], list[RuleHit] | None]]:
    """Register a rule-logic predicate under ``name``."""

    def decorator(
        func: Callable[[ScanContext], list[RuleHit] | None],
    ) -> Callable[[ScanContext], list[RuleHit] | None]:
        if name in _LOGIC:
            raise ValueError(f"duplicate rule logic name: {name}")
        _LOGIC[name] = func
        return func

    return decorator


def registered_logic() -> list[str]:
    """Names of every registered check (used by ``dnscope rules list``)."""
    return sorted(_LOGIC)


def get_logic(name: str) -> Callable[[ScanContext], list[RuleHit] | None] | None:
    """Look up a check by name."""
    return _LOGIC.get(name)


def register_logic(name: str, func: Callable[[ScanContext], list[RuleHit] | None]) -> None:
    """Register a check supplied by a plugin or custom Python rule file."""
    _LOGIC[name] = func


# --------------------------------------------------------------------- helpers


def _join(values: Iterable[Any], limit: int = 6) -> str:
    """Compact rendering of a value list for evidence text."""
    items = [str(item) for item in values]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"


def _txt_values(context: ScanContext, hostname: str | None = None) -> list[str]:
    """TXT rdata as plain strings."""
    return [str(value).strip('"') for value in context.rdata("TXT", hostname)]


def _dns_evidence(context: ScanContext, rtype: str, hostname: str | None = None) -> Any:
    """Build evidence for a DNS query, whatever the answer was."""
    subject = normalize_hostname(hostname) if hostname else context.target
    status = context.status(rtype, hostname)
    values = context.rdata(rtype, hostname)
    response = _join(values) if values else (status or "no answer")
    return context.evidence(
        f"{rtype} {subject}",
        response,
        record_type=rtype,
        provider="dns",
        source=context.resolver or "configured resolver",
        raw={"status": status, "count": len(values)},
    )


# =========================================================================
# DNS
# =========================================================================


@logic("dns_ns_insufficient")
def dns_ns_insufficient(context: ScanContext) -> list[RuleHit] | None:
    """Fewer than two authoritative nameservers."""
    nameservers = context.rdata("NS")
    if context.status("NS") != "NOERROR":
        return None
    if len(nameservers) >= 2:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "NS", "count": len(nameservers)},
            evidence=[_dns_evidence(context, "NS")],
            context={"nameservers": nameservers, "count": len(nameservers)},
            description=(
                f"the zone publishes {len(nameservers)} nameserver(s); a second authoritative "
                "server is required for the zone to survive one outage"
            ),
        )
    ]


@logic("dns_ns_single_provider")
def dns_ns_single_provider(context: ScanContext) -> list[RuleHit] | None:
    """All nameservers share one hostname suffix (single failure domain)."""
    nameservers = [normalize_hostname(value) for value in context.rdata("NS")]
    if len(nameservers) < 2:
        return None
    suffixes = {registered_domain(item) for item in nameservers if item}
    if len(suffixes) != 1:
        return None
    provider = suffixes.pop()
    if provider == context.domain:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "NS", "provider": provider},
            evidence=[_dns_evidence(context, "NS")],
            context={"provider": provider, "nameservers": nameservers},
            description=f"all {len(nameservers)} nameservers are hosted by {provider}",
        )
    ]


@logic("dns_apex_missing_address")
def dns_apex_missing_address(context: ScanContext) -> list[RuleHit] | None:
    """The apex does not resolve to an address."""
    a_status = context.status("A")
    aaaa_status = context.status("AAAA")
    if a_status not in ("NOERROR", "NXDOMAIN", "") and aaaa_status not in ("NOERROR", "NXDOMAIN", ""):
        return None
    if context.rdata("A") or context.rdata("AAAA"):
        return None
    if context.rdata("MX"):
        # A mail-only apex is legitimate; do not call it broken.
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "A/AAAA"},
            evidence=[_dns_evidence(context, "A"), _dns_evidence(context, "AAAA")],
            context={"a_status": a_status, "aaaa_status": aaaa_status},
            description="the apex domain returns no A or AAAA record",
        )
    ]


@logic("dns_no_ipv6")
def dns_no_ipv6(context: ScanContext) -> list[RuleHit] | None:
    """The apex is reachable over IPv4 only."""
    if context.status("AAAA") != "NOERROR":
        return None
    if context.rdata("AAAA") or not context.rdata("A"):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "AAAA"},
            evidence=[_dns_evidence(context, "A"), _dns_evidence(context, "AAAA")],
            context={"ipv4": context.rdata("A")},
            description="the apex publishes A records but no AAAA record",
        )
    ]


@logic("dns_cname_at_apex")
def dns_cname_at_apex(context: ScanContext) -> list[RuleHit] | None:
    """A CNAME at the zone apex, which RFC 1034 forbids."""
    cnames = context.rdata("CNAME")
    if not cnames or context.target != context.domain:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "CNAME", "hostname": context.target},
            evidence=[_dns_evidence(context, "CNAME")],
            context={"cname": cnames},
            description=(
                f"the zone apex carries a CNAME ({_join(cnames, 2)}), "
                "which conflicts with the SOA and NS records"
            ),
        )
    ]


@logic("dns_soa_misconfigured")
def dns_soa_misconfigured(context: ScanContext) -> list[RuleHit] | None:
    """SOA timers that risk a zone outage."""
    records = context.records("SOA")
    if not records:
        return None
    parsed = records[0].parsed or {}
    hits: list[RuleHit] = []
    expire = int(parsed.get("expire") or 0)
    refresh = int(parsed.get("refresh") or 0)
    serial = int(parsed.get("serial") or 0)
    problems: list[str] = []
    if expire and expire < 604800:
        problems.append(f"expire={expire}s is under one week")
    if refresh and refresh > 86400:
        problems.append(f"refresh={refresh}s is over one day")
    if serial == 0:
        problems.append("serial is 0")
    if not problems:
        return None
    hits.append(
        RuleHit(
            target=context.target,
            location={"record_type": "SOA"},
            evidence=[_dns_evidence(context, "SOA")],
            context={"expire": expire, "refresh": refresh, "serial": serial, "problems": problems},
            description="SOA timers are outside the recommended range: " + "; ".join(problems),
        )
    )
    return hits


@logic("dns_ttl_very_low")
def dns_ttl_very_low(context: ScanContext) -> list[RuleHit] | None:
    """Stable records published with an unusually short TTL."""
    records = [*context.records("NS"), *context.records("SOA")]
    short = [record for record in records if 0 < int(record.ttl or 0) < 300]
    if not short:
        return None
    lowest = min(int(record.ttl) for record in short)
    return [
        RuleHit(
            target=context.target,
            location={"record_type": _join({record.rtype for record in short}, 3)},
            evidence=[_dns_evidence(context, short[0].rtype)],
            context={"lowest_ttl": lowest, "records": [record.rtype for record in short]},
            description=(
                f"delegation records carry a {lowest}s TTL, which multiplies "
                "query load on the authoritative servers"
            ),
        )
    ]


@logic("dns_wildcard_present")
def dns_wildcard_present(context: ScanContext) -> list[RuleHit] | None:
    """The zone answers for arbitrary names (wildcard)."""
    if not context.wildcard_addresses:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "A/AAAA", "hostname": "*." + context.target},
            evidence=[
                context.evidence(
                    f"wildcard probe {context.target}",
                    f"synthesized answers resolve to {_join(context.wildcard_addresses, 3)}",
                    quality="OBSERVED",
                )
            ],
            context={"addresses": context.wildcard_addresses},
            needs_verification=True,
            description=(
                "the zone answers for arbitrary hostnames, which hides typos and inflates discovery results"
            ),
        )
    ]


@logic("dns_host_unreachable")
def dns_host_unreachable(context: ScanContext) -> list[RuleHit] | None:
    """A known hostname that no longer resolves."""
    hits: list[RuleHit] = []
    for host in context.subdomains():
        if getattr(host, "state", "") != "NXDOMAIN":
            continue
        name = normalize_hostname(getattr(host, "hostname", ""))
        if not name or context.is_wildcard_artifact(name):
            continue
        hits.append(
            RuleHit(
                target=name,
                location={"record_type": "A", "hostname": name},
                evidence=[
                    context.evidence(
                        f"A {name}",
                        f"NXDOMAIN (state={getattr(host, 'state', '')})",
                        record_type="A",
                        quality="OBSERVED",
                        confidence=getattr(host, "confidence", "MEDIUM"),
                    )
                ],
                context={"sources": list(getattr(host, "sources", []))},
                description="the hostname is known from a passive source but no longer resolves",
            )
        )
    return hits or None


# =========================================================================
# DNSSEC
# =========================================================================


@logic("dnssec_missing")
def dnssec_missing(context: ScanContext) -> list[RuleHit] | None:
    """The zone is not signed."""
    analysis = context.dnssec
    if analysis is None:
        return None
    status = str(getattr(analysis, "status", "")).upper()
    if status in ("UNSIGNED", "NOT_SIGNED", "INSECURE"):
        return [
            RuleHit(
                target=context.target,
                location={"record_type": "DNSKEY"},
                evidence=[
                    context.evidence(
                        f"DNSKEY {context.target}",
                        getattr(analysis, "evidence", "") or f"status={status}",
                        record_type="DNSKEY",
                        quality="OBSERVED",
                        confidence=str(getattr(analysis, "confidence", "MEDIUM")),
                    )
                ],
                context={"status": status, "keys": len(getattr(analysis, "keys", []))},
                description="the zone publishes no DNSSEC keys, so answers cannot be authenticated",
            )
        ]
    return None


@logic("dnssec_no_ds")
def dnssec_no_ds(context: ScanContext) -> list[RuleHit] | None:
    """The zone has keys but no DS record in the parent."""
    analysis = context.dnssec
    if analysis is None:
        return None
    keys = list(getattr(analysis, "keys", []) or [])
    ds_records = list(getattr(analysis, "ds_records", []) or [])
    if not keys or ds_records:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "DS"},
            evidence=[
                context.evidence(
                    f"DS {context.target}",
                    "no DS record in the parent zone",
                    record_type="DS",
                    quality="OBSERVED",
                ),
                context.evidence(
                    f"DNSKEY {context.target}",
                    f"{len(keys)} key(s) published",
                    record_type="DNSKEY",
                    quality="OBSERVED",
                ),
            ],
            context={"keys": len(keys)},
            needs_verification=True,
            description=(
                "the zone publishes DNSKEY records but the parent has "
                "no DS record, so the chain of trust is broken"
            ),
        )
    ]


@logic("dnssec_weak_algorithm")
def dnssec_weak_algorithm(context: ScanContext) -> list[RuleHit] | None:
    """Zone keys using a deprecated algorithm."""
    from dnscope.dns.dnssec import WEAK_ALGORITHMS

    analysis = context.dnssec
    if analysis is None:
        return None
    hits: list[RuleHit] = []
    for key in getattr(analysis, "keys", []) or []:
        algorithm = int(getattr(key, "algorithm", 0) or 0)
        if algorithm not in WEAK_ALGORITHMS:
            continue
        hits.append(
            RuleHit(
                target=context.target,
                location={"record_type": "DNSKEY", "algorithm": algorithm},
                evidence=[
                    context.evidence(
                        f"DNSKEY {context.target}",
                        f"algorithm {algorithm} ({getattr(key, 'algorithm_name', '')}), "
                        f"role={getattr(key, 'role', '')}, bits={getattr(key, 'key_size_bits', '')}",
                        record_type="DNSKEY",
                        quality="OBSERVED",
                    )
                ],
                context={"algorithm": algorithm, "algorithm_name": getattr(key, "algorithm_name", "")},
                description=f"the zone uses DNSSEC algorithm {algorithm}, which is deprecated",
            )
        )
    return hits or None


@logic("dnssec_rrsig_expired")
def dnssec_rrsig_expired(context: ScanContext) -> list[RuleHit] | None:
    """Signatures past their validity window."""
    analysis = context.dnssec
    if analysis is None:
        return None
    expired = list(getattr(analysis, "rrsig_expired", []) or [])
    if not expired:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "RRSIG", "types": expired},
            evidence=[
                context.evidence(
                    f"RRSIG {context.target}",
                    f"expired signature(s) for {_join(expired, 4)}",
                    record_type="RRSIG",
                    quality="OBSERVED",
                )
            ],
            context={"expired": expired},
            description="one or more RRSIG records have passed their expiry, so validation will fail",
        )
    ]


@logic("dnssec_key_too_small")
def dnssec_key_too_small(context: ScanContext) -> list[RuleHit] | None:
    """RSA zone keys smaller than 2048 bits."""
    analysis = context.dnssec
    if analysis is None:
        return None
    hits: list[RuleHit] = []
    for key in getattr(analysis, "keys", []) or []:
        name = str(getattr(key, "algorithm_name", "")).upper()
        bits = getattr(key, "key_size_bits", None)
        if "RSA" not in name or not bits or int(bits) >= 2048:
            continue
        hits.append(
            RuleHit(
                target=context.target,
                location={"record_type": "DNSKEY", "role": getattr(key, "role", "")},
                evidence=[
                    context.evidence(
                        f"DNSKEY {context.target}",
                        f"{name} key is {bits} bits (role={getattr(key, 'role', '')})",
                        record_type="DNSKEY",
                        quality="OBSERVED",
                    )
                ],
                context={"bits": int(bits), "role": getattr(key, "role", "")},
                description=(
                    f"the {getattr(key, 'role', '') or 'zone'} key is {bits} "
                    "bits; 2048 bits is the recommended minimum"
                ),
            )
        )
    return hits or None


# =========================================================================
# Email security
# =========================================================================


def _spf(context: ScanContext) -> Any:
    """The SPF record, or ``None``."""
    return getattr(context.email, "spf", None) if context.email is not None else None


def _dmarc(context: ScanContext) -> Any:
    """The DMARC record, or ``None``."""
    return getattr(context.email, "dmarc", None) if context.email is not None else None


@logic("email_no_spf")
def email_no_spf(context: ScanContext) -> list[RuleHit] | None:
    """No SPF record published."""
    spf = _spf(context)
    if spf is None:
        return None
    if getattr(spf, "found", False):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": context.target},
            evidence=[getattr(spf, "evidence", None) or _dns_evidence(context, "TXT")],
            context={"issues": list(getattr(spf, "issues", []))},
            description=(
                "no SPF record is published, so receivers cannot tell legitimate mail from spoofed mail"
            ),
        )
    ]


@logic("email_spf_permissive")
def email_spf_permissive(context: ScanContext) -> list[RuleHit] | None:
    """SPF ``all`` mechanism that authorizes any sender."""
    spf = _spf(context)
    if spf is None or not getattr(spf, "found", False):
        return None
    qualifier = str(getattr(spf, "all_mechanism", "") or "")
    if qualifier not in ("+all", "?all"):
        return None
    severity = "CRITICAL" if qualifier == "+all" else "HIGH"
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "mechanism": qualifier},
            evidence=[getattr(spf, "evidence", None) or _dns_evidence(context, "TXT")],
            context={"all_mechanism": qualifier, "record": getattr(spf, "record", "")},
            severity=severity,
            description=(
                f"the SPF record ends in '{qualifier}', which authorizes any host to send mail for the domain"
            ),
        )
    ]


@logic("email_spf_no_all")
def email_spf_no_all(context: ScanContext) -> list[RuleHit] | None:
    """SPF without an ``all`` mechanism (implicitly neutral)."""
    spf = _spf(context)
    if spf is None or not getattr(spf, "found", False):
        return None
    if getattr(spf, "all_mechanism", "") or getattr(spf, "redirect", ""):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT"},
            evidence=[getattr(spf, "evidence", None) or _dns_evidence(context, "TXT")],
            context={"record": getattr(spf, "record", "")},
            description="the SPF record has no 'all' mechanism, so unmatched senders default to neutral",
        )
    ]


@logic("email_spf_lookup_limit")
def email_spf_lookup_limit(context: ScanContext) -> list[RuleHit] | None:
    """SPF expansion hit the RFC 7208 ten-lookup limit."""
    spf = _spf(context)
    if spf is None or not getattr(spf, "found", False):
        return None
    limit = int(getattr(spf, "max_lookups", 10) or 10)
    used = int(getattr(spf, "lookup_count", 0) or 0)
    if used < limit:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "mechanism": "include"},
            evidence=[getattr(spf, "evidence", None) or _dns_evidence(context, "TXT")],
            context={"lookups": used, "limit": limit, "chain": list(getattr(spf, "include_chain", []))},
            needs_verification=True,
            description=(
                f"SPF expansion reached the RFC 7208 limit of {limit} DNS lookups; "
                "receivers must return PermError, so mail may be rejected"
            ),
        )
    ]


@logic("email_spf_ptr_mechanism")
def email_spf_ptr_mechanism(context: ScanContext) -> list[RuleHit] | None:
    """SPF ``ptr`` mechanism, deprecated by RFC 7208."""
    spf = _spf(context)
    if spf is None or not getattr(spf, "found", False):
        return None
    if not getattr(spf, "has_mechanism", None) or not spf.has_mechanism("ptr"):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "mechanism": "ptr"},
            evidence=[getattr(spf, "evidence", None) or _dns_evidence(context, "TXT")],
            context={"record": getattr(spf, "record", "")},
            description="the SPF record uses the 'ptr' mechanism, which RFC 7208 marks as deprecated",
        )
    ]


@logic("email_no_dmarc")
def email_no_dmarc(context: ScanContext) -> list[RuleHit] | None:
    """No DMARC policy published."""
    dmarc = _dmarc(context)
    if dmarc is None:
        return None
    if getattr(dmarc, "found", False):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": f"_dmarc.{context.target}"},
            evidence=[
                getattr(dmarc, "evidence", None) or _dns_evidence(context, "TXT", f"_dmarc.{context.target}")
            ],
            context={"issues": list(getattr(dmarc, "issues", []))},
            description=(
                "no DMARC policy is published, so receivers have no instruction for failing authentication"
            ),
        )
    ]


@logic("email_dmarc_no_enforcement")
def email_dmarc_no_enforcement(context: ScanContext) -> list[RuleHit] | None:
    """DMARC published with ``p=none``."""
    dmarc = _dmarc(context)
    if dmarc is None or not getattr(dmarc, "found", False):
        return None
    policy = str(getattr(dmarc, "policy", "") or "").lower()
    if policy != "none":
        return None
    percentage = getattr(dmarc, "percentage", None)
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": f"_dmarc.{context.target}", "policy": policy},
            evidence=[
                getattr(dmarc, "evidence", None) or _dns_evidence(context, "TXT", f"_dmarc.{context.target}")
            ],
            context={"policy": policy, "rua": list(getattr(dmarc, "rua", [])), "pct": percentage},
            description="the DMARC policy is p=none, which monitors but does not stop spoofed mail",
        )
    ]


@logic("email_dmarc_partial")
def email_dmarc_partial(context: ScanContext) -> list[RuleHit] | None:
    """DMARC enforcement limited by ``pct`` or weakened for subdomains."""
    dmarc = _dmarc(context)
    if dmarc is None or not getattr(dmarc, "found", False):
        return None
    problems: list[str] = []
    percentage = getattr(dmarc, "percentage", None)
    if percentage is not None and int(percentage) < 100:
        problems.append(f"pct={percentage} leaves {100 - int(percentage)}% of mail unenforced")
    sub_policy = str(getattr(dmarc, "subdomain_policy", "") or "").lower()
    policy = str(getattr(dmarc, "policy", "") or "").lower()
    if sub_policy and policy in ("quarantine", "reject") and sub_policy == "none":
        problems.append("sp=none exempts every subdomain from the parent policy")
    if not problems:
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": f"_dmarc.{context.target}"},
            evidence=[
                getattr(dmarc, "evidence", None) or _dns_evidence(context, "TXT", f"_dmarc.{context.target}")
            ],
            context={"pct": percentage, "sp": sub_policy, "p": policy},
            description="; ".join(problems),
        )
    ]


@logic("email_dmarc_no_reporting")
def email_dmarc_no_reporting(context: ScanContext) -> list[RuleHit] | None:
    """DMARC with no aggregate report address."""
    dmarc = _dmarc(context)
    if dmarc is None or not getattr(dmarc, "found", False):
        return None
    if getattr(dmarc, "rua", None):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": f"_dmarc.{context.target}"},
            evidence=[
                getattr(dmarc, "evidence", None) or _dns_evidence(context, "TXT", f"_dmarc.{context.target}")
            ],
            context={"policy": getattr(dmarc, "policy", "")},
            description="the DMARC record has no rua address, so no aggregate reports are collected",
        )
    ]


@logic("email_dkim_weak_key")
def email_dkim_weak_key(context: ScanContext) -> list[RuleHit] | None:
    """A published DKIM key that is too small or revoked."""
    results = list(getattr(context.email, "dkim", []) or []) if context.email is not None else []
    hits: list[RuleHit] = []
    for result in results:
        if not getattr(result, "found", False):
            continue
        bits = getattr(result, "key_size_bits", None)
        selector = str(getattr(result, "selector", ""))
        if getattr(result, "revoked", False):
            hits.append(
                RuleHit(
                    target=context.target,
                    location={"record_type": "TXT", "hostname": getattr(result, "query_name", "")},
                    evidence=[getattr(result, "evidence", None) or _dns_evidence(context, "TXT")],
                    context={"selector": selector, "revoked": True},
                    description=(
                        f"the DKIM key at selector '{selector}' has an empty p= tag (revoked or placeholder)"
                    ),
                )
            )
            continue
        if bits and int(bits) < 2048:
            hits.append(
                RuleHit(
                    target=context.target,
                    location={"record_type": "TXT", "hostname": getattr(result, "query_name", "")},
                    evidence=[getattr(result, "evidence", None) or _dns_evidence(context, "TXT")],
                    context={"selector": selector, "bits": int(bits)},
                    description=(
                        f"the DKIM key at selector '{selector}' is {int(bits)} bits; 2048 bits is recommended"
                    ),
                )
            )
    return hits or None


@logic("email_no_mta_sts")
def email_no_mta_sts(context: ScanContext) -> list[RuleHit] | None:
    """MTA-STS not deployed for a domain that receives mail."""
    report = context.email
    if report is None:
        return None
    mta_sts = getattr(report, "mta_sts", None)
    if mta_sts is None or getattr(mta_sts, "found", False):
        return None
    if not getattr(report, "mx_hosts", None):
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "TXT", "hostname": f"_mta-sts.{context.target}"},
            evidence=[
                getattr(mta_sts, "evidence", None)
                or _dns_evidence(context, "TXT", f"_mta-sts.{context.target}")
            ],
            context={"mx": list(getattr(report, "mx_hosts", []))[:5]},
            description="no MTA-STS policy is published, so SMTP TLS cannot be enforced against downgrade",
        )
    ]


@logic("email_null_mx_without_rejection")
def email_null_mx_without_rejection(context: ScanContext) -> list[RuleHit] | None:
    """RFC 7505 null MX without a matching SPF ``-all``."""
    report = context.email
    if report is None:
        return None
    mx_hosts = list(getattr(report, "mx_hosts", []) or [])
    null_mx = any(str(host).strip().rstrip(".") in ("", ".") for host in mx_hosts)
    if not null_mx:
        return None
    spf = getattr(report, "spf", None)
    if spf is not None and str(getattr(spf, "all_mechanism", "")) == "-all":
        return None
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "MX"},
            evidence=[_dns_evidence(context, "MX"), _dns_evidence(context, "TXT")],
            context={"mx": mx_hosts, "spf_all": str(getattr(spf, "all_mechanism", "") or "absent")},
            description=(
                "the zone publishes a null MX (it accepts no mail) but SPF does not end in '-all'; "
                "RFC 7505 requires both"
            ),
        )
    ]


# =========================================================================
# Certificates
# =========================================================================


def _certificates(context: ScanContext) -> list[Any]:
    """Certificates from the intelligence layer."""
    if context.intelligence is None:
        return []
    report = getattr(context.intelligence, "certificates", None)
    return list(getattr(report, "certificates", []) or [])


@logic("cert_expired")
def cert_expired(context: ScanContext) -> list[RuleHit] | None:
    """A certificate whose validity has ended."""
    from dnscope.analyzers.tls_probe import describe_expiry

    hits: list[RuleHit] = []
    for certificate in _certificates(context):
        remaining = certificate.days_until_expiry()
        if remaining is None or remaining >= 0:
            continue
        hits.append(
            RuleHit(
                target=certificate.subject_cn or context.target,
                location={"fingerprint": certificate.identity[:16], "issuer": certificate.issuer_cn},
                evidence=[
                    context.evidence(
                        f"certificate {certificate.identity[:16]}",
                        describe_expiry(certificate),
                        quality="OBSERVED",
                        provider=certificate.source or "ct",
                        raw={"not_after": str(certificate.not_after), "issuer": certificate.issuer_cn},
                    )
                ],
                context={"days_remaining": remaining, "sans": certificate.subject_alternative_names[:10]},
                description=f"the certificate {describe_expiry(certificate)}",
            )
        )
    return hits or None


@logic("cert_expiring_soon")
def cert_expiring_soon(context: ScanContext) -> list[RuleHit] | None:
    """A certificate expiring within 30 days."""
    from dnscope.analyzers.tls_probe import describe_expiry
    from dnscope.intelligence.certificates import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS

    hits: list[RuleHit] = []
    for certificate in _certificates(context):
        remaining = certificate.days_until_expiry()
        if remaining is None or remaining < 0 or remaining >= EXPIRY_WARNING_DAYS:
            continue
        hits.append(
            RuleHit(
                target=certificate.subject_cn or context.target,
                location={"fingerprint": certificate.identity[:16], "issuer": certificate.issuer_cn},
                evidence=[
                    context.evidence(
                        f"certificate {certificate.identity[:16]}",
                        describe_expiry(certificate),
                        quality="OBSERVED",
                        provider=certificate.source or "ct",
                        raw={"not_after": str(certificate.not_after)},
                    )
                ],
                context={"days_remaining": remaining},
                severity="HIGH" if remaining < EXPIRY_CRITICAL_DAYS else "",
                description=f"the certificate {describe_expiry(certificate)}",
            )
        )
    return hits or None


@logic("cert_weak_material")
def cert_weak_material(context: ScanContext) -> list[RuleHit] | None:
    """A certificate with a small key or a broken signature algorithm."""
    from dnscope.intelligence.certificates import WEAK_KEY_BITS, WEAK_SIGNATURES

    hits: list[RuleHit] = []
    for certificate in _certificates(context):
        algorithm = str(certificate.public_key_algorithm or "").lower()
        bits = certificate.public_key_bits or 0
        threshold = next((limit for name, limit in WEAK_KEY_BITS.items() if name in algorithm), 0)
        signature = str(certificate.signature_algorithm or "").lower()
        problems: list[str] = []
        if threshold and bits and bits < threshold:
            problems.append(f"{algorithm.upper()} key is {bits} bits (minimum {threshold})")
        if any(needle in signature for needle in WEAK_SIGNATURES):
            problems.append(f"signature algorithm {certificate.signature_algorithm} is considered broken")
        if not problems:
            continue
        hits.append(
            RuleHit(
                target=certificate.subject_cn or context.target,
                location={
                    "fingerprint": certificate.identity[:16],
                    "algorithm": certificate.public_key_algorithm,
                },
                evidence=[
                    context.evidence(
                        f"certificate {certificate.identity[:16]}",
                        "; ".join(problems),
                        quality="OBSERVED",
                        provider=certificate.source or "ct",
                    )
                ],
                context={"bits": bits, "algorithm": algorithm, "signature": certificate.signature_algorithm},
                description="; ".join(problems),
            )
        )
    return hits or None


# =========================================================================
# Infrastructure
# =========================================================================


@logic("infra_no_caa")
def infra_no_caa(context: ScanContext) -> list[RuleHit] | None:
    """No CAA record restricting which CAs may issue."""
    report = context.email
    caa = getattr(report, "caa", None) if report is not None else None
    if caa is None:
        return None
    if getattr(caa, "restricts_issuance", False):
        return None
    found = bool(getattr(caa, "found", False))
    description = (
        "CAA records exist but none carry issue/issuewild, so any CA may issue for the domain"
        if found
        else "no CAA record restricts which certificate authorities may issue for the domain"
    )
    return [
        RuleHit(
            target=context.target,
            location={"record_type": "CAA"},
            evidence=[getattr(caa, "evidence", None) or _dns_evidence(context, "CAA")],
            context={"found": found, "records": list(getattr(caa, "records", []))[:8]},
            description=description,
        )
    ]


@logic("infra_private_address")
def infra_private_address(context: ScanContext) -> list[RuleHit] | None:
    """A public hostname resolving into private or reserved space."""
    intelligence = context.intelligence
    if intelligence is None:
        return None
    report = getattr(intelligence, "ip_intelligence", None)
    if report is None:
        return None
    hits: list[RuleHit] = []
    for risk in getattr(report, "risks", []) or []:
        flags = risk.flags()
        if "PRIVATE_ADDRESS" not in flags and "RESERVED_ADDRESS" not in flags:
            continue
        hits.append(
            RuleHit(
                target=risk.ip,
                location={"ip": risk.ip},
                evidence=[
                    context.evidence(
                        f"PTR {risk.ip}",
                        "; ".join(risk.notes) or _join(flags),
                        quality="OBSERVED",
                        provider="dns",
                    )
                ],
                context={"flags": flags, "co_hosted": risk.co_hosted[:10]},
                description=(
                    f"{risk.ip} is in {'private' if 'PRIVATE_ADDRESS' in flags else 'reserved'} address space"
                ),
            )
        )
    return hits or None


@logic("infra_ptr_mismatch")
def infra_ptr_mismatch(context: ScanContext) -> list[RuleHit] | None:
    """Reverse DNS that does not forward-confirm."""
    intelligence = context.intelligence
    if intelligence is None:
        return None
    report = getattr(intelligence, "ip_intelligence", None)
    if report is None:
        return None
    hits: list[RuleHit] = []
    for risk in getattr(report, "risks", []) or []:
        if "PTR_FORWARD_MISMATCH" not in risk.flags():
            continue
        hits.append(
            RuleHit(
                target=risk.ip,
                location={"ip": risk.ip},
                evidence=[
                    context.evidence(
                        f"PTR {risk.ip}",
                        "; ".join(risk.notes),
                        quality="OBSERVED",
                        provider="dns",
                    )
                ],
                context={"flags": risk.flags(), "co_hosted": risk.co_hosted[:10]},
                needs_verification=True,
                description=f"the reverse record for {risk.ip} does not forward-resolve back to the address",
            )
        )
    return hits or None


@logic("infra_shared_infrastructure")
def infra_shared_infrastructure(context: ScanContext) -> list[RuleHit] | None:
    """Many in-scope hosts sharing one address, ASN or nameserver."""
    hits: list[RuleHit] = []
    for group in context.correlations:
        members = list(getattr(group, "members", []) or [])
        if len(members) < 3:
            continue
        hits.append(
            RuleHit(
                target=context.target,
                location={"dimension": getattr(group, "dimension", ""), "value": getattr(group, "value", "")},
                evidence=[
                    context.evidence(
                        f"correlation {getattr(group, 'dimension', '')}={getattr(group, 'value', '')}",
                        f"{len(members)} hosts share this {_join([getattr(group, 'dimension', '')], 1)}",
                        quality="CORRELATED",
                        confidence=str(getattr(group, "confidence", "MEDIUM")),
                    )
                ],
                context={
                    "dimension": getattr(group, "dimension", ""),
                    "value": getattr(group, "value", ""),
                    "members": members[:20],
                    "count": len(members),
                },
                description=(
                    f"{len(members)} in-scope hosts share "
                    f"{getattr(group, 'dimension', 'infrastructure')} {getattr(group, 'value', '')}"
                ),
            )
        )
    return hits or None


@logic("infra_asn_concentration")
def infra_asn_concentration(context: ScanContext) -> list[RuleHit] | None:
    """Most addresses sit in a single autonomous system."""
    intelligence = context.intelligence
    if intelligence is None:
        return None
    summary = getattr(intelligence, "asn_summary", None)
    if summary is None or not getattr(summary, "concentrated", False):
        return None
    top = getattr(summary, "top_asn", "")
    share = float(getattr(summary, "top_share", 0.0))
    return [
        RuleHit(
            target=context.target,
            location={"asn": top},
            evidence=[
                context.evidence(
                    f"origin ASN for {summary.total_addresses} address(es)",
                    f"{share * 100:.0f}% are in {top}",
                    quality="OBSERVED",
                    provider="team-cymru",
                )
            ],
            context={"asn": top, "share": share, "diversity": summary.diversity_score()},
            description=(
                f"{share * 100:.0f}% of identified addresses are in {top}; an incident in that network "
                "affects most of the estate"
            ),
        )
    ]


# =========================================================================
# Takeover (passive indicators only)
# =========================================================================


@logic("takeover_dangling_dns")
def takeover_dangling_dns(context: ScanContext) -> list[RuleHit] | None:
    """A CNAME pointing at a third-party endpoint that no longer resolves.

    DNScope reports the *indicator* only. It never claims, registers or tests
    ownership of the target service, and the wording says so.
    """
    hits: list[RuleHit] = []
    for indicator in context.takeover:
        if not getattr(indicator, "is_dangling", False):
            continue
        name = normalize_hostname(getattr(indicator, "hostname", ""))
        if not name:
            continue
        evidence = [
            context.evidence(
                f"CNAME {name}",
                str(item),
                quality="OBSERVED",
                confidence=str(getattr(indicator, "confidence", "MEDIUM")),
            )
            for item in getattr(indicator, "evidence", []) or []
        ] or [_dns_evidence(context, "CNAME", name)]
        hits.append(
            RuleHit(
                target=name,
                location={
                    "record_type": "CNAME",
                    "hostname": name,
                    "cname_target": getattr(indicator, "cname_target", ""),
                },
                evidence=evidence,
                context={
                    "state": "POSSIBLE_DANGLING_CNAME",
                    "provider": getattr(indicator, "provider", ""),
                    "service": getattr(indicator, "service", ""),
                    "cname_target": getattr(indicator, "cname_target", ""),
                    "target_status": getattr(indicator, "target_status", ""),
                },
                confidence=str(getattr(indicator, "confidence", "MEDIUM")),
                needs_verification=bool(getattr(indicator, "needs_verification", True)),
                description=(
                    f"{name} points at {getattr(indicator, 'cname_target', '')} "
                    f"({getattr(indicator, 'service', '') or getattr(indicator, 'provider', '')}), "
                    "which no longer resolves. This is an indicator for the asset owner to clean up; "
                    "DNScope does not test or claim the resource."
                ),
            )
        )
    return hits or None


# =========================================================================
# Enterprise / registration / reputation
# =========================================================================


@logic("enterprise_registration_unlocked")
def enterprise_registration_unlocked(context: ScanContext) -> list[RuleHit] | None:
    """The domain registration carries no registry lock."""
    registration = getattr(context.intelligence, "registration", None) if context.intelligence else None
    if registration is None or not getattr(registration, "found", False):
        return None
    if getattr(registration, "registry_locked", False):
        return None
    return [
        RuleHit(
            target=context.domain,
            location={"registrar": getattr(registration, "registrar", "")},
            evidence=[
                context.evidence(
                    f"rdap {context.domain}",
                    f"status={_join(getattr(registration, 'status', []), 6) or 'none published'}",
                    quality="OBSERVED",
                    provider=registration.source.provider or "rdap",
                )
            ],
            context={"status": list(getattr(registration, "status", []))},
            needs_verification=True,
            description="the registration has no clientTransferProhibited (or equivalent) lock",
        )
    ]


@logic("enterprise_domain_expiring")
def enterprise_domain_expiring(context: ScanContext) -> list[RuleHit] | None:
    """The domain registration is expiring or has expired."""
    registration = getattr(context.intelligence, "registration", None) if context.intelligence else None
    if registration is None or not getattr(registration, "found", False):
        return None
    remaining = registration.days_until_expiry()
    if remaining is None or remaining >= 30:
        return None
    return [
        RuleHit(
            target=context.domain,
            location={"registrar": getattr(registration, "registrar", "")},
            evidence=[
                context.evidence(
                    f"rdap {context.domain}",
                    f"expiration={registration.expiration_date}",
                    quality="OBSERVED",
                    provider=registration.source.provider or "rdap",
                )
            ],
            context={"days_remaining": remaining, "expiration_date": registration.expiration_date},
            severity="CRITICAL" if remaining < 0 else "HIGH",
            description=(
                f"the domain registration expired {abs(remaining)} day(s) ago"
                if remaining < 0
                else f"the domain registration expires in {remaining} day(s)"
            ),
        )
    ]


@logic("enterprise_nameserver_drift")
def enterprise_nameserver_drift(context: ScanContext) -> list[RuleHit] | None:
    """Registry-published nameservers differ from live DNS."""
    registration = getattr(context.intelligence, "registration", None) if context.intelligence else None
    if registration is None or not getattr(registration, "found", False):
        return None
    drift = registration.nameserver_drift()
    if not drift["registry_only"] and not drift["dns_only"]:
        return None
    return [
        RuleHit(
            target=context.domain,
            location={"registrar": getattr(registration, "registrar", "")},
            evidence=[
                context.evidence(
                    f"rdap {context.domain}",
                    f"registry={_join(getattr(registration, 'nameservers', []), 4)}",
                    quality="OBSERVED",
                    provider=registration.source.provider or "rdap",
                ),
                _dns_evidence(context, "NS"),
            ],
            context=drift,
            needs_verification=True,
            description=(
                "the registry publishes "
                f"{_join(drift['registry_only'], 3) or 'no extra nameservers'} while DNS answers "
                f"{_join(drift['dns_only'], 3) or 'the same set'}"
            ),
        )
    ]


@logic("threat_hostile_reputation")
def threat_hostile_reputation(context: ScanContext) -> list[RuleHit] | None:
    """A third-party provider reports a hostile reputation for a subject."""
    threat = getattr(context.intelligence, "threat", None) if context.intelligence else None
    if threat is None or not getattr(threat, "available", False):
        return None
    hits: list[RuleHit] = []
    for indicator in threat.hostile():
        hits.append(
            RuleHit(
                target=str(getattr(indicator, "subject", "")),
                location={"provider": getattr(indicator, "provider", "")},
                evidence=[
                    context.evidence(
                        f"{getattr(indicator, 'provider', '')} reputation "
                        "for {getattr(indicator, 'subject', '')}",
                        getattr(indicator, "summary", lambda: "")(),
                        quality="CORRELATED",
                        confidence="MEDIUM",
                        provider=getattr(indicator, "provider", ""),
                    )
                ],
                context={
                    "score": getattr(indicator, "score", None),
                    "verdict": getattr(indicator, "verdict", ""),
                    "tags": list(getattr(indicator, "tags", []))[:10],
                },
                needs_verification=True,
                description=(
                    f"{getattr(indicator, 'provider', '')} reports a hostile reputation for this subject; "
                    "reputation feeds disagree, so verify before acting"
                ),
            )
        )
    return hits or None


@logic("intelligence_observations")
def intelligence_observations(context: ScanContext) -> list[RuleHit] | None:
    """Generic bridge for observations the intelligence layer already produced.

    Rule packs can point at this check and filter by observation id through the
    rule's ``match`` setting, so a new intelligence observation becomes a finding
    without new Python code.
    """
    if not context.observations:
        return None
    hits: list[RuleHit] = []
    for observation in context.observations:
        hits.append(
            RuleHit(
                target=str(observation.get("target", context.target)),
                location={"observation": str(observation.get("id", ""))},
                evidence=[
                    context.evidence(
                        str(observation.get("evidence", observation.get("id", ""))),
                        str(observation.get("detail", "")),
                        quality=str(observation.get("quality", "OBSERVED")),
                        provider=str(observation.get("source", "intelligence")),
                    )
                ],
                context={
                    key: value
                    for key, value in observation.items()
                    if key not in ("id", "detail", "evidence")
                },
                description=str(observation.get("detail", "")),
            )
        )
    return hits or None


__all__ = ["RuleHit", "get_logic", "register_logic", "registered_logic"]

"""Email security suite: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, MX and CAA.

The suite is mechanical and evidence-based:

* SPF is parsed token by token; expansion is bounded by depth, lookup count,
  cycle detection and a timeout so a hostile ``include:`` chain cannot cause
  unbounded recursion.
* DMARC is parsed from ``_dmarc`` and (if absent) inherited from the
  organizational domain, which is recorded explicitly.
* DKIM is only commented on for selectors the operator asked us to test, and the
  report says so - absence of a record at ``google._domainkey`` is **not**
  evidence that the domain has no DKIM key.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Iterable, Sequence
from typing import Any

from dnscope.dns.engine import DNSEngine
from dnscope.models.common import Confidence, Evidence, SourceRecord
from dnscope.models.email import (
    CAARecordInfo,
    DKIMResult,
    DMARCRecord,
    EmailSecurityReport,
    MTASTSResult,
    SPFRecord,
    TLSRPTResult,
)
from dnscope.utils.domains import normalize_hostname, parent_domain, valid_hostname
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("analyzers.email")

#: Mechanisms that consume a DNS lookup (RFC 7208 section 4.6.4).
LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")

#: Well-known mail providers recognized from MX hostnames.
MAIL_PROVIDERS = {
    "google": ("google.com", "googlemail.com", "aspmx.l.google.com"),
    "microsoft": ("outlook.com", "protection.outlook.com", "mail.protection.outlook.com"),
    "microsoft365": ("protection.outlook.com",),
    "zoho": ("zoho.com", "zoho.eu"),
    "amazon-ses": ("amazonses.com", "email.amazonses.com"),
    "mimecast": ("mimecast.com",),
    "proofpoint": ("pphosted.com",),
    "fastmail": ("fastmail.com", "messagingengine.com"),
    "rackspace": ("emailsrvr.com",),
    "yandex": ("yandex.ru", "yandex.net"),
    "mailgun": ("mailgun.org",),
    "sendgrid": ("sendgrid.net",),
    "postmark": ("pm.mtasv.net", "smtp.postmarkapp.com"),
}


def _check_ip_mechanism(record: SPFRecord, name: str, value: str, token: str) -> None:
    """Validate an ``ip4:``/``ip6:`` mechanism and record any problem.

    RFC 7208 section 5.6 makes a malformed address a PermError; we surface it as
    an issue instead of silently accepting it, because a typo in an SPF record is
    exactly the kind of thing that silently breaks mail.
    """
    import ipaddress

    if not value:
        record.issues.append(f"{name} mechanism is missing a value ({token})")
        return
    expected = 4 if name == "ip4" else 6
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != expected:
                record.issues.append(f"{name}:{value} is not an IPv{expected} network")
                return
            if network.num_addresses > 2**16:
                record.issues.append(f"{token} authorizes {network.num_addresses} addresses (very broad)")
        else:
            address = ipaddress.ip_address(value)
            if address.version != expected:
                record.issues.append(f"{name}:{value} is not an IPv{expected} address")
                return
    except ValueError:
        record.issues.append(f"{name}:{value} is not a valid IPv{expected} address/network")
        return
    # Store the literal text: expansion compares against the same string, so the
    # same network can never appear twice in the authorized list.
    if value not in record.authorized_networks:
        record.authorized_networks.append(value)


class SPFParser:
    """Mechanical SPF record parser with bounded expansion."""

    def __init__(
        self,
        engine: DNSEngine | None = None,
        *,
        max_depth: int = 5,
        max_lookups: int = 10,
        timeout: float = 10.0,
        auto_expand: bool = True,
    ) -> None:
        self.engine = engine
        self.max_depth = max(1, max_depth)
        self.max_lookups = max(0, max_lookups)
        self.timeout = timeout
        self.auto_expand = auto_expand

    # ------------------------------------------------------------------ parsing

    def parse(self, domain: str, record_text: str) -> SPFRecord:
        """Parse SPF record text without any DNS access."""
        record = SPFRecord(domain=normalize_hostname(domain), record=record_text.strip())
        text = record.record
        if not text:
            return record

        tokens = text.split()
        if not tokens or tokens[0].lower() != "v=spf1":
            # Not an SPF record at all: ``found`` stays False so downstream code
            # never claims SPF is present (or misconfigured) from a random TXT.
            record.issues.append("record does not start with 'v=spf1'")
            return record
        record.found = True
        record.version = tokens[0]

        for token in tokens[1:]:
            if "=" in token and not token.startswith(("+", "-", "~", "?")):
                key, _, value = token.partition("=")
                record.modifiers.append({"name": key.lower(), "value": value})
                if key.lower() == "redirect":
                    record.redirect = normalize_hostname(value)
                elif key.lower() == "exp":
                    record.explanation = value
                continue
            qualifier = "+"
            if token[0] in "+-~?":
                qualifier, token = token[0], token[1:]
                if not token:
                    record.issues.append("empty mechanism after qualifier")
                    continue
            if ":" in token:
                name, _, value = token.partition(":")
            elif "/" in token:
                name, _, value = token.partition("/")
                value = token  # ip4:/ip6: carry CIDR in the value
            else:
                name, value = token, ""
            name = name.lower()
            if name in ("ip4", "ip6"):
                _check_ip_mechanism(record, name, value, token)
            elif name in ("include", "redirect") and value and not valid_hostname(value):
                record.issues.append(f"{name}:{value} is not a valid hostname")
            mechanism: dict[str, Any] = {
                "type": name,
                "qualifier": qualifier,
                "value": value,
                "raw": token,
                "counts_as_lookup": name in LOOKUP_MECHANISMS,
            }
            record.mechanisms.append(mechanism)
            if name == "all":
                record.all_mechanism = f"{qualifier}all"

        if not record.all_mechanism:
            record.issues.append("no 'all' mechanism; RFC 7208 defaults to 'neutral'")
        return record

    # ---------------------------------------------------------------- expansion

    def expand(self, domain: str, record: SPFRecord) -> SPFRecord:
        """Resolve ``include``/``redirect`` chains within strict limits."""
        if self.engine is None or not self.auto_expand:
            return record
        started = time.monotonic()
        visited: set[str] = set()
        self._expand_recursive(record, record.domain, visited, depth=0, started=started)
        record.include_chain = sorted(visited)
        return record

    def _expand_recursive(
        self,
        root: SPFRecord,
        domain: str,
        visited: set[str],
        *,
        depth: int,
        started: float,
    ) -> None:
        """Depth- and lookup-bounded SPF expansion."""
        normalized = normalize_hostname(domain)
        if not normalized or not valid_hostname(normalized):
            return
        if normalized in visited:
            root.cycle_detected = True
            root.issues.append(f"include cycle detected at {normalized}")
            return
        if depth >= self.max_depth:
            root.truncated = True
            root.issues.append(f"expansion stopped at depth {self.max_depth}")
            return
        if root.lookup_count >= self.max_lookups:
            root.truncated = True
            root.issues.append(f"DNS lookup limit ({self.max_lookups}) reached")
            return
        if time.monotonic() - started > self.timeout:
            root.truncated = True
            root.issues.append("expansion timed out")
            return
        visited.add(normalized)

        current = root if depth == 0 else self._fetch_spf(normalized, root)
        if current is None:
            return

        for mechanism in current.mechanisms:
            if root.lookup_count >= self.max_lookups:
                root.truncated = True
                break
            name = str(mechanism.get("type", "")).lower()
            raw_value = str(mechanism.get("value", ""))
            # ip4:/ip6: values are addresses and networks: normalize_hostname()
            # splits on '/' and ':' and would turn "74.125.0.0/16" into
            # "74.125.0.0" and "2001:4860::/56" into "2001", so keep them raw.
            value = raw_value if name in ("ip4", "ip6") else normalize_hostname(raw_value)
            if name in LOOKUP_MECHANISMS:
                root.lookup_count += 1
            if name == "include" and value:
                root.include_chain.append(value)
                self._expand_recursive(root, value, visited, depth=depth + 1, started=started)
            elif name in ("ip4", "ip6") and value:
                if value not in root.authorized_networks:
                    root.authorized_networks.append(value)
            elif name in ("a", "mx") and depth < self.max_depth:
                # A bare "a" or "mx" means "this domain".
                target = value or normalize_hostname(current.domain)
                if target:
                    self._collect_addresses(root, target, name)

        if current.redirect and current.redirect not in visited:
            root.lookup_count += 1
            self._expand_recursive(root, current.redirect, visited, depth=depth + 1, started=started)

        root.lookup_depth = max(root.lookup_depth, depth + 1)

    def _fetch_spf(self, domain: str, root: SPFRecord) -> SPFRecord | None:
        """Fetch and parse the SPF record of an included domain."""
        if self.engine is None:
            return None
        result = self.engine.query(domain, "TXT")
        if not result.ok:
            root.issues.append(f"{domain}: SPF include could not be resolved ({result.status})")
            return None
        for record in result.records:
            text = str((record.parsed or {}).get("text", ""))
            if text.lower().startswith("v=spf1"):
                return self.parse(domain, text)
        root.issues.append(f"{domain}: no SPF record found")
        return None

    def _collect_addresses(self, root: SPFRecord, domain: str, mechanism: str) -> None:
        """Collect A/AAAA values for ``a`` and ``mx`` mechanisms.

        Both record families are queried because RFC 7208 matches ``a``/``mx``
        against IPv4 *and* IPv6.
        """
        if self.engine is None:
            return
        if mechanism == "a":
            for hostname in (domain,):
                self._extend_addresses(root, hostname)
            return
        mx_result = self.engine.query(domain, "MX")
        if not mx_result.ok:
            return
        for record in mx_result.records:
            exchange = str((record.parsed or {}).get("exchange", ""))
            if exchange:
                self._extend_addresses(root, exchange)

    def _extend_addresses(self, root: SPFRecord, hostname: str) -> None:
        """Add the A and AAAA values of ``hostname`` to the authorized list."""
        for rtype in ("A", "AAAA"):
            result = self.engine.query(hostname, rtype)
            if not result.ok:
                continue
            for value in result.values:
                if value not in root.authorized_networks:
                    root.authorized_networks.append(value)

    def analyze(self, domain: str) -> SPFRecord:
        """Query, parse and expand the SPF record for ``domain``."""
        normalized = normalize_hostname(domain)
        record = SPFRecord(domain=normalized)
        if self.engine is None:
            record.issues.append("no DNS engine available")
            return record
        result = self.engine.query(normalized, "TXT")
        record.evidence = _evidence(f"TXT {normalized}", result)
        if not result.ok:
            record.issues.append(f"TXT query returned {result.status}")
            return record
        for dns_record in result.records:
            text = str((dns_record.parsed or {}).get("text", ""))
            if text.lower().startswith("v=spf1"):
                record = self.parse(normalized, text)
                record.evidence = _evidence(f"TXT {normalized}", result)
                record.max_depth = self.max_depth
                record.max_lookups = self.max_lookups
                return self.expand(normalized, record)
        record.issues.append("no SPF record in the TXT response")
        return record


class DMARCParser:
    """DMARC record parser with organizational-domain inheritance."""

    def parse(self, domain: str, record_text: str, *, inherited_from: str = "") -> DMARCRecord:
        """Parse a ``v=DMARC1`` record."""
        record = DMARCRecord(
            domain=normalize_hostname(domain),
            record=record_text.strip(),
            inherited_from=inherited_from,
        )
        text = record.record
        if not text:
            return record
        record.found = True
        tags = _parse_tags(text, separator=";")
        record.version = tags.get("v", "")
        if record.version.upper() != "DMARC1":
            record.issues.append("record does not declare v=DMARC1")
        record.policy = tags.get("p", "").lower()
        record.subdomain_policy = tags.get("sp", "").lower()
        record.adkim = tags.get("adkim", "").lower()
        record.aspf = tags.get("aspf", "").lower()
        record.fo = tags.get("fo", "").lower()
        record.rua = [item.strip() for item in tags.get("rua", "").split(",") if item.strip()]
        record.ruf = [item.strip() for item in tags.get("ruf", "").split(",") if item.strip()]
        if tags.get("pct"):
            try:
                record.percentage = max(0, min(100, int(tags["pct"])))
            except ValueError:
                record.issues.append(f"invalid pct value: {tags['pct']}")
        if tags.get("ri"):
            try:
                record.ri = max(0, int(tags["ri"]))
            except ValueError:
                record.issues.append(f"invalid ri value: {tags['ri']}")

        if record.policy not in ("none", "quarantine", "reject"):
            record.issues.append(f"invalid or missing policy: {record.policy or 'none'}")
        if record.subdomain_policy and record.subdomain_policy not in ("none", "quarantine", "reject"):
            record.issues.append(f"invalid subdomain policy: {record.subdomain_policy}")
        if record.policy == "none" and not record.rua:
            record.issues.append("p=none without a rua reporting address provides no visibility")
        if record.policy in ("quarantine", "reject") and record.percentage not in (None, 100):
            record.issues.append(f"policy is only applied to {record.percentage}% of mail")
        return record

    def analyze(self, domain: str, engine: DNSEngine | None) -> DMARCRecord:
        """Query ``_dmarc.<domain>``, falling back to the organizational domain."""
        normalized = normalize_hostname(domain)
        record = DMARCRecord(domain=normalized)
        if engine is None:
            record.issues.append("no DNS engine available")
            return record

        result = engine.query(f"_dmarc.{normalized}", "TXT")
        record.evidence = _evidence(f"TXT _dmarc.{normalized}", result)
        text = _first_prefixed(result, "v=dmarc1")
        if text:
            parsed = self.parse(normalized, text)
            # parse() builds a fresh model, so the query evidence collected above
            # has to be carried across or findings about DMARC would have nothing
            # to point at.
            parsed.evidence = record.evidence
            return parsed

        # Inherit from the organizational domain (RFC 7489 section 3).
        parent = parent_domain(normalized)
        attempts = 0
        while parent and "." in parent and attempts < 3:
            attempts += 1
            inherited = engine.query(f"_dmarc.{parent}", "TXT")
            inherited_text = _first_prefixed(inherited, "v=dmarc1")
            if inherited_text:
                parsed = self.parse(normalized, inherited_text, inherited_from=parent)
                parsed.evidence = _evidence(f"TXT _dmarc.{parent}", inherited)
                return parsed
            parent = parent_domain(parent)
        record.issues.append("no DMARC record at _dmarc or at the organizational domain")
        return record


class DKIMAnalyzer:
    """Explicit-selector DKIM testing."""

    def __init__(self, engine: DNSEngine | None, selectors: Sequence[str] | None = None) -> None:
        self.engine = engine
        self.selectors = [str(item).strip().lower() for item in (selectors or []) if str(item).strip()]

    def analyze(self, domain: str) -> list[DKIMResult]:
        """Test each configured selector; returns one result per selector."""
        normalized = normalize_hostname(domain)
        results: list[DKIMResult] = []
        for selector in self.selectors:
            query_name = f"{selector}._domainkey.{normalized}"
            result = DKIMResult(domain=normalized, selector=selector, query_name=query_name)
            if self.engine is None:
                result.issues.append("no DNS engine available")
                results.append(result)
                continue
            dns_result = self.engine.query(query_name, "TXT")
            result.evidence = _evidence(f"TXT {query_name}", dns_result)
            if not dns_result.ok:
                if dns_result.nxdomain:
                    result.issues.append("no TXT record at this selector")
                else:
                    result.issues.append(f"query returned {dns_result.status}")
                results.append(result)
                continue
            text = _first_prefixed(dns_result, "v=dkim1")
            if not text:
                result.issues.append("TXT record exists but is not a DKIM key")
                results.append(result)
                continue
            self._parse(result, text)
            results.append(result)
        return results

    def _parse(self, result: DKIMResult, text: str) -> None:
        """Parse the DKIM TXT record into typed fields."""
        result.found = True
        result.record = text
        tags = _parse_tags(text, separator=";")
        result.version = tags.get("v", "")
        result.key_type = tags.get("k", "rsa")
        result.hash_algorithm = tags.get("h", "")
        result.service = tags.get("s", "")
        result.flags = tags.get("t", "")
        public_key = tags.get("p", "")
        if not public_key:
            result.issues.append("DKIM record has an empty 'p=' tag (key revoked or placeholder)")
            result.revoked = True
        else:
            result.key_size_bits = _rsa_key_bits(public_key)
            if result.key_size_bits and result.key_size_bits < 1024:
                result.issues.append(f"DKIM key is only {result.key_size_bits} bits")
        if "y" in result.flags:
            result.issues.append("DKIM record is in test mode (t=y)")


class EmailSecurityAnalyzer:
    """Runs the full mail-security suite for a domain."""

    def __init__(
        self,
        engine: DNSEngine | None,
        *,
        dkim_selectors: Sequence[str] | None = None,
        max_spf_depth: int = 5,
        max_spf_lookups: int = 10,
    ) -> None:
        self.engine = engine
        self.spf = SPFParser(engine, max_depth=max_spf_depth, max_lookups=max_spf_lookups)
        self.dmarc = DMARCParser()
        self.dkim = DKIMAnalyzer(engine, dkim_selectors)

    def analyze(self, domain: str, *, include_transport: bool = True) -> EmailSecurityReport:
        """Collect SPF, DMARC, DKIM, MX, CAA, MTA-STS and TLS-RPT observations."""
        normalized = normalize_hostname(domain)
        report = EmailSecurityReport(domain=normalized)
        report.spf = self.spf.analyze(normalized)
        report.dmarc = self.dmarc.analyze(normalized, self.engine)
        report.dkim = self.dkim.analyze(normalized)
        report.dkim_selectors_tested = list(self.dkim.selectors)
        report.dkim_conclusive = bool(self.dkim.selectors)
        report.caa = self._caa(normalized)
        report.mx_hosts, report.mx_providers = self._mx(normalized)
        if include_transport:
            report.mta_sts = self._mta_sts(normalized)
            report.tls_rpt = self._tls_rpt(normalized)
        report.issues = self._collect_issues(report)
        report.score = self._score(report)
        return report

    # ------------------------------------------------------------------ helpers

    def _caa(self, domain: str) -> CAARecordInfo | None:
        """Parse the CAA record set for ``domain``."""
        if self.engine is None:
            return None
        result = self.engine.query(domain, "CAA")
        info = CAARecordInfo(domain=domain, evidence=_evidence(f"CAA {domain}", result))
        if not result.ok:
            return info
        for record in result.records:
            parsed = record.parsed or {}
            tag = str(parsed.get("tag", "")).lower()
            value = str(parsed.get("value", ""))
            info.records.append(record.rdata_text)
            if tag == "issue":
                info.issue.append(value)
            elif tag == "issuewild":
                info.issuewild.append(value)
            elif tag == "iodef":
                info.iodef.append(value)
            if parsed.get("critical"):
                info.critical_flags.append(record.rdata_text)
        info.found = bool(info.records)
        return info

    def _mx(self, domain: str) -> tuple[list[str], list[str]]:
        """Return MX hosts and the providers they imply."""
        if self.engine is None:
            return [], []
        result = self.engine.query(domain, "MX")
        if not result.ok:
            return [], []
        hosts: list[str] = []
        for record in result.records:
            exchange = str((record.parsed or {}).get("exchange", ""))
            if exchange:
                hosts.append(exchange)
        null_mx = any(host in (".", "") for host in hosts)
        if null_mx:
            return ["(null MX)"], ["none"]
        providers = sorted({detect_mail_provider(host) for host in hosts if detect_mail_provider(host)})
        return sorted(hosts), providers

    def _mta_sts(self, domain: str) -> MTASTSResult | None:
        """Discover MTA-STS via DNS only (no HTTPS fetch by default)."""
        if self.engine is None:
            return None
        result = MTASTSResult(domain=domain, policy_host=f"mta-sts.{domain}")
        txt = self.engine.query(f"_mta-sts.{domain}", "TXT")
        result.evidence = _evidence(f"TXT _mta-sts.{domain}", txt)
        text = _first_prefixed(txt, "v=stsv1")
        if not text:
            result.issues.append("no MTA-STS TXT record")
            return result
        result.found = True
        result.record = text
        tags = _parse_tags(text, separator=";")
        result.version = tags.get("v", "")
        result.policy_id = tags.get("id", "")
        policy_host_result = self.engine.query(result.policy_host, "A")
        result.policy_host_resolves = bool(policy_host_result.ok and policy_host_result.answer_count)
        if not result.policy_host_resolves:
            result.issues.append(f"policy host {result.policy_host} does not resolve")
        return result

    def _tls_rpt(self, domain: str) -> TLSRPTResult | None:
        """Discover TLS-RPT (``_smtp._tls``) via DNS."""
        if self.engine is None:
            return None
        result = TLSRPTResult(domain=domain)
        txt = self.engine.query(f"_smtp._tls.{domain}", "TXT")
        result.evidence = _evidence(f"TXT _smtp._tls.{domain}", txt)
        text = _first_prefixed(txt, "v=tlsrpt")
        if not text:
            result.issues.append("no TLS-RPT record")
            return result
        result.found = True
        result.record = text
        tags = _parse_tags(text, separator=";")
        result.version = tags.get("v", "")
        result.rua = [item.strip() for item in tags.get("rua", "").split(",") if item.strip()]
        if not result.rua:
            result.issues.append("TLS-RPT record has no rua reporting address")
        return result

    def _collect_issues(self, report: EmailSecurityReport) -> list[str]:
        """Aggregate issue strings from every sub-analyzer."""
        issues: list[str] = []
        if report.spf:
            issues.extend(f"SPF: {item}" for item in report.spf.issues)
        if report.dmarc:
            issues.extend(f"DMARC: {item}" for item in report.dmarc.issues)
        for result in report.dkim:
            issues.extend(f"DKIM[{result.selector}]: {item}" for item in result.issues)
        if report.caa and not report.caa.found:
            issues.append("CAA: no CAA record restricts which CAs may issue certificates")
        elif report.caa and report.caa.found and not report.caa.restricts_issuance:
            issues.append("CAA: records exist but none carry issue/issuewild, so issuance is not restricted")
        for result in report.dkim:
            if result.found and result.key_size_bits and result.key_size_bits < 2048:
                issues.append(
                    f"DKIM[{result.selector}]: {result.key_size_bits}-bit key; 2048 bits is recommended"
                )
        if report.mta_sts and report.mta_sts.issues:
            issues.extend(f"MTA-STS: {item}" for item in report.mta_sts.issues)
        if report.tls_rpt and report.tls_rpt.issues:
            issues.extend(f"TLS-RPT: {item}" for item in report.tls_rpt.issues)
        return issues

    def _score(self, report: EmailSecurityReport) -> float:
        """Simple 0-100 mail-security posture score (explainable in the report)."""
        weights = {
            "spf": 20.0,
            "spf_strict": 10.0,
            "dmarc": 25.0,
            "dmarc_enforcing": 15.0,
            "dkim": 15.0,
            "caa": 5.0,
            "mta_sts": 5.0,
            "tls_rpt": 5.0,
        }
        earned = 0.0
        if report.spf and report.spf.found:
            earned += weights["spf"]
            if report.spf.all_mechanism in ("-all", "~all"):
                earned += weights["spf_strict"]
        if report.dmarc and report.dmarc.found:
            earned += weights["dmarc"]
            if report.dmarc.enforces:
                earned += weights["dmarc_enforcing"]
        earned += _dkim_credit(report.dkim, weights["dkim"])
        # CAA only earns credit when it actually restricts issuance: a record
        # with just contactemail/iodef does not stop a rogue CA.
        if report.caa and report.caa.restricts_issuance:
            earned += weights["caa"]
        if report.mta_sts and report.mta_sts.found:
            earned += weights["mta_sts"]
        if report.tls_rpt and report.tls_rpt.found:
            earned += weights["tls_rpt"]
        return round(earned, 1)


def _dkim_credit(results: list[DKIMResult], weight: float) -> float:
    """Award DKIM credit scaled by the strongest key actually published.

    A 1024-bit key earns half credit and anything weaker earns none, so the
    score cannot reward a key that should be rotated.
    """
    sizes = [
        result.key_size_bits
        for result in results
        if result.found and not result.revoked and result.key_size_bits
    ]
    if not sizes:
        # A key exists but its size could not be determined: partial credit only.
        return weight / 2 if any(result.found and not result.revoked for result in results) else 0.0
    strongest = max(sizes)
    if strongest >= 2048:
        return weight
    if strongest >= 1024:
        return weight / 2
    return 0.0


# ------------------------------------------------------------------- utilities


def detect_mail_provider(host: str) -> str:
    """Map an MX hostname to a provider name (empty when unknown)."""
    normalized = normalize_hostname(host)
    for provider, needles in MAIL_PROVIDERS.items():
        for needle in needles:
            if normalized == needle or normalized.endswith(f".{needle}"):
                return provider
    return ""


def _parse_tags(text: str, *, separator: str = ";") -> dict[str, str]:
    """Parse ``k=v;k2=v2`` tag strings."""
    tags: dict[str, str] = {}
    for chunk in text.split(separator):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        key, _, value = item.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def _first_prefixed(result: Any, prefix: str) -> str:
    """Return the first TXT string starting with ``prefix``."""
    if result is None or not result.ok:
        return ""
    for record in result.records:
        text = str((record.parsed or {}).get("text", ""))
        if text.lower().startswith(prefix):
            return text
    return ""


def _evidence(query: str, result: Any) -> Evidence:
    """Build an :class:`Evidence` entry from a DNS query result."""
    if result is None:
        return Evidence(query=query, response="no result", source=SourceRecord(provider="dns"))
    if result.ok:
        response = f"{result.status}/{result.answer_count}"
        # data_records only: with DO set the answer also carries RRSIG records,
        # and signature text is not the data a reader wants to see.
        if result.data_records:
            response += ": " + "; ".join(item.rdata_text for item in result.data_records[:3])
    else:
        response = f"{result.status}" + (f" ({result.error})" if result.error else "")
    return Evidence(
        query=query,
        response=response[:500],
        record_type=result.rtype,
        source=SourceRecord(provider="dns", source=result.meta.resolver, confidence=Confidence.HIGH),
    )


def _rsa_key_bits(public_key_b64: str) -> int | None:
    """Return the exact key size of a DKIM ``p=`` value, or ``None``.

    The value is a base64-encoded SubjectPublicKeyInfo. It is parsed with
    ``cryptography`` so the reported size is the real modulus length rather than
    a byte-count estimate - key size is what a DKIM finding is about, so an
    approximation would produce wrong advice.
    """
    text = "".join(public_key_b64.split())
    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=False)
    except Exception:
        return None
    if len(raw) < 3:
        return None

    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        key = load_der_public_key(raw)
        numbers = key.public_numbers()  # type: ignore[attr-defined]
        return int(numbers.n).bit_length()
    except Exception:
        return _der_bit_size_fallback(raw)


def _der_bit_size_fallback(raw: bytes) -> int | None:
    """Fallback size estimate for keys ``cryptography`` cannot parse.

    Walks the DER structure to find the BIT STRING holding the key, so the
    estimate is still bounded by the actual encoded key rather than the blob.
    """
    index = 0
    try:
        while index < len(raw):
            tag = raw[index]
            index += 1
            length = raw[index]
            index += 1
            if length & 0x80:
                count = length & 0x7F
                length = int.from_bytes(raw[index : index + count], "big")
                index += count
            if tag == 0x03:  # BIT STRING carrying the SubjectPublicKey
                payload = raw[index : index + length]
                if payload:
                    payload = payload[1:]  # drop the unused-bits octet
                return max(0, (len(payload) - 24) * 8)
            index += length
    except (IndexError, ValueError):
        return None
    return None


def analyze_email(
    engine: DNSEngine | None,
    domain: str,
    *,
    dkim_selectors: Iterable[str] | None = None,
) -> EmailSecurityReport:
    """Convenience wrapper used by the CLI and the orchestrator."""
    analyzer = EmailSecurityAnalyzer(engine, dkim_selectors=list(dkim_selectors or []))
    report = analyzer.analyze(domain)
    _log.debug("email analysis for %s completed at %s", domain, utc_now_iso())
    return report


__all__ = [
    "DKIMAnalyzer",
    "DMARCParser",
    "EmailSecurityAnalyzer",
    "EmailSecurityReport",
    "SPFParser",
    "analyze_email",
    "detect_mail_provider",
]

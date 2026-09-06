"""DNS Engine 2.0.

Responsibilities
----------------
* Send queries over the configured transport with retries and backoff
* Normalize every response into :class:`DNSQueryResult` (rcode, flags, EDNS,
  timing, TTLs, parsed rdata)
* Follow CNAME chains with a hard depth limit
* Compare answers across resolvers to detect inconsistent views
* Detect wildcard responses so discovery results are not polluted
* Profile authoritative nameservers and walk the delegation chain

The engine is synchronous by default and exposes bounded-concurrency async
helpers built on :class:`dnscope.utils.async_utils.BoundedGatherer`.
"""

from __future__ import annotations

import random
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from dnscope.core.config import ResolverConfig
from dnscope.dns.records import record_type_name, to_dns_record
from dnscope.dns.transport import DNSTransportLayer, TransportResult
from dnscope.exceptions import DNSError, DNSResolutionError, DNSTimeout
from dnscope.models.common import Confidence
from dnscope.models.dns import (
    DelegationInfo,
    DelegationLevel,
    DNSAnswer,
    DNSQueryResult,
    DNSRecord,
    DNSResponseMeta,
    DNSTransport,
    Fingerprint,
    NameserverProfile,
    ResolverInfo,
)
from dnscope.utils.async_utils import BoundedGatherer, GatherError, run_async
from dnscope.utils.domains import normalize_hostname, registered_domain, reverse_pointer
from dnscope.utils.logging import get_logger
from dnscope.utils.time_utils import utc_now_iso

_log = get_logger("dns.engine")

#: Cookie EDNS option code (RFC 7873).
EDNS_COOKIE = 10


@dataclass
class WildcardInfo:
    """Result of wildcard detection for a zone."""

    domain: str
    wildcard: bool = False
    probe_names: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    confidence: str = Confidence.LOW.value
    evidence: str = ""


class DNSEngine:
    """High-level DNS query engine."""

    def __init__(
        self,
        config: ResolverConfig | None = None,
        *,
        cache: Any = None,
        max_cname_depth: int = 8,
        max_records: int = 500,
        rate_limit: float = 0.0,
        concurrency: int = 20,
        offline: bool = False,
    ) -> None:
        self.config = config or ResolverConfig()
        self.cache = cache
        self.max_cname_depth = max(1, max_cname_depth)
        self.max_records = max(1, max_records)
        self.concurrency = max(1, concurrency)
        self.rate_limit = rate_limit
        self.offline = offline
        self._resolver_cache: dict[str, dns.resolver.Resolver] = {}
        self._wildcard_cache: dict[str, WildcardInfo] = {}
        #: Counters surfaced by ``dnscope benchmark`` and ``/metrics``.
        self.queries_sent = 0
        self.queries_cached = 0
        self.queries_failed = 0
        self.total_latency_ms = 0.0
        self.resolver_stats: dict[str, ResolverInfo] = {}
        self.errors: list[str] = []

    # ------------------------------------------------------------- resolvers

    @property
    def nameservers(self) -> list[str]:
        """Configured nameservers (empty means "use the system resolver")."""
        return self.config.effective_nameservers()

    def transport_layer(self, resolver: str | None = None) -> DNSTransportLayer:
        """Build the transport layer for the configured transport."""
        return DNSTransportLayer(
            transport=self.config.transport,
            timeout=self.config.timeout,
            port=self.config.port,
            doh_url=self.config.doh_url,
            dot_host=self.config.dot_host,
            edns_payload=self.config.edns_payload,
        )

    def system_nameservers(self) -> list[str]:
        """Nameservers discovered from the operating system configuration."""
        try:
            resolver = dns.resolver.Resolver(configure=True)
            return [str(item) for item in resolver.nameservers]
        except Exception:
            return []

    def active_resolvers(self) -> list[str]:
        """Resolvers DNScope will actually query."""
        configured = self.nameservers
        if configured:
            return configured
        return self.system_nameservers()

    def comparison_resolvers(self) -> list[str]:
        """Resolvers used for cross-resolver consistency checks."""
        base = self.config.comparison_resolvers or ["8.8.8.8", "1.1.1.1"]
        seen: list[str] = []
        for item in base:
            address = self.config.resolve_preset(item)
            if address not in seen:
                seen.append(address)
        return seen

    # ----------------------------------------------------------------- queries

    def query(
        self,
        name: str,
        rtype: str = "A",
        *,
        resolver: str | None = None,
        want_dnssec: bool | None = None,
        use_cache: bool = True,
        follow_cnames: bool = True,
    ) -> DNSQueryResult:
        """Query ``name`` for ``rtype`` and return a normalized result.

        Never raises for DNS-level failures: NXDOMAIN, SERVFAIL and timeouts are
        returned as structured results with ``ok=False`` so a scan can continue
        and the report can show what could not be verified.
        """
        qname = normalize_hostname(name)
        if name in (".", "root", "ROOT", "") and rtype.upper() in ("NS", "DS", "DNSKEY"):
            # The DNS root zone is addressable as "." but normalizes to "".
            qname = "."
        rdtype = str(rtype).upper()
        if not qname:
            return self._error_result(qname, rdtype, "empty query name")

        cache_key = self._cache_key(qname, rdtype, resolver, want_dnssec)
        if use_cache and self.cache is not None:
            cached = self._cache_get(cache_key)
            if cached is not None:
                result = DNSQueryResult.model_validate(cached)
                result.meta.cached = True
                self.queries_cached += 1
                return result

        started = time.monotonic()
        result = self._query_with_retry(qname, rdtype, resolver=resolver, want_dnssec=want_dnssec)
        if follow_cnames and result.ok and rdtype not in ("CNAME", "ANY"):
            result = self._follow_cnames(result, qname, rdtype, resolver=resolver)
        result.meta.duration_ms += (time.monotonic() - started) * 1000.0

        if result.ok:
            self.queries_sent += 1
            self.total_latency_ms += result.meta.duration_ms
            self._record_resolver(result.meta.resolver, result.meta.duration_ms)
            if use_cache and self.cache is not None:
                self._cache_put(cache_key, result)
        else:
            self.queries_failed += 1
        return result

    def _query_with_retry(
        self,
        qname: str,
        rdtype: str,
        *,
        resolver: str | None,
        want_dnssec: bool | None,
    ) -> DNSQueryResult:
        """Send a query with retry/backoff across the configured resolvers."""
        targets = [resolver] if resolver else (self.nameservers or [None])
        attempts_allowed = max(1, self.config.retries + 1)
        last_error = ""
        for attempt in range(attempts_allowed):
            for target in targets:
                try:
                    return self._send(qname, rdtype, target, want_dnssec)
                except DNSTimeout as exc:
                    last_error = str(exc)
                except DNSError as exc:
                    last_error = str(exc)
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts_allowed - 1:
                time.sleep(min(2.0, 0.25 * (2**attempt)) * (0.5 + random.random()))
        return self._error_result(qname, rdtype, last_error or "query failed")

    def _send(
        self,
        qname: str,
        rdtype: str,
        resolver: str | None,
        want_dnssec: bool | None,
    ) -> DNSQueryResult:
        """Perform a single query and normalize the response."""
        dnssec = self.config.dnssec if want_dnssec is None else want_dnssec
        ednsflags = dns.flags.DO if (dnssec or self.config.dnssec) else 0
        message = dns.message.make_query(
            qname,
            rdtype,
            use_edns=0 if self.config.edns else False,
            want_dnssec=bool(dnssec),
            ednsflags=ednsflags,
            payload=self.config.edns_payload if self.config.edns else 512,
        )

        layer = self.transport_layer()
        if resolver:
            result: TransportResult = layer.send(message, resolver)
        elif self.config.transport in ("doh", "dot"):
            result = layer.send(message, "")
        else:
            result = self._send_via_system(message)

        return self._normalize(qname, rdtype, result, dnssec=dnssec)

    def _send_via_system(self, message: Any) -> TransportResult:
        """Send through the OS resolver configuration (UDP with TCP fallback)."""
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.lifetime
        started = time.monotonic()
        qname = message.question[0].name
        rdtype_text = dns.rdatatype.to_text(message.question[0].rdtype)
        nameservers = ",".join(str(item) for item in resolver.nameservers) or "system"
        try:
            response = resolver.query(qname, rdtype_text)
            payload = response.response
        except dns.exception.Timeout as exc:
            raise DNSTimeout("system resolver timed out") from exc
        except dns.resolver.NoNameservers as exc:
            raise DNSError(f"no system nameservers available: {exc}") from exc
        except dns.resolver.NXDOMAIN as exc:
            # query() promises never to raise for DNS-level failures, so an
            # NXDOMAIN becomes a structured result rather than an exception.
            payload = _response_from_exception(exc, qname, rdtype_text, dns.rcode.NXDOMAIN)
        except dns.resolver.NoAnswer as exc:
            payload = _response_from_exception(exc, qname, rdtype_text, dns.rcode.NOERROR)
        except Exception as exc:
            raise DNSError(f"system resolver failed: {exc}") from exc
        return TransportResult(
            response=payload,
            duration_ms=(time.monotonic() - started) * 1000.0,
            transport=DNSTransport.SYSTEM,
            resolver=nameservers,
            truncated=bool(payload.flags & dns.flags.TC),
        )

    def _normalize(
        self,
        qname: str,
        rdtype: str,
        result: TransportResult,
        *,
        dnssec: bool = False,
    ) -> DNSQueryResult:
        """Convert a raw DNS message into a :class:`DNSQueryResult`."""
        message = result.response
        observed = utc_now_iso()
        rcode = message.rcode()
        rcode_name = dns.rcode.to_text(rcode).upper()

        records: list[DNSRecord] = []
        cname_chain: list[str] = []
        for rrset in message.answer:
            type_name = record_type_name(rrset.rdtype)
            if len(records) >= self.max_records:
                break
            for rdata in rrset:
                if len(records) >= self.max_records:
                    break
                records.append(
                    to_dns_record(
                        str(rrset.name),
                        type_name,
                        rdata,
                        ttl=int(rrset.ttl),
                        resolver=result.resolver,
                        observed_at=observed,
                    )
                )
                if type_name == "CNAME":
                    target = str(rdata.target).rstrip(".").lower()
                    if target not in cname_chain:
                        cname_chain.append(target)

        authority: list[DNSRecord] = []
        for rrset in message.authority[:20]:
            type_name = record_type_name(rrset.rdtype)
            for rdata in list(rrset)[:10]:
                authority.append(
                    to_dns_record(
                        str(rrset.name),
                        type_name,
                        rdata,
                        ttl=int(rrset.ttl),
                        resolver=result.resolver,
                        observed_at=observed,
                    )
                )

        additional: list[DNSRecord] = []
        for rrset in message.additional[:20]:
            type_name = record_type_name(rrset.rdtype)
            if type_name == "OPT":
                continue
            for rdata in list(rrset)[:10]:
                additional.append(
                    to_dns_record(
                        str(rrset.name),
                        type_name,
                        rdata,
                        ttl=int(rrset.ttl),
                        resolver=result.resolver,
                        observed_at=observed,
                    )
                )

        edns_version = message.edns if message.edns is not None and message.edns >= 0 else None
        options = list(getattr(message, "options", ()) or ())
        meta = DNSResponseMeta(
            resolver=result.resolver,
            transport=result.transport,
            rcode=rcode,
            rcode_name=rcode_name,
            authoritative=bool(message.flags & dns.flags.AA),
            recursion_desired=bool(message.flags & dns.flags.RD),
            recursion_available=bool(message.flags & dns.flags.RA),
            truncated=bool(message.flags & dns.flags.TC),
            authentic_data=bool(message.flags & dns.flags.AD),
            checking_disabled=bool(message.flags & dns.flags.CD),
            edns_version=edns_version,
            edns_payload=int(message.payload) if edns_version is not None else None,
            dnssec_ok=bool(getattr(message, "ednsflags", 0) & dns.flags.DO),
            edns_cookies=any(getattr(option, "otype", None) == EDNS_COOKIE for option in options),
            edns_options=[f"OPT{getattr(option, 'otype', '?')}" for option in options],
            message_size=len(message.to_wire()),
            question_count=len(message.question),
            answer_count=len(message.answer),
            authority_count=len(message.authority),
            additional_count=len(message.additional),
            duration_ms=result.duration_ms,
            attempts=1,
            tcp_fallback=result.tcp_fallback,
            error=result.error,
        )

        nxdomain = rcode == 3
        if nxdomain:
            # An NXDOMAIN response can still carry the CNAME that led to the dead
            # end (a dangling record). That is evidence, not an answer: keep it in
            # ``cname_chain`` for takeover analysis but drop it from ``records``
            # so ``answer_count`` and ``nxdomain`` never contradict each other.
            records = [record for record in records if record.rtype != "CNAME"]

        answered_types = {record.rtype for record in records}
        no_data = rcode == 0 and rdtype not in answered_types and not cname_chain

        return DNSQueryResult(
            name=qname,
            rtype=rdtype,
            status=rcode_name,
            ok=rcode == 0,
            records=records,
            meta=meta,
            authority=authority,
            additional=additional,
            error="" if rcode == 0 else f"{rcode_name} for {rdtype} {qname}",
            queried_at=observed,
            no_data=no_data,
            nxdomain=nxdomain,
            cname_chain=cname_chain,
        )

    def _follow_cnames(
        self,
        result: DNSQueryResult,
        qname: str,
        rdtype: str,
        *,
        resolver: str | None,
    ) -> DNSQueryResult:
        """Continue the CNAME chain until the requested type is answered."""
        current = result
        depth = 0
        while current.ok and current.no_data and current.cname_chain and depth < self.max_cname_depth:
            next_name = current.cname_chain[-1]
            depth += 1
            follow = self._query_with_retry(next_name, rdtype, resolver=resolver, want_dnssec=None)
            if not follow.ok:
                break
            merged = list(current.records)
            for record in follow.records:
                if record.rtype != "CNAME" or record.name != next_name:
                    merged.append(record)
            chain = list(dict.fromkeys([*current.cname_chain, *follow.cname_chain]))
            answered = {record.rtype for record in merged}
            current = DNSQueryResult(
                name=qname,
                rtype=rdtype,
                status=follow.status,
                ok=follow.ok,
                records=merged[: self.max_records],
                meta=current.meta.model_copy(
                    update={
                        "duration_ms": current.meta.duration_ms + follow.meta.duration_ms,
                        "answer_count": len(merged),
                    }
                ),
                authority=follow.authority or current.authority,
                additional=follow.additional or current.additional,
                queried_at=current.queried_at,
                no_data=rdtype not in answered,
                nxdomain=False,
                cname_chain=chain,
            )
        return current

    def _error_result(self, qname: str, rdtype: str, error: str) -> DNSQueryResult:
        """Build a failure result (timeout/SERVFAIL/transport error)."""
        status = "TIMEOUT" if "timed out" in error.lower() else "ERROR"
        if error:
            self.errors.append(f"{rdtype} {qname}: {error}")
        return DNSQueryResult(
            name=qname,
            rtype=rdtype,
            status=status,
            ok=False,
            error=error,
            queried_at=utc_now_iso(),
            meta=DNSResponseMeta(resolver=",".join(self.active_resolvers()), error=error),
        )

    # ------------------------------------------------------------ higher level

    def resolve_all(
        self,
        name: str,
        types: Sequence[str] | None = None,
        *,
        resolver: str | None = None,
        want_dnssec: bool | None = None,
        use_cache: bool = True,
    ) -> DNSAnswer:
        """Query every requested record type for one name."""
        requested = list(types or ["A", "AAAA"])
        queries = [
            self.query(
                name,
                rdtype,
                resolver=resolver,
                want_dnssec=want_dnssec,
                use_cache=use_cache,
            )
            for rdtype in requested
        ]
        return DNSAnswer(
            name=normalize_hostname(name),
            queries=queries,
            resolver=resolver or ",".join(self.active_resolvers()),
            observed_at=utc_now_iso(),
        )

    def query_many(
        self,
        names: Iterable[str],
        types: Sequence[str] | None = None,
        *,
        concurrency: int | None = None,
        rate_limit: float | None = None,
        use_cache: bool = True,
    ) -> dict[str, DNSAnswer]:
        """Resolve many names concurrently with bounded fan-out.

        Returns a mapping keyed by the normalized hostname. Failures are
        captured per-name so one bad target cannot abort the batch.
        """
        requested = list(types or ["A"])
        unique = list(dict.fromkeys(normalize_hostname(n) for n in names if n))
        answers: dict[str, DNSAnswer] = {}

        gatherer = BoundedGatherer(
            concurrency=concurrency or self.concurrency,
            rate=rate_limit if rate_limit is not None else self.rate_limit,
            name="dns",
        )

        def _work(name: str) -> tuple[str, DNSAnswer]:
            return name, self.resolve_all(name, requested, use_cache=use_cache)

        results = run_async(gatherer.map(_work, unique))
        for item in results:
            if isinstance(item, GatherError):
                _log.warning("dns batch failure: %s", item.message)
                continue
            name, answer = item
            answers[name] = answer
        return answers

    def compare_resolvers(
        self,
        name: str,
        rtype: str = "A",
        *,
        resolvers: Sequence[str] | None = None,
    ) -> dict[str, DNSQueryResult]:
        """Query the same name from several resolvers (consistency analysis)."""
        targets = list(resolvers or self.comparison_resolvers())
        results: dict[str, DNSQueryResult] = {}
        for target in targets:
            results[target] = self.query(name, rtype, resolver=target, use_cache=False)
        return results

    def resolver_consistency(
        self, name: str, rtype: str = "A", *, resolvers: Sequence[str] | None = None
    ) -> dict[str, Any]:
        """Summarize cross-resolver agreement for one name."""
        results = self.compare_resolvers(name, rtype, resolvers=resolvers)
        value_sets = {
            resolver: tuple(sorted(result.rdata_set())) for resolver, result in results.items() if result.ok
        }
        distinct = {value for values in value_sets.values() for value in values}
        return {
            "name": normalize_hostname(name),
            "rtype": rtype,
            "resolvers_queried": list(results),
            "resolvers_answered": list(value_sets),
            "consistent": len({frozenset(values) for values in value_sets.values()}) <= 1,
            "distinct_values": sorted(distinct),
            "failures": {resolver: result.error for resolver, result in results.items() if not result.ok},
        }

    # --------------------------------------------------------------- utilities

    def reverse(self, ip: str, *, resolver: str | None = None) -> DNSQueryResult:
        """PTR lookup for an IP literal."""
        pointer = reverse_pointer(ip)
        if not pointer:
            return self._error_result(ip, "PTR", "not an IP address")
        return self.query(pointer, "PTR", resolver=resolver)

    def nameserver_addresses(self, nameserver: str, *, resolver: str | None = None) -> dict[str, list[str]]:
        """Resolve A/AAAA records for a nameserver hostname."""
        ipv4 = self.query(nameserver, "A", resolver=resolver)
        ipv6 = self.query(nameserver, "AAAA", resolver=resolver)
        return {
            "ipv4": sorted(ipv4.rdata_set()) if ipv4.ok else [],
            "ipv6": sorted(ipv6.rdata_set()) if ipv6.ok else [],
        }

    def detect_wildcard(self, domain: str, *, probes: int = 3, resolver: str | None = None) -> WildcardInfo:
        """Detect wildcard A/AAAA responses for ``domain``.

        Random labels that all resolve to the same address set indicate a
        wildcard. Discovery results are filtered against this so ``*.example.com``
        answers are not reported as real hosts.
        """
        normalized = normalize_hostname(domain)
        if normalized in self._wildcard_cache:
            return self._wildcard_cache[normalized]

        info = WildcardInfo(domain=normalized)
        seen: list[set[str]] = []
        for index in range(max(1, probes)):
            label = f"dnscope-wc-{index}-{random.getrandbits(24):06x}"
            probe = f"{label}.{normalized}"
            info.probe_names.append(probe)
            result = self.query(probe, "A", resolver=resolver)
            if result.ok:
                seen.append(result.rdata_set())
            else:
                seen.append(set())
        non_empty = [item for item in seen if item]
        if non_empty and len(non_empty) == len(seen) and len({frozenset(item) for item in non_empty}) == 1:
            info.wildcard = True
            info.addresses = sorted(non_empty[0])
            info.confidence = Confidence.HIGH.value
            info.evidence = f"{len(non_empty)}/{len(seen)} random labels resolved to {info.addresses}"
        elif non_empty:
            info.confidence = Confidence.LOW.value
            info.evidence = f"{len(non_empty)}/{len(seen)} random labels resolved (inconsistent)"
        else:
            info.confidence = Confidence.HIGH.value
            info.evidence = f"none of {len(seen)} random labels resolved"
        self._wildcard_cache[normalized] = info
        return info

    def is_wildcard_match(self, hostname: str, addresses: Iterable[str]) -> bool:
        """Return ``True`` when ``hostname``'s addresses match the wildcard set."""
        wildcard_set = set(addresses)
        if not wildcard_set:
            return False
        result = self.query(hostname, "A", use_cache=True)
        return result.ok and result.rdata_set() == wildcard_set

    def fingerprint(self, name: str, types: Sequence[str] | None = None) -> Fingerprint:
        """Build a change-detection fingerprint for ``name``."""
        requested = list(types or ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"])
        answer = self.resolve_all(name, requested)
        return fingerprint_from_answer(answer)

    # -------------------------------------------------------------- delegation

    def delegation(self, domain: str, *, max_depth: int = 6) -> DelegationInfo:
        """Walk root -> TLD -> delegation to map authoritative infrastructure.

        Every zone in the path is queried for NS and DS so the chain of trust is
        visible, and the final level carries the nameservers that actually
        answer for the domain.
        """
        normalized = normalize_hostname(domain)
        info = DelegationInfo(domain=normalized)
        if not normalized:
            info.error = "empty domain"
            return info

        zones = self._zone_chain(normalized, max_depth=max_depth)
        for index, zone in enumerate(zones):
            is_last = index == len(zones) - 1
            level = self._delegation_level(zone, index)
            if is_last:
                level.level = "authoritative"
            info.levels.append(level)
            if is_last:
                info.authoritative_nameservers = sorted(level.nameservers)
                break

        base = registered_domain(normalized)
        for nameserver in info.authoritative_nameservers:
            if nameserver == normalized or nameserver.endswith(f".{base}") or base.endswith(nameserver):
                info.in_bailiwick.append(nameserver)
            else:
                info.out_of_bailiwick.append(nameserver)
        info.consistent = bool(info.authoritative_nameservers)
        if not info.authoritative_nameservers:
            info.error = "could not determine authoritative nameservers"
        return info

    def _zone_chain(self, target: str, *, max_depth: int = 6) -> list[str]:
        """Zone names from the root down to ``target`` (bounded by ``max_depth``)."""
        labels = target.split(".")
        zones = ["."]
        for index in range(len(labels) - 1, -1, -1):
            zones.append(".".join(labels[index:]))
        return zones[: max(2, max_depth)]

    def _delegation_level(self, zone: str, index: int) -> DelegationLevel:
        """Query NS (and DS) for one zone in the chain."""
        level_name = "root" if zone == "." else ("tld" if index == 1 else "delegation")
        ns_result = self.query(zone, "NS")
        level = DelegationLevel(
            level=level_name,
            name=zone,
            nameservers=sorted({str(record.parsed.get("target", "")) for record in ns_result.records})
            if ns_result.ok
            else [],
            rcode=ns_result.status,
            error=ns_result.error,
        )
        ds_result = self.query(zone, "DS")
        if ds_result.ok:
            level.ds_records = sorted(ds_result.rdata_set())
        # Glue records arrive in the additional section.
        for record in ns_result.additional:
            if record.rtype in ("A", "AAAA"):
                level.glue.append(f"{record.name} {record.rdata_text}")
        return level

    def profile_nameservers(
        self,
        domain: str,
        *,
        resolver: str | None = None,
        enrich: bool = True,
        probe_timeout: float = 3.0,
    ) -> list[NameserverProfile]:
        """Profile the authoritative nameservers of ``domain``."""
        normalized = normalize_hostname(domain)
        ns_result = self.query(normalized, "NS", resolver=resolver)
        profiles: list[NameserverProfile] = []
        nameservers = sorted(
            {
                str(record.parsed.get("target", ""))
                for record in ns_result.records
                if record.parsed.get("target")
            }
        )
        for nameserver in nameservers:
            profile = NameserverProfile(
                nameserver=nameserver,
                available=False,
                confidence=Confidence.LOW,
            )
            addresses = self.nameserver_addresses(nameserver, resolver=resolver)
            profile.ipv4 = addresses["ipv4"]
            profile.ipv6 = addresses["ipv6"]
            if addresses["ipv4"] or addresses["ipv6"]:
                probe = self.query(
                    normalized,
                    "SOA",
                    resolver=(addresses["ipv4"] or addresses["ipv6"])[0],
                    use_cache=False,
                )
                profile.response_time_ms = probe.meta.duration_ms
                profile.available = probe.ok
                profile.rcode_seen = [probe.status]
                profile.consistent = probe.ok
                if probe.ok:
                    profile.confidence = Confidence.HIGH
                else:
                    profile.errors.append(probe.error)
            else:
                profile.errors.append("nameserver does not resolve")
                profile.confidence = Confidence.MEDIUM
            if enrich and (profile.ipv4 or profile.ipv6):
                pointer = self.reverse((profile.ipv4 or profile.ipv6)[0])
                if pointer.ok:
                    profile.ptr = sorted(pointer.rdata_set())
            profiles.append(profile)
        return profiles

    # ------------------------------------------------------------ introspection

    def txt_resolver(self) -> TxtResolver:
        """Return a TXT-only facade for DNS-backed providers."""
        return TxtResolver(self)

    def stats(self) -> dict[str, Any]:
        """Engine counters for ``dnscope benchmark`` and reports."""
        return {
            "queries_sent": self.queries_sent,
            "queries_cached": self.queries_cached,
            "queries_failed": self.queries_failed,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "average_latency_ms": round(self.total_latency_ms / self.queries_sent, 2)
            if self.queries_sent
            else 0.0,
            "resolvers": {name: info.to_dict() for name, info in sorted(self.resolver_stats.items())},
            "errors": self.errors[-25:],
        }

    def reset_stats(self) -> None:
        """Clear counters."""
        self.queries_sent = 0
        self.queries_cached = 0
        self.queries_failed = 0
        self.total_latency_ms = 0.0
        self.errors.clear()

    def _record_resolver(self, resolver: str, duration_ms: float) -> None:
        """Track latency samples per resolver."""
        if not resolver:
            return
        info = self.resolver_stats.get(resolver)
        if info is None:
            info = ResolverInfo(address=resolver)
            self.resolver_stats[resolver] = info
        info.record_latency(duration_ms)
        info.available = True

    # ------------------------------------------------------------------- cache

    def _cache_key(self, name: str, rtype: str, resolver: str | None, dnssec: bool | None) -> str:
        return f"dns:{name}:{rtype}:{resolver or 'default'}:{bool(dnssec)}"

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        """Read a cached query result, honouring freshness."""
        if self.cache is None:
            return None
        try:
            return self.cache.get(key, namespace="dns")
        except Exception:
            return None

    def _cache_put(self, key: str, result: DNSQueryResult) -> None:
        """Store a query result using its minimum TTL as freshness."""
        if self.cache is None:
            return
        ttl = result.min_ttl()
        try:
            self.cache.set(key, result.to_dict(), ttl=ttl, namespace="dns")
        except Exception as exc:
            _log.debug("dns cache write failed: %s", exc)


# ------------------------------------------------------------------ fingerprints


def fingerprint_from_answer(answer: DNSAnswer) -> Fingerprint:
    """Derive a :class:`Fingerprint` from a completed :class:`DNSAnswer`."""
    rdata: dict[str, list[str]] = {}
    ttls: dict[str, list[int]] = {}
    record_types: list[str] = []
    nameservers: list[str] = []
    dnssec_flags: dict[str, bool] = {}
    resolver = answer.resolver
    status = "NOERROR"

    for query in answer.queries:
        record_types.append(query.rtype)
        if query.records:
            rdata[query.rtype] = sorted(query.rdata_set())
            ttls[query.rtype] = sorted({record.ttl for record in query.records})
        if not query.ok:
            status = query.status
        for flag, value in query.meta.flags.items():
            if flag in ("ad", "do"):
                dnssec_flags[flag] = dnssec_flags.get(flag, False) or value
        if query.rtype == "NS":
            nameservers.extend(query.rdata_set())
        if query.meta.resolver:
            resolver = query.meta.resolver

    fingerprint = Fingerprint(
        name=answer.name,
        resolver=resolver,
        response_code=status,
        answer_count=sum(query.answer_count for query in answer.queries),
        authority_count=sum(query.meta.authority_count for query in answer.queries),
        additional_count=sum(query.meta.additional_count for query in answer.queries),
        record_types=record_types,
        rdata=rdata,
        ttl_pattern={
            key: {"distinct": values, "min": min(values), "max": max(values)}
            for key, values in sorted(ttls.items())
            if values
        },
        dnssec_flags=dnssec_flags,
        nameservers=sorted({normalize_hostname(item) for item in nameservers if item}),
        observed_at=answer.observed_at,
    )
    fingerprint.compute_hash()
    return fingerprint


def _response_from_exception(exc: Any, qname: Any, rdtype: str, rcode: int) -> Any:
    """Build a DNS message for a dnspython NXDOMAIN/NoAnswer exception.

    dnspython raises instead of returning for these two rcodes, but the rest of
    DNScope expects structured answers. The exception usually carries the real
    response; when it does not we synthesize an empty one with the right rcode.
    """
    attached = getattr(exc, "response", None)
    if attached is not None and getattr(attached, "rcode", None) is not None:
        return attached
    for candidate in ("responses", "_responses"):
        values = getattr(exc, candidate, None)
        if values:
            try:
                return list(values)[-1]
            except TypeError:  # pragma: no cover - defensive
                break
    message = dns.message.make_query(qname, rdtype)
    message.set_rcode(rcode)
    return message


class TxtResolver:
    """TXT-only resolver facade handed to DNS-backed providers.

    Providers such as Team Cymru answer over DNS TXT. Giving them this narrow
    facade (instead of the whole engine) keeps the provider surface small and
    makes it obvious that a provider cannot issue arbitrary queries.
    """

    __slots__ = ("_engine", "failures", "lookups", "not_found")

    def __init__(self, engine: DNSEngine) -> None:
        self._engine = engine
        self.lookups = 0
        self.failures = 0
        self.not_found = 0

    @property
    def engine(self) -> DNSEngine:
        """The underlying engine (read-only, for diagnostics only)."""
        return self._engine

    def txt(self, name: str) -> list[str]:
        """Return the TXT strings published at ``name``.

        Raises :class:`DNSResolutionError` for NXDOMAIN and :class:`DNSError`
        for any other failure, so a provider can tell "nothing published here"
        apart from "the lookup itself failed" - those are different findings.
        """
        self.lookups += 1
        result = self._engine.query(name, "TXT")
        if not result.ok:
            if result.nxdomain:
                self.not_found += 1
                raise DNSResolutionError(f"NXDOMAIN for TXT {name}", rcode="NXDOMAIN")
            self.failures += 1
            raise DNSError(f"TXT lookup for {name} returned {result.status}: {result.error}")
        return [value.strip('"') for value in result.values]

    def txt_or_empty(self, name: str) -> list[str]:
        """Like :meth:`txt` but returns an empty list instead of raising."""
        try:
            return self.txt(name)
        except DNSError:
            return []

    def stats(self) -> dict[str, int]:
        """Lookup counters (surfaced by ``dnscope benchmark``)."""
        return {"lookups": self.lookups, "failures": self.failures, "not_found": self.not_found}


__all__ = [
    "DNSEngine",
    "TxtResolver",
    "WildcardInfo",
    "fingerprint_from_answer",
]

"""Asset correlation.

Correlation joins observations across hosts to answer questions like "which of
these hosts share infrastructure?". The results are explicitly labelled
``CORRELATED`` and never claim ownership: two domains on the same IP may be
unrelated tenants of the same provider.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from dnscope.models.common import Confidence, EvidenceQuality, SchemaVersioned
from dnscope.utils.domains import normalize_hostname, registered_domain

#: Correlation dimensions, in decreasing order of interest.
BY_IP = "ip"
BY_PREFIX = "prefix"
BY_ASN = "asn"
BY_CNAME = "cname"
BY_NAMESERVER = "nameserver"
BY_MAIL = "mail"
BY_CERTIFICATE = "certificate"
BY_ORGANIZATION = "organization"
BY_PROVIDER = "provider"


class CorrelationGroup(BaseModel):
    """A set of assets linked by one shared attribute."""

    dimension: str
    value: str
    members: list[str] = Field(default_factory=list)
    #: Extra context (provider name, prefix, etc).
    context: dict[str, Any] = Field(default_factory=dict)
    quality: str = EvidenceQuality.CORRELATED.value
    confidence: str = Confidence.MEDIUM.value
    #: ``True`` when members span more than one registrable domain.
    cross_domain: bool = False

    @property
    def size(self) -> int:
        """Number of members."""
        return len(self.members)

    def describe(self) -> str:
        """One-line description for reports."""
        sample = ", ".join(self.members[:4])
        suffix = f" (+{self.size - 4} more)" if self.size > 4 else ""
        return f"{self.size} asset(s) share {self.dimension}={self.value}: {sample}{suffix}"


class CorrelationResult(SchemaVersioned):
    """Aggregated correlation output for a scan."""

    groups: list[CorrelationGroup] = Field(default_factory=list)
    #: Shared-infrastructure "hubs" ordered by member count.
    hubs: list[dict[str, Any]] = Field(default_factory=list)
    #: Assets that appear in several groups (infrastructure concentration).
    concentration: list[dict[str, Any]] = Field(default_factory=list)
    #: Distinct registrable domains involved.
    domains: list[str] = Field(default_factory=list)
    summary: str = ""

    def by_dimension(self, dimension: str) -> list[CorrelationGroup]:
        """Groups for one dimension."""
        return [group for group in self.groups if group.dimension == dimension]

    def largest(self, limit: int = 10) -> list[CorrelationGroup]:
        """The biggest groups (most shared infrastructure)."""
        return sorted(self.groups, key=lambda group: -group.size)[:limit]

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        """JSON-ready dictionary."""
        return {
            "groups": [group.model_dump() for group in self.groups],
            "hubs": self.hubs,
            "concentration": self.concentration,
            "domains": self.domains,
            "summary": self.summary,
        }


class _Asset:
    """Minimal asset shape the correlation engine understands."""

    __slots__ = (
        "asns",
        "certificates",
        "cnames",
        "hostname",
        "ips",
        "mail",
        "nameservers",
        "organizations",
        "prefixes",
        "providers",
    )

    def __init__(
        self,
        hostname: str,
        *,
        ips: Iterable[str] = (),
        prefixes: Iterable[str] = (),
        asns: Iterable[str] = (),
        cnames: Iterable[str] = (),
        nameservers: Iterable[str] = (),
        mail: Iterable[str] = (),
        certificates: Iterable[str] = (),
        organizations: Iterable[str] = (),
        providers: Iterable[str] = (),
    ) -> None:
        self.hostname = normalize_hostname(hostname)
        self.ips = {str(item) for item in ips if item}
        self.prefixes = {str(item) for item in prefixes if item}
        self.asns = {str(item).upper() for item in asns if item}
        self.cnames = {normalize_hostname(item) for item in cnames if item}
        self.nameservers = {normalize_hostname(item) for item in nameservers if item}
        self.mail = {normalize_hostname(item) for item in mail if item}
        self.certificates = {str(item).lower() for item in certificates if item}
        self.organizations = {str(item) for item in organizations if item}
        self.providers = {str(item) for item in providers if item}


class CorrelationEngine:
    """Finds shared infrastructure across a set of assets."""

    def __init__(self, *, minimum_group_size: int = 2, ignore_apex_nameservers: bool = False) -> None:
        self.minimum_group_size = max(2, minimum_group_size)
        self.ignore_apex_nameservers = ignore_apex_nameservers

    def correlate(self, assets: Iterable[_Asset | dict[str, Any]]) -> CorrelationResult:
        """Correlate a list of assets."""
        normalized = [self._coerce(asset) for asset in assets]
        normalized = [asset for asset in normalized if asset.hostname]
        result = CorrelationResult()
        result.domains = sorted({registered_domain(asset.hostname) for asset in normalized if asset.hostname})

        dimensions: dict[str, dict[str, set[str]]] = {
            BY_IP: defaultdict(set),
            BY_PREFIX: defaultdict(set),
            BY_ASN: defaultdict(set),
            BY_CNAME: defaultdict(set),
            BY_NAMESERVER: defaultdict(set),
            BY_MAIL: defaultdict(set),
            BY_CERTIFICATE: defaultdict(set),
            BY_ORGANIZATION: defaultdict(set),
            BY_PROVIDER: defaultdict(set),
        }

        for asset in normalized:
            for value in asset.ips:
                dimensions[BY_IP][value].add(asset.hostname)
            for value in asset.prefixes:
                dimensions[BY_PREFIX][value].add(asset.hostname)
            for value in asset.asns:
                dimensions[BY_ASN][value].add(asset.hostname)
            for value in asset.cnames:
                dimensions[BY_CNAME][value].add(asset.hostname)
            for value in asset.nameservers:
                dimensions[BY_NAMESERVER][value].add(asset.hostname)
            for value in asset.mail:
                dimensions[BY_MAIL][value].add(asset.hostname)
            for value in asset.certificates:
                dimensions[BY_CERTIFICATE][value].add(asset.hostname)
            for value in asset.organizations:
                dimensions[BY_ORGANIZATION][value].add(asset.hostname)
            for value in asset.providers:
                dimensions[BY_PROVIDER][value].add(asset.hostname)

        membership: dict[str, int] = defaultdict(int)
        for dimension, buckets in dimensions.items():
            if dimension == BY_NAMESERVER and self.ignore_apex_nameservers:
                continue
            for value, members in sorted(buckets.items()):
                if len(members) < self.minimum_group_size:
                    continue
                ordered = sorted(members)
                domains = {registered_domain(member) for member in ordered}
                group = CorrelationGroup(
                    dimension=dimension,
                    value=value,
                    members=ordered,
                    context=self._context(dimension, value, ordered),
                    confidence=self._confidence(dimension, len(ordered)),
                    cross_domain=len(domains) > 1,
                )
                result.groups.append(group)
                for member in ordered:
                    membership[member] += 1

        result.hubs = [
            {"dimension": group.dimension, "value": group.value, "members": group.size}
            for group in result.largest(10)
        ]
        result.concentration = [
            {"asset": name, "shared_groups": count}
            for name, count in sorted(membership.items(), key=lambda item: -item[1])[:20]
            if count > 1
        ]
        result.summary = self._summary(result)
        return result

    # ---------------------------------------------------------------- internals

    def _context(self, dimension: str, value: str, members: list[str]) -> dict[str, Any]:
        """Attach helpful context to a group."""
        domains = sorted({registered_domain(member) for member in members})
        context: dict[str, Any] = {"domains": domains, "domain_count": len(domains)}
        if dimension == BY_ASN:
            context["note"] = "shared ASN does not imply shared ownership"
        if dimension == BY_IP:
            context["note"] = "shared IP may indicate shared hosting rather than a relationship"
        if dimension == BY_CERTIFICATE:
            context["note"] = "the same certificate covers these names"
        return context

    def _confidence(self, dimension: str, size: int) -> str:
        """Confidence that the shared attribute is meaningful."""
        if dimension in (BY_CERTIFICATE, BY_CNAME):
            return Confidence.HIGH.value
        if dimension in (BY_IP, BY_PREFIX) and size <= 3:
            return Confidence.MEDIUM.value
        if dimension == BY_ASN:
            return Confidence.LOW.value
        return Confidence.MEDIUM.value

    def _summary(self, result: CorrelationResult) -> str:
        """Human summary of the correlation output."""
        if not result.groups:
            return "no shared infrastructure observed"
        top = result.largest(3)
        parts = [f"{group.size} asset(s) share {group.dimension}={group.value}" for group in top]
        cross = sum(1 for group in result.groups if group.cross_domain)
        return "; ".join(parts) + (f"; {cross} group(s) span multiple domains" if cross else "")

    def _coerce(self, asset: _Asset | dict[str, Any]) -> _Asset:
        """Accept either an :class:`_Asset` or a plain mapping."""
        if isinstance(asset, _Asset):
            return asset
        data = asset or {}
        return _Asset(
            str(data.get("hostname") or data.get("name") or ""),
            ips=data.get("ips", []) or [],
            prefixes=data.get("prefixes", []) or [],
            asns=data.get("asns", []) or [],
            cnames=data.get("cnames", []) or [],
            nameservers=data.get("nameservers", []) or [],
            mail=data.get("mail", []) or [],
            certificates=data.get("certificates", []) or [],
            organizations=data.get("organizations", []) or [],
            providers=data.get("providers", []) or [],
        )


def asset(
    hostname: str,
    *,
    ips: Iterable[str] = (),
    prefixes: Iterable[str] = (),
    asns: Iterable[str] = (),
    cnames: Iterable[str] = (),
    nameservers: Iterable[str] = (),
    mail: Iterable[str] = (),
    certificates: Iterable[str] = (),
    organizations: Iterable[str] = (),
    providers: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the plain-mapping asset form accepted by :class:`CorrelationEngine`."""
    return {
        "hostname": hostname,
        "ips": list(ips),
        "prefixes": list(prefixes),
        "asns": list(asns),
        "cnames": list(cnames),
        "nameservers": list(nameservers),
        "mail": list(mail),
        "certificates": list(certificates),
        "organizations": list(organizations),
        "providers": list(providers),
    }


__all__ = [
    "BY_ASN",
    "BY_CERTIFICATE",
    "BY_CNAME",
    "BY_IP",
    "BY_MAIL",
    "BY_NAMESERVER",
    "BY_ORGANIZATION",
    "BY_PREFIX",
    "BY_PROVIDER",
    "CorrelationEngine",
    "CorrelationGroup",
    "CorrelationResult",
    "asset",
]

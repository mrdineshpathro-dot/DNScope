"""Graph construction from analysis results.

The builder is the only place that knows how a scan result maps onto nodes and
edges, so the rest of DNScope can treat the graph as an opaque structure.
"""

from __future__ import annotations

from typing import Any, Iterable

from dnscope.graph.model import EdgeType, Graph, NodeKind
from dnscope.models.common import EvidenceQuality
from dnscope.utils.domains import (
    format_asn,
    normalize_hostname,
    parent_domain,
    registered_domain,
)


class GraphBuilder:
    """Turns scan output into an infrastructure graph."""

    def __init__(self, *, max_nodes: int = 20_000, max_edges: int = 60_000) -> None:
        self.graph = Graph(max_nodes=max_nodes, max_edges=max_edges)

    # ------------------------------------------------------------------ targets

    def add_target(self, target: str, *, kind: str = NodeKind.DOMAIN, source: str = "target") -> str:
        """Add the scanned target as the graph's root node."""
        name = normalize_hostname(target)
        domain = registered_domain(name)
        self.graph.add_node(
            name,
            kind,
            label=name,
            source=source,
            domain=domain,
            attributes={"target": True},
        )
        if domain and domain != name:
            self.graph.add_node(domain, NodeKind.DOMAIN, label=domain, source=source, domain=domain)
            self.graph.add_edge(
                name,
                EdgeType.PARENT_OF,
                domain,
                source_kind=kind,
                target_kind=NodeKind.DOMAIN,
                provenance=source,
            )
        return name

    def add_dns_answer(self, hostname: str, answer: Any, *, source: str = "dns") -> None:
        """Add nodes/edges for one :class:`dnscope.models.dns.DNSAnswer`."""
        name = normalize_hostname(hostname)
        if not name:
            return
        self.graph.add_node(
            name, NodeKind.SUBDOMAIN if parent_domain(name) else NodeKind.DOMAIN,
            label=name, source=source, domain=registered_domain(name),
        )
        for query in answer.queries:
            rtype = query.rtype
            for record in query.records:
                parsed = record.parsed or {}
                if rtype in ("A", "AAAA"):
                    address = str(parsed.get("address", ""))
                    if not address:
                        continue
                    self.graph.add_node(
                        address, NodeKind.IP, label=address, source=source,
                        attributes={"version": parsed.get("version")},
                        quality=EvidenceQuality.OBSERVED.value,
                    )
                    self.graph.add_edge(
                        name, EdgeType.RESOLVES_TO, address,
                        source_kind=NodeKind.SUBDOMAIN, target_kind=NodeKind.IP,
                        attributes={"ttl": record.ttl, "rtype": rtype},
                        provenance=source,
                    )
                elif rtype == "CNAME":
                    target = str(parsed.get("target", ""))
                    if target:
                        self.graph.add_node(
                            target, NodeKind.CNAME, label=target, source=source,
                            domain=registered_domain(target),
                        )
                        self.graph.add_edge(
                            name, EdgeType.CNAME_TO, target,
                            source_kind=NodeKind.SUBDOMAIN, target_kind=NodeKind.CNAME,
                            attributes={"ttl": record.ttl}, provenance=source,
                        )
                elif rtype == "NS":
                    ns = str(parsed.get("target", ""))
                    if ns:
                        self.graph.add_node(
                            ns, NodeKind.NS, label=ns, source=source,
                            domain=registered_domain(ns),
                        )
                        self.graph.add_edge(
                            name, EdgeType.USES_NS, ns,
                            source_kind=NodeKind.DOMAIN, target_kind=NodeKind.NS,
                            provenance=source,
                        )
                elif rtype == "MX":
                    exchange = str(parsed.get("exchange", ""))
                    if exchange and exchange != ".":
                        self.graph.add_node(
                            exchange, NodeKind.MX, label=exchange, source=source,
                            domain=registered_domain(exchange),
                        )
                        self.graph.add_edge(
                            name, EdgeType.USES_MX, exchange,
                            source_kind=NodeKind.DOMAIN, target_kind=NodeKind.MX,
                            attributes={"preference": parsed.get("preference")},
                            provenance=source,
                        )
                elif rtype == "PTR":
                    for value in record.rdata:
                        pointer = normalize_hostname(value)
                        if pointer:
                            self.graph.add_node(
                                pointer, NodeKind.SUBDOMAIN, label=pointer, source=source,
                                domain=registered_domain(pointer),
                            )
                            self.graph.add_edge(
                                name, EdgeType.RELATED_TO, pointer,
                                attributes={"rtype": "PTR"}, provenance=source,
                            )

    def add_ip_intelligence(
        self,
        address: str,
        *,
        asn: str = "",
        organization: str = "",
        prefix: str = "",
        provider: str = "",
        source: str = "ip-intel",
    ) -> None:
        """Attach ASN/organization nodes to an IP."""
        ip = str(address).strip()
        if not ip:
            return
        self.graph.add_node(ip, NodeKind.IP, label=ip, source=source)
        normalized_asn = format_asn(asn)
        if normalized_asn:
            self.graph.add_node(
                normalized_asn, NodeKind.ASN, label=normalized_asn, source=source,
                attributes={"organization": organization, "prefix": prefix},
            )
            self.graph.add_edge(
                ip, EdgeType.BELONGS_TO_ASN, normalized_asn,
                source_kind=NodeKind.IP, target_kind=NodeKind.ASN,
                provenance=source, quality=EvidenceQuality.OBSERVED.value,
            )
        if provider:
            self.graph.add_node(
                provider, NodeKind.CLOUD_PROVIDER, label=provider, source=source,
                quality=EvidenceQuality.INFERRED.value,
            )
            self.graph.add_edge(
                ip, EdgeType.HOSTED_BY, provider,
                source_kind=NodeKind.IP, target_kind=NodeKind.CLOUD_PROVIDER,
                provenance=source, quality=EvidenceQuality.INFERRED.value,
            )

    def add_certificate(
        self,
        certificate: dict[str, Any],
        *,
        covered_hosts: Iterable[str] = (),
        source: str = "ct",
    ) -> None:
        """Add a certificate node and link it to the names it covers."""
        identity = str(
            certificate.get("fingerprint_sha256")
            or certificate.get("serial_number")
            or certificate.get("subject_cn")
            or ""
        ).lower()
        if not identity:
            return
        node_id = f"cert:{identity[:32]}"
        self.graph.add_node(
            node_id,
            NodeKind.CERTIFICATE,
            label=str(certificate.get("subject_cn") or identity[:16]),
            source=source,
            attributes={
                "serial": certificate.get("serial_number", ""),
                "not_before": certificate.get("not_before"),
                "not_after": certificate.get("not_after"),
                "issuer": certificate.get("issuer_cn", ""),
            },
            quality=EvidenceQuality.OBSERVED.value,
        )
        issuer = normalize_hostname(str(certificate.get("issuer_cn") or ""))
        if issuer:
            self.graph.add_node(issuer, NodeKind.CA, label=issuer, source=source)
            self.graph.add_edge(
                node_id, EdgeType.ISSUED_BY, issuer,
                source_kind=NodeKind.CERTIFICATE, target_kind=NodeKind.CA,
                provenance=source,
            )
        for host in covered_hosts:
            normalized = normalize_hostname(host)
            if not normalized:
                continue
            self.graph.add_node(
                normalized, NodeKind.SUBDOMAIN, label=normalized, source=source,
                domain=registered_domain(normalized),
            )
            self.graph.add_edge(
                node_id, EdgeType.ISSUED_TO, normalized,
                source_kind=NodeKind.CERTIFICATE, target_kind=NodeKind.SUBDOMAIN,
                provenance=source,
            )

    def add_cloud_provider(
        self,
        subject: str,
        provider: str,
        *,
        category: str = "cloud",
        evidence: str = "",
        confidence: str = "MEDIUM",
        source: str = "fingerprint",
    ) -> None:
        """Link a host or IP to a detected provider."""
        subject_id = normalize_hostname(subject) or str(subject)
        if not subject_id or not provider:
            return
        kind = {
            "cdn": NodeKind.CDN,
            "waf": NodeKind.WAF,
            "dns": NodeKind.DNS_PROVIDER,
        }.get(category, NodeKind.CLOUD_PROVIDER)
        self.graph.add_node(
            provider, kind, label=provider, source=source,
            attributes={"category": category, "evidence": evidence, "confidence": confidence},
            quality=EvidenceQuality.INFERRED.value,
        )
        relation = EdgeType.PROXIED_BY if category in ("cdn", "waf") else EdgeType.HOSTED_BY
        self.graph.add_edge(
            subject_id, relation, provider,
            target_kind=kind, provenance=source,
            attributes={"evidence": evidence}, quality=EvidenceQuality.INFERRED.value,
        )

    def add_registrar(self, domain: str, registrar: str, *, source: str = "rdap") -> None:
        """Link a domain to its registrar."""
        name = normalize_hostname(domain)
        if not name or not registrar:
            return
        self.graph.add_node(name, NodeKind.DOMAIN, label=name, source=source)
        self.graph.add_node(registrar, NodeKind.REGISTRAR, label=registrar, source=source)
        self.graph.add_edge(
            name, EdgeType.REGISTERED_WITH, registrar,
            source_kind=NodeKind.DOMAIN, target_kind=NodeKind.REGISTRAR,
            provenance=source,
        )

    def add_threat_indicator(
        self,
        subject: str,
        indicator: str,
        *,
        provider: str = "",
        detail: str = "",
    ) -> None:
        """Attach a third-party threat indicator (attributed)."""
        subject_id = normalize_hostname(subject) or str(subject)
        if not subject_id or not indicator:
            return
        node_id = f"indicator:{indicator.lower()[:64]}"
        self.graph.add_node(
            node_id, NodeKind.THREAT_INDICATOR, label=indicator,
            source=provider or "threat-intel",
            attributes={"detail": detail, "provider": provider},
            quality=EvidenceQuality.OBSERVED.value,
        )
        self.graph.add_edge(
            subject_id, EdgeType.RELATED_TO, node_id,
            target_kind=NodeKind.THREAT_INDICATOR,
            provenance=provider or "threat-intel",
        )

    def add_parent_relationship(self, hostname: str) -> None:
        """Link a subdomain to its parent name (hierarchy for the graph view)."""
        name = normalize_hostname(hostname)
        parent = parent_domain(name)
        if not name or not parent:
            return
        self.graph.add_node(name, NodeKind.SUBDOMAIN, label=name, domain=registered_domain(name))
        self.graph.add_node(parent, NodeKind.DOMAIN, label=parent, domain=registered_domain(parent))
        self.graph.add_edge(
            name, EdgeType.PARENT_OF, parent,
            source_kind=NodeKind.SUBDOMAIN, target_kind=NodeKind.DOMAIN,
            provenance="hierarchy",
        )

    # ------------------------------------------------------------------ output

    def build(self) -> Graph:
        """Return the constructed graph."""
        return self.graph


__all__ = ["GraphBuilder"]

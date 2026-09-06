"""Graph analytics: degree, centrality, clusters and shared infrastructure."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any

from pydantic import BaseModel, Field

from dnscope.graph.model import Graph
from dnscope.models.assets import AssetKind


class GraphMetrics(BaseModel):
    """Computed metrics for a graph."""

    node_count: int = 0
    edge_count: int = 0
    component_count: int = 0
    largest_component: int = 0
    density: float = 0.0
    average_degree: float = 0.0
    max_degree: int = 0
    #: Top nodes by degree centrality.
    hubs: list[dict[str, Any]] = Field(default_factory=list)
    #: Nodes with the highest betweenness (bounded computation).
    bridges: list[dict[str, Any]] = Field(default_factory=list)
    #: Provider concentration: how much infrastructure sits with each provider.
    provider_concentration: list[dict[str, Any]] = Field(default_factory=list)
    #: Clusters of nodes sharing infrastructure.
    clusters: list[dict[str, Any]] = Field(default_factory=list)
    kinds: dict[str, int] = Field(default_factory=dict)
    relations: dict[str, int] = Field(default_factory=dict)

    def summary(self) -> str:
        """One-line summary for terminal output."""
        return (
            f"{self.node_count} nodes, {self.edge_count} edges, "
            f"{self.component_count} component(s), density {self.density:.4f}, "
            f"avg degree {self.average_degree:.2f}"
        )


class GraphAnalytics:
    """Computes structural metrics over a :class:`Graph`."""

    def __init__(self, graph: Graph, *, betweenness_sample: int = 100) -> None:
        self.graph = graph
        #: Betweenness is O(V*E); sample large graphs to stay predictable.
        self.betweenness_sample = max(10, betweenness_sample)

    # ------------------------------------------------------------------ public

    def analyze(self) -> GraphMetrics:
        """Compute the full metric set."""
        metrics = GraphMetrics()
        counts = self.graph.counts()
        metrics.node_count = counts["nodes"]
        metrics.edge_count = counts["edges"]
        metrics.kinds = counts["by_kind"]
        metrics.relations = counts["by_relation"]

        components = self.graph.components()
        metrics.component_count = len(components)
        metrics.largest_component = len(components[0]) if components else 0

        degrees = self.degree_distribution()
        if degrees:
            metrics.average_degree = round(sum(degrees.values()) / len(degrees), 3)
            metrics.max_degree = max(degrees.values())
        if metrics.node_count > 1:
            possible = metrics.node_count * (metrics.node_count - 1)
            metrics.density = round(metrics.edge_count / possible, 5) if possible else 0.0

        metrics.hubs = self.top_hubs()
        metrics.bridges = self.top_betweenness()
        metrics.provider_concentration = self.provider_concentration()
        metrics.clusters = self.shared_infrastructure_clusters()
        return metrics

    def degree_distribution(self) -> dict[str, int]:
        """Total degree per node."""
        return {node_id: self.graph.degree(node_id)["total"] for node_id in self.graph.nodes}

    def centrality(self) -> dict[str, float]:
        """Normalized degree centrality per node."""
        degrees = self.degree_distribution()
        if not degrees:
            return {}
        denominator = max(1, len(self.graph.nodes) - 1)
        return {node_id: round(value / denominator, 5) for node_id, value in degrees.items()}

    def top_hubs(self, limit: int = 10) -> list[dict[str, Any]]:
        """Highest-degree nodes, with their kind and neighbours."""
        centrality = self.centrality()
        ranked = sorted(centrality.items(), key=lambda item: -item[1])[:limit]
        hubs: list[dict[str, Any]] = []
        for node_id, value in ranked:
            node = self.graph.node(node_id)
            degree = self.graph.degree(node_id)
            hubs.append(
                {
                    "node_id": node_id,
                    "kind": node.kind if node else "",
                    "label": node.label if node else node_id,
                    "degree": degree["total"],
                    "in_degree": degree["in"],
                    "out_degree": degree["out"],
                    "centrality": value,
                    "neighbours": self.graph.neighbors(node_id, direction="both")[:10],
                }
            )
        return hubs

    def top_betweenness(self, limit: int = 10) -> list[dict[str, Any]]:
        """Approximate betweenness centrality (Brandes' algorithm, sampled).

        Nodes that sit between otherwise separate parts of the graph are
        infrastructure choke points, which is exactly what an attack-surface
        review wants to see.
        """
        if len(self.graph.nodes) < 3:
            return []
        adjacency = self._undirected_adjacency()
        nodes = list(self.graph.nodes)
        sample = nodes if len(nodes) <= self.betweenness_sample else nodes[: self.betweenness_sample]
        scores: dict[str, float] = defaultdict(float)
        for source in sample:
            stack: list[str] = []
            predecessors: dict[str, list[str]] = defaultdict(list)
            sigma: dict[str, float] = defaultdict(float)
            distance: dict[str, int] = defaultdict(lambda: -1)
            sigma[source] = 1.0
            distance[source] = 0
            queue = deque([source])
            while queue:
                current = queue.popleft()
                stack.append(current)
                for neighbour in adjacency.get(current, []):
                    if distance[neighbour] < 0:
                        distance[neighbour] = distance[current] + 1
                        queue.append(neighbour)
                    if distance[neighbour] == distance[current] + 1:
                        sigma[neighbour] += sigma[current]
                        predecessors[neighbour].append(current)
            delta: dict[str, float] = defaultdict(float)
            while stack:
                node = stack.pop()
                for predecessor in predecessors[node]:
                    if sigma[node]:
                        delta[predecessor] += (sigma[predecessor] / sigma[node]) * (1 + delta[node])
                if node != source:
                    scores[node] += delta[node]

        if len(sample) > 1:
            scale = 1.0 / ((len(sample) - 1) * (len(sample) - 2)) if len(sample) > 2 else 1.0
            scores = {key: value * scale for key, value in scores.items()}
        ranked = sorted(scores.items(), key=lambda item: -item[1])[:limit]
        bridges: list[dict[str, Any]] = []
        for node_id, value in ranked:
            node = self.graph.node(node_id)
            bridges.append(
                {
                    "node_id": node_id,
                    "kind": node.kind if node else "",
                    "label": node.label if node else node_id,
                    "betweenness": round(value, 5),
                }
            )
        return bridges

    def provider_concentration(self, limit: int = 15) -> list[dict[str, Any]]:
        """How many assets depend on each provider/CDN/CA node."""
        provider_kinds = {
            AssetKind.CLOUD_PROVIDER,
            AssetKind.CDN,
            AssetKind.WAF,
            AssetKind.DNS_PROVIDER,
            AssetKind.CA,
            AssetKind.NS,
            AssetKind.ASN,
        }
        rows: list[dict[str, Any]] = []
        for node in self.graph.nodes.values():
            if node.kind not in provider_kinds:
                continue
            dependents = self.graph.edges_to(node.node_id)
            if not dependents:
                continue
            dependant_ids = sorted({edge.source for edge in dependents})
            rows.append(
                {
                    "provider": node.label or node.node_id,
                    "kind": node.kind,
                    "dependents": len(dependant_ids),
                    "examples": dependant_ids[:10],
                }
            )
        rows.sort(key=lambda row: -row["dependents"])
        return rows[:limit]

    def shared_infrastructure_clusters(self, limit: int = 20) -> list[dict[str, Any]]:
        """Groups of hosts sharing an IP, ASN, CNAME or nameserver."""
        clusters: list[dict[str, Any]] = []
        for relation in ("RESOLVES_TO", "CNAME_TO", "USES_NS", "BELONGS_TO_ASN", "USES_MX"):
            buckets: dict[str, list[str]] = defaultdict(list)
            for edge in self.graph.edges:
                if edge.relation != relation:
                    continue
                buckets[edge.target].append(edge.source)
            for value, members in buckets.items():
                unique = sorted(set(members))
                if len(unique) < 2:
                    continue
                clusters.append(
                    {
                        "relation": relation,
                        "shared_with": value,
                        "members": unique,
                        "size": len(unique),
                    }
                )
        clusters.sort(key=lambda item: -item["size"])
        return clusters[:limit]

    def kind_counts(self) -> Counter[str]:
        """Node counts by kind."""
        return Counter(node.kind for node in self.graph.nodes.values())

    def relation_counts(self) -> Counter[str]:
        """Edge counts by relation."""
        return Counter(edge.relation for edge in self.graph.edges)

    def isolated_nodes(self) -> list[str]:
        """Nodes with no relationships (often stale or mis-scoped assets)."""
        return [
            node_id
            for node_id in self.graph.nodes
            if self.graph.degree(node_id)["total"] == 0
        ]

    # --------------------------------------------------------------- internals

    def _undirected_adjacency(self) -> dict[str, set[str]]:
        """Adjacency ignoring edge direction."""
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in self.graph.edges:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)
        return adjacency


__all__ = ["GraphAnalytics", "GraphMetrics"]

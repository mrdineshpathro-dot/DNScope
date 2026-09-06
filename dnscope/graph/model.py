"""Graph model: nodes, edges and traversal primitives.

The graph is a plain in-memory structure with hard ceilings on nodes and edges so
a huge scan cannot exhaust memory. Every node and edge carries observation
timestamps, which is what makes historical ("as of") queries possible.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from dnscope.exceptions import LimitsExceeded
from dnscope.models.assets import AssetKind, EdgeType
from dnscope.models.common import EvidenceQuality
from dnscope.utils.time_utils import now_utc, parse_timestamp

#: Node kinds re-exported for graph callers.
NodeKind = AssetKind


class GraphNode(BaseModel):
    """A vertex in the infrastructure graph."""

    node_id: str
    kind: str
    label: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[str] = Field(default_factory=list)
    quality: str = EvidenceQuality.OBSERVED.value
    #: Registrable domain the node belongs to (for scoping/aggregation).
    domain: str = ""

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @property
    def identity(self) -> str:
        """Canonical identity used for de-duplication."""
        return self.node_id.lower()

    def touch(self, moment: datetime | None = None) -> None:
        """Update observation lifetime."""
        when = moment or now_utc()
        if self.first_seen is None or when < self.first_seen:
            self.first_seen = when
        if self.last_seen is None or when > self.last_seen:
            self.last_seen = when

    def merge(self, other: GraphNode) -> None:
        """Merge attributes and sources from another observation."""
        self.touch(other.last_seen)
        for key, value in (other.attributes or {}).items():
            if key not in self.attributes or not self.attributes[key]:
                self.attributes[key] = value
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)


class GraphEdge(BaseModel):
    """A directed, typed relationship between two nodes."""

    source: str
    target: str
    relation: str
    weight: float = 1.0
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    quality: str = EvidenceQuality.OBSERVED.value
    sources: list[str] = Field(default_factory=list)

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def _parse(cls, value: Any) -> Any:
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @property
    def identity(self) -> str:
        """Canonical identity for de-duplication."""
        return f"{self.source.lower()}|{self.relation}|{self.target.lower()}"

    def touch(self, moment: datetime | None = None) -> None:
        """Update observation lifetime."""
        when = moment or now_utc()
        if self.first_seen is None or when < self.first_seen:
            self.first_seen = when
        if self.last_seen is None or when > self.last_seen:
            self.last_seen = when

    def to_tuple(self) -> tuple[str, str, str]:
        """``(source, relation, target)`` triple."""
        return (self.source, self.relation, self.target)


class PathStep(BaseModel):
    """One hop in a relationship path."""

    node_id: str
    kind: str = ""
    label: str = ""
    relation: str = ""

    def describe(self) -> str:
        """Human readable step, e.g. ``-> RESOLVES_TO -> 1.2.3.4``."""
        arrow = f"-> {self.relation} -> " if self.relation else ""
        return f"{arrow}{self.label or self.node_id}"


class Graph(BaseModel):
    """Bounded property graph with traversal helpers."""

    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)
    #: Adjacency built lazily (invalidated on mutation).
    _adjacency: dict[str, list[GraphEdge]] | None = None
    _reverse: dict[str, list[GraphEdge]] | None = None
    max_nodes: int = 20_000
    max_edges: int = 60_000

    model_config = {"arbitrary_types_allowed": True}

    # ---------------------------------------------------------------- mutation

    def add_node(
        self,
        node_id: str,
        kind: str,
        *,
        label: str = "",
        attributes: dict[str, Any] | None = None,
        source: str = "",
        quality: str = EvidenceQuality.OBSERVED.value,
        domain: str = "",
        observed_at: datetime | None = None,
    ) -> GraphNode:
        """Add (or update) a node."""
        key = node_id.strip().lower()
        if not key:
            raise ValueError("node_id must not be empty")
        existing = self.nodes.get(key)
        if existing is not None:
            existing.touch(observed_at)
            if label and not existing.label:
                existing.label = label
            if attributes:
                for name, value in attributes.items():
                    if value not in (None, "", []):
                        existing.attributes[name] = value
            if source and source not in existing.sources:
                existing.sources.append(source)
            self._invalidate()
            return existing
        if len(self.nodes) >= self.max_nodes:
            raise LimitsExceeded(
                f"graph node limit reached ({self.max_nodes})",
                details={"limit": self.max_nodes},
            )
        node = GraphNode(
            node_id=key,
            kind=kind,
            label=label or key,
            attributes=attributes or {},
            sources=[source] if source else [],
            quality=quality,
            domain=domain,
        )
        node.touch(observed_at)
        self.nodes[key] = node
        self._invalidate()
        return node

    def add_edge(
        self,
        source: str,
        relation: str,
        target: str,
        *,
        weight: float = 1.0,
        attributes: dict[str, Any] | None = None,
        source_label: str = "",
        source_kind: str = "",
        target_label: str = "",
        target_kind: str = "",
        quality: str = EvidenceQuality.OBSERVED.value,
        provenance: str = "",
        observed_at: datetime | None = None,
        create_missing: bool = True,
    ) -> GraphEdge | None:
        """Add (or update) an edge, creating endpoint nodes when asked."""
        src = source.strip().lower()
        dst = target.strip().lower()
        if not src or not dst or not relation:
            return None
        if create_missing:
            if src not in self.nodes:
                self.add_node(
                    src, source_kind or NodeKind.DOMAIN, label=source_label, observed_at=observed_at
                )
            if dst not in self.nodes:
                self.add_node(
                    dst, target_kind or NodeKind.DOMAIN, label=target_label, observed_at=observed_at
                )
        if src not in self.nodes or dst not in self.nodes:
            return None

        identity = f"{src}|{relation}|{dst}"
        for edge in self._index()[identity]:
            edge.touch(observed_at)
            if weight and weight != 1.0:
                edge.weight += weight - 1.0
            if attributes:
                edge.attributes.update(attributes)
            if provenance and provenance not in edge.sources:
                edge.sources.append(provenance)
            self._invalidate()
            return edge

        if len(self.edges) >= self.max_edges:
            raise LimitsExceeded(
                f"graph edge limit reached ({self.max_edges})",
                details={"limit": self.max_edges},
            )
        edge = GraphEdge(
            source=src,
            target=dst,
            relation=relation,
            weight=weight,
            attributes=attributes or {},
            quality=quality,
            sources=[provenance] if provenance else [],
        )
        edge.touch(observed_at)
        self.edges.append(edge)
        self._invalidate()
        return edge

    # ------------------------------------------------------------------ lookup

    def node(self, node_id: str) -> GraphNode | None:
        """Return a node by id."""
        return self.nodes.get(node_id.strip().lower())

    def nodes_of_kind(self, kind: str) -> list[GraphNode]:
        """All nodes of a given kind."""
        return [node for node in self.nodes.values() if node.kind == kind]

    def edges_from(self, node_id: str, relation: str | None = None) -> list[GraphEdge]:
        """Outgoing edges from ``node_id`` (optionally filtered by relation)."""
        key = node_id.strip().lower()
        edges = self._adjacency_map().get(key, [])
        return [edge for edge in edges if relation is None or edge.relation == relation]

    def edges_to(self, node_id: str, relation: str | None = None) -> list[GraphEdge]:
        """Incoming edges to ``node_id``."""
        key = node_id.strip().lower()
        edges = self._reverse_map().get(key, [])
        return [edge for edge in edges if relation is None or edge.relation == relation]

    def neighbors(self, node_id: str, *, direction: str = "out") -> list[str]:
        """Neighbour ids in the requested direction (``out``/``in``/``both``)."""
        key = node_id.strip().lower()
        found: set[str] = set()
        if direction in ("out", "both"):
            found.update(edge.target for edge in self._adjacency_map().get(key, []))
        if direction in ("in", "both"):
            found.update(edge.source for edge in self._reverse_map().get(key, []))
        return sorted(found)

    def degree(self, node_id: str) -> dict[str, int]:
        """In/out/total degree of a node."""
        key = node_id.strip().lower()
        out_degree = len(self._adjacency_map().get(key, []))
        in_degree = len(self._reverse_map().get(key, []))
        return {"in": in_degree, "out": out_degree, "total": in_degree + out_degree}

    # --------------------------------------------------------------- traversal

    def path(self, start: str, end: str, *, max_depth: int = 8) -> list[PathStep] | None:
        """Shortest relationship path between two nodes (BFS, undirected)."""
        src = start.strip().lower()
        dst = end.strip().lower()
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            node = self.nodes[src]
            return [PathStep(node_id=src, kind=node.kind, label=node.label)]

        adjacency = self._adjacency_map()
        reverse = self._reverse_map()
        queue: deque[tuple[str, list[PathStep]]] = deque([(src, [self._step(src, "")])])
        visited = {src}
        depth = 0
        while queue and depth <= max_depth:
            current, path = queue.popleft()
            if len(path) > max_depth + 1:
                continue
            for edge in adjacency.get(current, []):
                if edge.target in visited:
                    continue
                step = self._step(edge.target, edge.relation)
                candidate = [*path, step]
                if edge.target == dst:
                    return candidate
                visited.add(edge.target)
                queue.append((edge.target, candidate))
            for edge in reverse.get(current, []):
                if edge.source in visited:
                    continue
                step = self._step(edge.source, edge.relation)
                candidate = [*path, step]
                if edge.source == dst:
                    return candidate
                visited.add(edge.source)
                queue.append((edge.source, candidate))
            depth += 1
        return None

    def components(self) -> list[list[str]]:
        """Connected components (undirected), largest first."""
        adjacency = self._adjacency_map()
        reverse = self._reverse_map()
        seen: set[str] = set()
        groups: list[list[str]] = []
        for node_id in self.nodes:
            if node_id in seen:
                continue
            component: list[str] = []
            stack = [node_id]
            while stack:
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)
                component.append(current)
                stack.extend(edge.target for edge in adjacency.get(current, []))
                stack.extend(edge.source for edge in reverse.get(current, []))
            groups.append(sorted(component))
        groups.sort(key=len, reverse=True)
        return groups

    def subgraph(self, node_ids: Iterable[str]) -> Graph:
        """Return a new graph containing only ``node_ids`` and internal edges."""
        wanted = {item.strip().lower() for item in node_ids}
        graph = Graph(max_nodes=self.max_nodes, max_edges=self.max_edges)
        for node_id in wanted:
            node = self.nodes.get(node_id)
            if node is not None:
                graph.nodes[node_id] = node.model_copy(deep=True)
        graph.edges = [
            edge.model_copy(deep=True)
            for edge in self.edges
            if edge.source in wanted and edge.target in wanted
        ]
        return graph

    def as_of(self, moment: datetime | str) -> Graph:
        """Graph restricted to observations valid at ``moment``."""
        when = parse_timestamp(moment) if isinstance(moment, str) else moment
        if when is None:
            raise ValueError(f"invalid timestamp: {moment!r}")
        graph = Graph(max_nodes=self.max_nodes, max_edges=self.max_edges)
        for node_id, node in self.nodes.items():
            if _valid(node.first_seen, node.last_seen, when):
                graph.nodes[node_id] = node.model_copy(deep=True)
        graph.edges = [
            edge.model_copy(deep=True)
            for edge in self.edges
            if _valid(edge.first_seen, edge.last_seen, when)
            and edge.source in graph.nodes
            and edge.target in graph.nodes
        ]
        return graph

    # ------------------------------------------------------------------ output

    def counts(self) -> dict[str, Any]:
        """Node/edge counts plus the per-kind and per-relation breakdowns."""
        by_kind: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            by_kind[node.kind] += 1
        by_relation: dict[str, int] = defaultdict(int)
        for edge in self.edges:
            by_relation[edge.relation] += 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_kind": dict(sorted(by_kind.items())),
            "by_relation": dict(sorted(by_relation.items())),
        }

    def to_dict(self, *, limit_nodes: int = 2_000, limit_edges: int = 5_000) -> dict[str, Any]:
        """JSON-ready representation (bounded for report payloads)."""
        return {
            "counts": self.counts(),
            "nodes": [node.model_dump(mode="json") for node in list(self.nodes.values())[:limit_nodes]],
            "edges": [edge.model_dump(mode="json") for edge in self.edges[:limit_edges]],
        }

    def to_dot(self, *, limit: int = 500) -> str:
        """Graphviz DOT rendering (used by ``dnscope graph --format dot``)."""
        lines = ["graph dnscope {", "  rankdir=LR;", "  node [shape=box, fontsize=10];"]
        for node in list(self.nodes.values())[:limit]:
            label = (node.label or node.node_id).replace('"', "'")
            lines.append(f'  "{node.node_id}" [label="{label}\\n({node.kind})"];')
        for edge in self.edges[:limit]:
            lines.append(f'  "{edge.source}" -- "{edge.target}" [label="{edge.relation}", fontsize=8];')
        lines.append("}")
        return "\n".join(lines)

    def merge(self, other: Graph) -> None:
        """Merge another graph into this one."""
        for node_id, node in other.nodes.items():
            existing = self.nodes.get(node_id)
            if existing is None:
                self.nodes[node_id] = node.model_copy(deep=True)
            else:
                existing.merge(node)
        index = self._index()
        for edge in other.edges:
            if index[edge.identity]:
                continue
            self.edges.append(edge.model_copy(deep=True))
        self._invalidate()

    # --------------------------------------------------------------- internals

    def _step(self, node_id: str, relation: str) -> PathStep:
        node = self.nodes.get(node_id)
        return PathStep(
            node_id=node_id,
            kind=node.kind if node else "",
            label=(node.label if node else "") or node_id,
            relation=relation,
        )

    def _invalidate(self) -> None:
        """Clear cached adjacency structures."""
        self._adjacency = None
        self._reverse = None

    def _adjacency_map(self) -> dict[str, list[GraphEdge]]:
        if self._adjacency is None:
            mapping: dict[str, list[GraphEdge]] = defaultdict(list)
            for edge in self.edges:
                mapping[edge.source].append(edge)
            self._adjacency = dict(mapping)
        return self._adjacency

    def _reverse_map(self) -> dict[str, list[GraphEdge]]:
        if self._reverse is None:
            mapping: dict[str, list[GraphEdge]] = defaultdict(list)
            for edge in self.edges:
                mapping[edge.target].append(edge)
            self._reverse = dict(mapping)
        return self._reverse

    def _index(self) -> dict[str, list[GraphEdge]]:
        """Edge lookup by identity (rebuilt on demand)."""
        mapping: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in self.edges:
            mapping[edge.identity].append(edge)
        return mapping

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self.nodes)

    def iter_nodes(self) -> Iterator[GraphNode]:
        """Iterate the graph's nodes.

        Deliberately a named method rather than ``__iter__``: overriding
        ``__iter__`` on a Pydantic model replaces the key/value iteration that
        ``dict(model)`` relies on, which made ``dict(graph)`` raise.
        """
        return iter(self.nodes.values())


def _valid(first: datetime | None, last: datetime | None, when: datetime) -> bool:
    """Return ``True`` when an observation window covers ``when``."""
    if first is not None and when < first:
        return False
    return last is None or when <= last


__all__ = [
    "EdgeType",
    "Graph",
    "GraphEdge",
    "GraphNode",
    "NodeKind",
    "PathStep",
]

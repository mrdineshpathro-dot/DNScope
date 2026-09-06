"""Temporal graph queries.

Historical views are built **only from stored observations**: DNScope never
reconstructs what infrastructure "probably" looked like. If an observation was
not recorded, it is simply absent from the historical graph.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from pydantic import BaseModel, Field

from dnscope.graph.analytics import GraphAnalytics, GraphMetrics
from dnscope.graph.model import Graph
from dnscope.utils.time_utils import now_utc, parse_timestamp


class TemporalEdge(BaseModel):
    """A relationship with its observation window."""

    source: str
    relation: str
    target: str
    source_kind: str = ""
    target_kind: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class TemporalGraph:
    """Builds point-in-time views of the infrastructure graph."""

    def __init__(self, edges: Iterable[TemporalEdge | dict[str, Any]] = ()) -> None:
        self.edges: list[TemporalEdge] = [self._coerce(edge) for edge in edges]

    # ------------------------------------------------------------------ loading

    def add(self, edge: TemporalEdge | dict[str, Any]) -> None:
        """Add one historical relationship."""
        self.edges.append(self._coerce(edge))

    def extend(self, edges: Iterable[TemporalEdge | dict[str, Any]]) -> None:
        """Add many relationships."""
        for edge in edges:
            self.add(edge)

    @classmethod
    def from_rows(cls, rows: Iterable[dict[str, Any]]) -> "TemporalGraph":
        """Build from database rows produced by :mod:`dnscope.storage`."""
        return cls(rows)

    # ------------------------------------------------------------------ queries

    def as_of(self, moment: str | datetime | None = None) -> Graph:
        """Graph containing only relationships valid at ``moment``."""
        when = parse_timestamp(moment) if isinstance(moment, str) else (moment or now_utc())
        if when is None:
            raise ValueError(f"invalid timestamp: {moment!r}")
        graph = Graph()
        for edge in self.edges:
            if not self._valid(edge, when):
                continue
            graph.add_node(
                edge.source,
                edge.source_kind or "DOMAIN",
                label=edge.source,
                observed_at=edge.first_seen or when,
            )
            graph.add_node(
                edge.target,
                edge.target_kind or "DOMAIN",
                label=edge.target,
                observed_at=edge.first_seen or when,
            )
            graph.add_edge(
                edge.source,
                edge.relation,
                edge.target,
                attributes=edge.attributes,
                observed_at=edge.first_seen or when,
            )
        # Re-stamp ``last_seen`` so the window reflects the query time.
        for node in graph.nodes.values():
            node.touch(when)
        return graph

    def metrics_at(self, moment: str | datetime | None = None) -> GraphMetrics:
        """Analytics for the graph at ``moment``."""
        return GraphAnalytics(self.as_of(moment)).analyze()

    def diff(
        self,
        before: str | datetime,
        after: str | datetime,
    ) -> dict[str, Any]:
        """Relationships added/removed between two points in time."""
        previous = self.as_of(before)
        current = self.as_of(after)
        before_ids = {edge.identity for edge in previous.edges}
        after_ids = {edge.identity for edge in current.edges}
        added = sorted(after_ids - before_ids)
        removed = sorted(before_ids - after_ids)
        return {
            "before": {
                "timestamp": _iso(before),
                "nodes": len(previous.nodes),
                "edges": len(previous.edges),
            },
            "after": {
                "timestamp": _iso(after),
                "nodes": len(current.nodes),
                "edges": len(current.edges),
            },
            "added": added,
            "removed": removed,
            "unchanged": sorted(before_ids & after_ids),
        }

    def timeline(self, node_id: str | None = None) -> list[dict[str, Any]]:
        """Chronological list of relationship changes."""
        events: list[dict[str, Any]] = []
        for edge in self.edges:
            if node_id and node_id.lower() not in (edge.source.lower(), edge.target.lower()):
                continue
            events.append(
                {
                    "timestamp": (edge.first_seen or now_utc()).isoformat(),
                    "event": "relationship_observed",
                    "detail": f"{edge.source} -{edge.relation}-> {edge.target}",
                    "first_seen": edge.first_seen.isoformat() if edge.first_seen else "",
                    "last_seen": edge.last_seen.isoformat() if edge.last_seen else "",
                }
            )
        events.sort(key=lambda item: item["timestamp"])
        return events

    def coverage(self) -> dict[str, Any]:
        """Time range covered by the stored observations."""
        starts = [edge.first_seen for edge in self.edges if edge.first_seen]
        ends = [edge.last_seen for edge in self.edges if edge.last_seen]
        return {
            "edges": len(self.edges),
            "earliest": min(starts).isoformat() if starts else "",
            "latest": max(ends).isoformat() if ends else "",
        }

    # ---------------------------------------------------------------- internals

    def _valid(self, edge: TemporalEdge, when: datetime) -> bool:
        """Return ``True`` when the observation window covers ``when``."""
        if edge.first_seen and when < edge.first_seen:
            return False
        if edge.last_seen and when > edge.last_seen:
            return False
        return True

    def _coerce(self, edge: TemporalEdge | dict[str, Any]) -> TemporalEdge:
        """Accept either a model instance or a mapping."""
        if isinstance(edge, TemporalEdge):
            return edge
        data = dict(edge or {})
        return TemporalEdge.model_validate(data)


def _iso(value: str | datetime) -> str:
    """Normalize a timestamp to ISO-8601 text."""
    moment = parse_timestamp(value) if isinstance(value, str) else value
    return moment.isoformat() if moment else str(value)


__all__ = ["TemporalEdge", "TemporalGraph"]

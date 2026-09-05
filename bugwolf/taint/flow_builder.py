"""Taint flow graph — pure-data structure holding ``TaintFlow`` objects.

A flow graph groups flows by ``(file, line)`` so callers can ask
``flows_at(node_id)`` for everything that terminates at a given AST node.
This is the data-structure backbone used by :class:`VulnerabilityDetector`
and :class:`TaintReport`.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint flow builder (Phase 3.2)
## License: bugwolf-MIT

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from bugwolf.taint import TaintFlow, TaintSink, TaintSource


SCHEMA = "bugwolf-taint-v1"


@dataclass
class TaintFlowGraph:
    """Mutable graph of flows keyed by ``file:line``."""

    flows: List[TaintFlow] = field(default_factory=list)
    _by_node: Dict[str, List[TaintFlow]] = field(default_factory=dict)

    def add_flow(self, flow: TaintFlow) -> None:
        """Append ``flow`` and index it by ``file:line``."""

        self.flows.append(flow)
        node_id = self._node_id(flow.file, flow.line)
        self._by_node.setdefault(node_id, []).append(flow)

    def flows_at(self, node_id: str) -> List[TaintFlow]:
        """Return flows terminating at ``file:line``."""

        return list(self._by_node.get(node_id, []))

    def flows_for_file(self, filepath: str) -> List[TaintFlow]:
        """Return every flow that originates from ``filepath``."""

        return [f for f in self.flows if f.file == filepath]

    def vulnerable_flows(self) -> List[TaintFlow]:
        """Return only the flows marked as still vulnerable."""

        return [f for f in self.flows if f.is_vulnerable]

    def serialize(self) -> Dict[str, object]:
        """Return a JSON-able snapshot of the graph."""

        nodes: Dict[str, List[Dict[str, object]]] = {}
        for node_id, flows in self._by_node.items():
            nodes[node_id] = [f.to_dict() for f in flows]
        return {
            "schema": SCHEMA,
            "flow_count": len(self.flows),
            "vulnerable_count": sum(1 for f in self.flows if f.is_vulnerable),
            "node_count": len(self._by_node),
            "flows": [f.to_dict() for f in self.flows],
            "nodes": nodes,
        }

    @staticmethod
    def _node_id(filepath: str, line: int) -> str:
        return f"{filepath}:{int(line)}"

    def __len__(self) -> int:
        return len(self.flows)

    def __iter__(self):
        return iter(self.flows)


__all__ = ["TaintFlowGraph"]


def merge_flows(graphs: List[TaintFlowGraph]) -> TaintFlowGraph:
    """Merge a list of graphs into a single new graph."""

    out = TaintFlowGraph()
    for g in graphs:
        for f in g.flows:
            out.add_flow(f)
    return out


def top_sources(graph: TaintFlowGraph, limit: int = 10) -> List[Tuple[str, int]]:
    """Return the top-``limit`` sources by frequency."""

    counts: Dict[str, int] = {}
    for flow in graph.flows:
        counts[flow.source.value] = counts.get(flow.source.value, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return ranked[:limit]


def top_sinks(graph: TaintFlowGraph, limit: int = 10) -> List[Tuple[str, int]]:
    """Return the top-``limit`` sinks by frequency."""

    counts: Dict[str, int] = {}
    for flow in graph.flows:
        counts[flow.sink.value] = counts.get(flow.sink.value, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return ranked[:limit]


def by_file(graph: TaintFlowGraph) -> Dict[str, List[TaintFlow]]:
    """Group flows by their source file."""

    out: Dict[str, List[TaintFlow]] = {}
    for flow in graph.flows:
        out.setdefault(flow.file, []).append(flow)
    return out


def filter_by(graph: TaintFlowGraph, *, severity: Optional[str] = None,
              vulnerable_only: bool = False,
              source: Optional[TaintSource] = None,
              sink: Optional[TaintSink] = None) -> List[TaintFlow]:
    """Filter ``graph.flows`` by the supplied predicates."""

    out: List[TaintFlow] = []
    for flow in graph.flows:
        if vulnerable_only and not flow.is_vulnerable:
            continue
        if severity is not None and flow.severity != severity:
            continue
        if source is not None and flow.source != source:
            continue
        if sink is not None and flow.sink != sink:
            continue
        out.append(flow)
    return out


def shortest_path(graph: TaintFlowGraph) -> Optional[TaintFlow]:
    """Return the flow with the shortest propagation path."""

    if not graph.flows:
        return None
    return min(graph.flows, key=lambda f: len(f.path))


def longest_path(graph: TaintFlowGraph) -> Optional[TaintFlow]:
    """Return the flow with the longest propagation path."""

    if not graph.flows:
        return None
    return max(graph.flows, key=lambda f: len(f.path))


def confidence_histogram(graph: TaintFlowGraph, buckets: int = 5) -> List[int]:
    """Bucket every flow's confidence into ``buckets`` bins."""

    counts = [0] * max(1, int(buckets))
    for flow in graph.flows:
        idx = min(len(counts) - 1, int(flow.confidence * len(counts)))
        counts[idx] += 1
    return counts


def deduplicate(graph: TaintFlowGraph) -> TaintFlowGraph:
    """Return a new graph with duplicate flows removed."""

    seen: Set[Tuple[TaintSource, TaintSink, str, int]] = set()
    out = TaintFlowGraph()
    for flow in graph.flows:
        key = (flow.source, flow.sink, flow.file, flow.line)
        if key in seen:
            continue
        seen.add(key)
        out.add_flow(flow)
    return out


def diff(a: TaintFlowGraph, b: TaintFlowGraph) -> List[TaintFlow]:
    """Return flows present in ``a`` but not in ``b``."""

    keys_b = {(f.source, f.sink, f.file, f.line) for f in b.flows}
    return [f for f in a.flows if (f.source, f.sink, f.file, f.line) not in keys_b]


def intersect(a: TaintFlowGraph, b: TaintFlowGraph) -> List[TaintFlow]:
    """Return flows present in both ``a`` and ``b``."""

    keys_b = {(f.source, f.sink, f.file, f.line) for f in b.flows}
    return [f for f in a.flows if (f.source, f.sink, f.file, f.line) in keys_b]


def sanitized_count(graph: TaintFlowGraph) -> int:
    """Return the count of flows that have at least one sanitizer recorded."""

    return sum(1 for f in graph.flows if f.sanitizers)


__all__.extend([
    "top_sinks",
    "by_file",
    "filter_by",
    "shortest_path",
    "longest_path",
    "confidence_histogram",
    "deduplicate",
    "diff",
    "intersect",
    "sanitized_count",
])

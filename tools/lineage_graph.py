#!/usr/bin/env python3
"""End-to-end evidence lineage graph (document -> action -> transaction)."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.reliability import append_jsonl, read_jsonl

KINDS = {"input", "mutation", "request", "transaction", "tool_call", "response",
         "state_snapshot", "document", "candidate"}


@dataclass
class LineageNode:
    id: str
    kind: str
    data: Dict[str, Any] = field(default_factory=dict)
    parent_ids: List[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown lineage kind: {self.kind}")
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LineageGraph:
    """Append-only, cycle-free local evidence graph."""

    def __init__(self, target: str, *, max_nodes: int = 100_000):
        self.target = str(target)
        self.max_nodes = max_nodes
        self._nodes: Dict[str, LineageNode] = {}
        self._children: Dict[str, List[str]] = {}

    def add(self, kind: str, data: Dict[str, Any], *, parent: Optional[str] = None,
            children: Optional[Iterable[str]] = None) -> LineageNode:
        if parent is not None and parent not in self._nodes:
            raise ValueError(f"unknown parent node: {parent}")
        if len(self._nodes) >= self.max_nodes:
            raise ValueError("lineage graph node limit reached")
        children = list(children or [])
        for child in children:
            if child not in self._nodes:
                raise ValueError(f"unknown child node: {child}")
            if self._would_cycle(parent, child):
                raise ValueError("lineage graph cycle detected")
        node = LineageNode(id="", kind=kind, data=dict(data or {}),
                           parent_ids=[parent] if parent else [])
        self._nodes[node.id] = node
        if parent:
            self._children.setdefault(parent, []).append(node.id)
        for child in children:
            node.parent_ids.append(child)
            self._children.setdefault(node.id, []).append(child)
        return node

    def _would_cycle(self, parent: Optional[str], child: str) -> bool:
        """True if adding parent -> child would create a cycle."""
        if parent is None:
            return False
        frontier = [parent]
        seen = set()
        while frontier:
            node = frontier.pop()
            if node == child:
                return True
            if node in seen:
                continue
            seen.add(node)
            frontier.extend(self._children.get(node, []))
        return False

    def path(self, start: str, end: str) -> List[LineageNode]:
        """Return a deterministic shortest path between two nodes."""
        if start not in self._nodes or end not in self._nodes:
            raise KeyError("unknown node in path request")
        from collections import deque
        queue = deque([start])
        previous = {start: None}
        while queue:
            node = queue.popleft()
            if node == end:
                break
            for neighbor in self._children.get(node, []):
                if neighbor not in previous:
                    previous[neighbor] = node
                    queue.append(neighbor)
        if end not in previous:
            return []
        path = []
        cursor = end
        while cursor is not None:
            path.append(self._nodes[cursor])
            cursor = previous[cursor]
        return list(reversed(path))

    def export(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        for node in self._nodes.values():
            append_jsonl(destination, node.to_dict())
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "LineageGraph":
        graph = cls("loaded")
        records, _ = read_jsonl(path)
        for record in records:
            node = LineageNode(**record)
            graph._nodes[node.id] = node
            for parent in node.parent_ids:
                graph._children.setdefault(parent, []).append(node.id)
        return graph
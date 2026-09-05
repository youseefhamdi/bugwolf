#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter agent.py:426-510 (1.5.a)
## Source: Agentic-Bug-Hunter agent.py:1013-1042
## Source: Agentic-Bug-Hunter agent.py:1305-1316
## License: MIT (sister project)
## Port: 2026-09-05

ReAct 3-layer memory (working / episodic / semantic).

The ReAct paper proposes a Thought -> Action -> Observation loop.  The
Agentic-Bug-Hunter project extends this with three persistent memory
layers so an agent can reason across sessions:

  * working   — ephemeral, tied to the current step
  * episodic  — chronological log of past observations
  * semantic  — distilled, reusable knowledge (definitions, fingerprints)

This module is a pure-Python re-implementation: no external services, no
network calls.  It is the abstract memory contract used by the cross-
project port; concrete persistence backends (sqlite, jsonl, redis) are
pluggable via :class:`MemoryStore` (default = in-memory dict).
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "bugwolf-react-memory/v1"


# ---------------------------------------------------------------------------
# Layer enum
# ---------------------------------------------------------------------------

class MemoryLayer(str, Enum):
    """The three ReAct memory layers."""

    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MemoryRecord:
    """A single memory record.

    ``content`` is the human-readable form (str) or structured dict.  The
    ``layer`` determines retention semantics: working is dropped at the
    end of a step, episodic is append-only chronological, semantic is
    deduped and merged by ``key``.
    """

    layer: MemoryLayer
    key: str
    content: Any
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    step_id: str = ""
    importance: float = 1.0  # 0..1, used for eviction
    evidence_sha256: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_sha256 and isinstance(self.content, (str, bytes)):
            blob = self.content if isinstance(self.content, bytes) \
                else self.content.encode("utf-8")
            object.__setattr__(
                self,
                "evidence_sha256",
                hashlib.sha256(blob).hexdigest(),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "key": self.key,
            "content": self.content,
            "timestamp_ms": self.timestamp_ms,
            "step_id": self.step_id,
            "importance": self.importance,
            "evidence_sha256": self.evidence_sha256,
        }


# ---------------------------------------------------------------------------
# Store (default = in-memory dict)
# ---------------------------------------------------------------------------

class MemoryStore:
    """Pluggable persistence layer.

    Default backend is a plain dict — fine for single-process use.  The
    interface is small (get / put / iter) so swapping for sqlite/jsonl is
    trivial.
    """

    def __init__(self) -> None:
        self._data: Dict[Tuple[MemoryLayer, str], MemoryRecord] = {}

    def put(self, record: MemoryRecord) -> None:
        if record.layer is MemoryLayer.SEMANTIC:
            existing = self._data.get((record.layer, record.key))
            if existing is not None:
                merged_content = self._merge_semantic(existing.content, record.content)
                object.__setattr__(record, "content", merged_content)
                object.__setattr__(
                    record, "importance",
                    min(1.0, max(existing.importance, record.importance)),
                )
        self._data[(record.layer, record.key)] = record

    def get(self, layer: MemoryLayer, key: str) -> Optional[MemoryRecord]:
        return self._data.get((layer, key))

    def iter(self, layer: MemoryLayer) -> Iterable[MemoryRecord]:
        for (l, _), rec in self._data.items():
            if l == layer:
                yield rec

    def clear(self, layer: Optional[MemoryLayer] = None) -> int:
        if layer is None:
            n = len(self._data)
            self._data.clear()
            return n
        keys = [k for k in self._data if k[0] == layer]
        for k in keys:
            del self._data[k]
        return len(keys)

    @staticmethod
    def _merge_semantic(a: Any, b: Any) -> Any:
        if isinstance(a, dict) and isinstance(b, dict):
            merged = dict(a)
            for k, v in b.items():
                if k in merged and merged[k] != v:
                    merged[k] = [merged[k], v]
                else:
                    merged[k] = v
            return merged
        if isinstance(a, list) and isinstance(b, list):
            return list(a) + [x for x in b if x not in a]
        if a == b:
            return a
        return [a, b]


# ---------------------------------------------------------------------------
# ReAct memory
# ---------------------------------------------------------------------------

@dataclass
class StepContext:
    """A single ReAct step's working-memory context."""

    step_id: str
    thought: str
    action: str
    observation: str
    started_at_ms: int


class ReActMemory:
    """3-layer memory manager for one ReAct loop.

    Public API:
      * :meth:`begin_step`       — create a working-memory slot
      * :meth:`record_observation` — append an episodic record
      * :meth:`record_semantic`   — upsert a semantic record
      * :meth:`recall_semantic`   — look up by key
      * :meth:`recent_episodes`   — tail of the episodic log
      * :meth:`end_step`         — drop the working slot
      * :meth:`snapshot`         — full dict for checkpointing
      * :meth:`restore`          — load from a snapshot
    """

    def __init__(self, store: Optional[MemoryStore] = None) -> None:
        self._store = store or MemoryStore()
        self._working: Dict[str, StepContext] = {}

    # -- working layer -------------------------------------------------------

    def begin_step(self, step_id: str, *, thought: str = "",
                   action: str = "") -> StepContext:
        ctx = StepContext(
            step_id=step_id,
            thought=thought,
            action=action,
            observation="",
            started_at_ms=int(time.time() * 1000),
        )
        self._working[step_id] = ctx
        return ctx

    def end_step(self, step_id: str) -> None:
        self._working.pop(step_id, None)

    def working(self, step_id: str) -> Optional[StepContext]:
        return self._working.get(step_id)

    # -- episodic layer ------------------------------------------------------

    def record_observation(self, step_id: str, key: str, observation: Any,
                           *, importance: float = 0.5) -> MemoryRecord:
        rec = MemoryRecord(
            layer=MemoryLayer.EPISODIC,
            key=f"{step_id}::{key}",
            content=observation,
            step_id=step_id,
            importance=max(0.0, min(1.0, importance)),
        )
        self._store.put(rec)
        ctx = self._working.get(step_id)
        if ctx is not None:
            object.__setattr__(ctx, "observation",
                               str(observation)[:1024])
        return rec

    def recent_episodes(self, *, limit: int = 10) -> List[MemoryRecord]:
        rows = list(self._store.iter(MemoryLayer.EPISODIC))
        rows.sort(key=lambda r: r.timestamp_ms, reverse=True)
        return rows[:limit]

    # -- semantic layer ------------------------------------------------------

    def record_semantic(self, key: str, content: Any, *,
                        importance: float = 1.0) -> MemoryRecord:
        rec = MemoryRecord(
            layer=MemoryLayer.SEMANTIC,
            key=key,
            content=content,
            importance=max(0.0, min(1.0, importance)),
        )
        self._store.put(rec)
        return rec

    def recall_semantic(self, key: str) -> Optional[MemoryRecord]:
        return self._store.get(MemoryLayer.SEMANTIC, key)

    # -- introspection / persistence ----------------------------------------

    def semantic_keys(self) -> List[str]:
        return sorted(r.key for r in self._store.iter(MemoryLayer.SEMANTIC))

    def episodic_count(self) -> int:
        return sum(1 for _ in self._store.iter(MemoryLayer.EPISODIC))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "semantic": [r.to_dict() for r in self._store.iter(MemoryLayer.SEMANTIC)],
            "episodic": [r.to_dict() for r in self._store.iter(MemoryLayer.EPISODIC)],
            "working": {
                sid: ctx.__dict__ for sid, ctx in self._working.items()
            },
        }

    def restore(self, snap: Mapping[str, Any]) -> None:
        if snap.get("schema") != SCHEMA:
            raise ValueError(f"unknown snapshot schema {snap.get('schema')!r}")
        self._store.clear()
        for d in snap.get("semantic") or []:
            self._store.put(MemoryRecord(
                layer=MemoryLayer.SEMANTIC,
                key=str(d["key"]),
                content=d["content"],
                timestamp_ms=int(d.get("timestamp_ms") or 0),
                step_id=str(d.get("step_id") or ""),
                importance=float(d.get("importance") or 1.0),
                evidence_sha256=str(d.get("evidence_sha256") or ""),
            ))
        for d in snap.get("episodic") or []:
            self._store.put(MemoryRecord(
                layer=MemoryLayer.EPISODIC,
                key=str(d["key"]),
                content=d["content"],
                timestamp_ms=int(d.get("timestamp_ms") or 0),
                step_id=str(d.get("step_id") or ""),
                importance=float(d.get("importance") or 0.5),
                evidence_sha256=str(d.get("evidence_sha256") or ""),
            ))


__all__ = [
    "SCHEMA", "MemoryLayer", "MemoryRecord", "MemoryStore",
    "StepContext", "ReActMemory",
]
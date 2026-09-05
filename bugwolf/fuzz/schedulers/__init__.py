## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Power-schedule scheduler implementations for coverage-guided fuzzing.

Three schedulers are exposed:

  * :class:`AFLFastScheduler` — AFL's fast power schedule (rare-edge
    preference with energy formula)
  * :class:`ExploreScheduler` — uniform random
  * :class:`COEScheduler`      — cut-off edge (COE) schedule

Each scheduler exposes ``select_next`` which returns one byte sample
from a queue.  Schedulers never raise; on an empty queue they
return ``b""``.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fuzz-scheduler-v1"


@dataclass
class AFLFastScheduler:
    """AFL fast power schedule.

    The scheduler prefers rare edges and high-frequency paths.  Each
    queue entry's "energy" is computed from its assigned edges; rare
    edges get a higher weight.  Selection is a weighted random draw.
    """

    name: str = "afl_fast"
    energy_exponent: float = 1.0
    rarity_boost: float = 2.0
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        self._rng = random.Random(0xA5A5)

    def select_next(
        self,
        queue: Sequence[bytes],
        *,
        edges_per_input: Optional[Sequence[Iterable[int]]] = None,
    ) -> bytes:
        """Return one queue entry selected by the power schedule.

        ``edges_per_input`` optionally maps each queue entry to the
        edges it covers.  When omitted, uniform random is used.
        """
        try:
            if not queue:
                return b""
            if edges_per_input is None or len(edges_per_input) != len(queue):
                return self._rng.choice(list(queue))
            weights = self._weights(edges_per_input)
            return self._weighted_choice(list(queue), weights)
        except Exception:
            try:
                return self._rng.choice(list(queue))
            except Exception:
                return b""

    # ------------------------------------------------------------ internals

    def _weights(self, edges_per_input: Sequence[Iterable[int]]) -> List[float]:
        edge_counts: dict = {}
        for edges in edges_per_input:
            for e in edges:
                try:
                    key = int(e) & 0xFFFFFFFF
                except Exception:
                    continue
                edge_counts[key] = edge_counts.get(key, 0) + 1
        weights: List[float] = []
        for edges in edges_per_input:
            try:
                novelty = sum(
                    self.rarity_boost / (1.0 + edge_counts.get(int(e) & 0xFFFFFFFF, 1))
                    for e in edges
                )
            except Exception:
                novelty = 1.0
            path_freq = max(1, len(list(edges)))
            weight = (1.0 + novelty) * (path_freq ** self.energy_exponent)
            weights.append(max(0.0001, weight))
        return weights

    def _weighted_choice(self, queue: Sequence[bytes], weights: Sequence[float]) -> bytes:
        total = sum(weights)
        if total <= 0:
            return self._rng.choice(list(queue))
        pick = self._rng.random() * total
        acc = 0.0
        for item, w in zip(queue, weights):
            acc += w
            if acc >= pick:
                return item
        return queue[-1]


@dataclass
class ExploreScheduler:
    """Uniform random scheduler."""

    name: str = "explore"
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        self._rng = random.Random(0xE1E1)

    def select_next(self, queue: Sequence[bytes], **_: object) -> bytes:
        try:
            if not queue:
                return b""
            return self._rng.choice(list(queue))
        except Exception:
            return b""


@dataclass
class COEScheduler:
    """Cut-off edge scheduler.

    COE schedules prefer inputs that cover the most recently
    discovered edges.  When no edge history is supplied the
    scheduler degrades to uniform random (the same fallback as
    :class:`ExploreScheduler`).
    """

    name: str = "coe"
    recency_window: int = 1024
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        self._rng = random.Random(0xC0E0)

    def select_next(
        self,
        queue: Sequence[bytes],
        *,
        edges_per_input: Optional[Sequence[Iterable[int]]] = None,
        recent_edges: Optional[Iterable[int]] = None,
    ) -> bytes:
        try:
            if not queue:
                return b""
            if edges_per_input is None or recent_edges is None:
                return self._rng.choice(list(queue))
            recent = set(int(e) & 0xFFFFFFFF for e in recent_edges)
            scored: List[Tuple[int, bytes]] = []
            for sample, edges in zip(queue, edges_per_input):
                try:
                    score = sum(1 for e in edges if (int(e) & 0xFFFFFFFF) in recent)
                except Exception:
                    score = 0
                scored.append((score, sample))
            scored.sort(key=lambda kv: kv[0], reverse=True)
            best = scored[0][0]
            top = [s for s in scored if s[0] == best]
            return self._rng.choice([t[1] for t in top])
        except Exception:
            try:
                return self._rng.choice(list(queue))
            except Exception:
                return b""


__all__ = [
    "AFLFastScheduler",
    "ExploreScheduler",
    "COEScheduler",
]

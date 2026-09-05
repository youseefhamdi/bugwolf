## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL bitmap concept (https://github.com/AFLplusplus/AFLplusplus)
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""In-memory coverage tracker for the BugWolf fuzzing substrate.

:class:`CoverageTracker` records the set of coverage edges observed
during fuzzing, supports merging from child trackers, and exposes a
simple score useful for ranking schedulers.

The tracker is purely in-process; no I/O is performed and no
dependencies are required.  All methods are stub-safe.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set


SCHEMA = "bugwolf-fuzz-coverage-v1"


@dataclass
class CoverageTracker:
    """In-memory coverage bitmap.

    Parameters
    ----------
    capacity:
        Soft cap on the number of distinct edges recorded.  When
        exceeded, the tracker keeps the first ``capacity`` edges
        observed and ignores further additions — this avoids unbounded
        memory growth during long campaigns.
    """

    capacity: int = 65536
    _edges: Set[int] = field(default_factory=set)
    _total_observations: int = 0

    # ----------------------------------------------------------------- API

    def record(self, edges: Iterable[int]) -> int:
        """Add ``edges`` to the bitmap.

        Returns the number of *new* edges added.
        """
        try:
            added = 0
            for e in edges:
                self._total_observations += 1
                if len(self._edges) >= self.capacity:
                    break
                try:
                    key = int(e) & 0xFFFFFFFF
                except Exception:
                    continue
                if key not in self._edges:
                    self._edges.add(key)
                    added += 1
            return added
        except Exception:
            return 0

    def merge(self, other: "CoverageTracker") -> int:
        """Merge ``other``'s edges into this tracker.

        Returns the number of newly added edges.
        """
        try:
            return self.record(other._edges)
        except Exception:
            return 0

    def score(self) -> float:
        """Return a coverage score in ``[0, 1]``.

        The score is ``len(_edges) / capacity`` clamped to ``[0, 1]``.
        """
        try:
            if self.capacity <= 0:
                return 0.0
            return min(1.0, len(self._edges) / float(self.capacity))
        except Exception:
            return 0.0

    @property
    def edges(self) -> Set[int]:
        """Return a copy of the recorded edge set."""
        try:
            return set(self._edges)
        except Exception:
            return set()

    def __len__(self) -> int:
        return len(self._edges)

    def __contains__(self, edge: int) -> bool:
        try:
            return int(edge) in self._edges
        except Exception:
            return False

    def reset(self) -> None:
        """Clear the bitmap."""
        self._edges.clear()
        self._total_observations = 0

    # ----------------------------------------------------------------- repr

    def __repr__(self) -> str:
        return (
            f"CoverageTracker(edges={len(self._edges)}, "
            f"capacity={self.capacity}, "
            f"observations={self._total_observations})"
        )


__all__ = ["CoverageTracker"]

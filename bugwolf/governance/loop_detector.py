"""Loop detector (Phase 1.4 — Governance Core).

A thread-safe sliding-window loop detector for action ids.

``record(action_id)`` returns True when ``action_id`` has appeared at
least ``max_repeats`` times within the previous ``window_seconds`` of
the most recent occurrence.  ``max_repeats`` defaults to 3, the
audit-cited threshold above which the runner is presumed to be in a
detection loop.

The detector also tracks a TOTAL counter per action id; callers can
inspect :meth:`total` to detect slow-burn loops that exceed the
sliding window but should still halt the runner.

No external deps; stdlib only.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"


class LoopDetector:
    """Thread-safe sliding-window loop detector."""

    schema = _SCHEMA

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        max_repeats: int = 3,
        clock: Optional["callable"] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_repeats <= 0:
            raise ValueError("max_repeats must be > 0")
        self._window = float(window_seconds)
        self._max_repeats = int(max_repeats)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._history: Dict[str, Deque[float]] = defaultdict(deque)
        self._totals: Dict[str, int] = defaultdict(int)

    # -- public API ---------------------------------------------------------

    def record(self, action_id: str) -> bool:
        """Record ``action_id``.  True iff this call trips the threshold."""
        with self._lock:
            now = self._clock()
            window = self._history[action_id]
            window.append(now)
            self._totals[action_id] += 1
            cutoff = now - self._window
            while window and window[0] < cutoff:
                window.popleft()
            return len(window) >= self._max_repeats

    def total(self, action_id: str) -> int:
        """Lifetime total of ``action_id`` (debug / slow-burn detection)."""
        with self._lock:
            return self._totals.get(action_id, 0)

    def window_count(self, action_id: str) -> int:
        """Number of occurrences of ``action_id`` in the current window."""
        with self._lock:
            now = self._clock()
            window = self._history.get(action_id)
            if not window:
                return 0
            cutoff = now - self._window
            while window and window[0] < cutoff:
                window.popleft()
            return len(window)

    def reset(self) -> None:
        """Clear all history (test escape hatch)."""
        with self._lock:
            self._history.clear()
            self._totals.clear()


__all__ = ["SCHEMA", "LoopDetector"]
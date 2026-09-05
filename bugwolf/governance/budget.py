"""Budget guard (Phase 1.4 — Governance Core).

Two-axis budget guard for mission runs:

  * ``max_steps`` — total number of ``consume()`` calls allowed
  * ``max_wall_clock`` — total wall-clock seconds since construction
  * ``min_steps`` — minimum number of steps that must be observed before
    a report can be emitted (the audit-cited ``min-steps floor``).

Both axes are fail-CLOSED: when exhausted, :meth:`BudgetGuard.consume`
returns False and the caller MUST stop dispatching work.  :meth:`reached_min_steps`
returns True only once enough steps have been observed.

No external deps; stdlib only.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"


@dataclass
class BudgetSnapshot:
    """A read-only snapshot of the budget's current state."""

    steps_consumed: int
    max_steps: int
    elapsed_seconds: float
    max_wall_clock: int
    min_steps: int


class BudgetGuard:
    """Fail-closed two-axis budget guard."""

    schema = _SCHEMA

    def __init__(
        self,
        *,
        max_steps: int = 200,
        max_wall_clock: int = 3600,
        min_steps: int = 3,
        clock: Optional["callable"] = None,
    ) -> None:
        if max_steps <= 0:
            raise ValueError("max_steps must be > 0")
        if max_wall_clock <= 0:
            raise ValueError("max_wall_clock must be > 0")
        if min_steps < 0:
            raise ValueError("min_steps must be >= 0")
        self._max_steps = int(max_steps)
        self._max_wall_clock = int(max_wall_clock)
        self._min_steps = int(min_steps)
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self._steps = 0
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    @property
    def max_steps(self) -> int:
        return self._max_steps

    @property
    def max_wall_clock(self) -> int:
        return self._max_wall_clock

    @property
    def min_steps(self) -> int:
        return self._min_steps

    def consume(self) -> bool:
        """Record one step.  Returns False when the budget is exhausted.

        Once exhausted, additional calls also return False until :meth:`reset`
        is invoked (useful in tests and operator-driven replays).
        """
        with self._lock:
            if self._exhausted_locked():
                return False
            self._steps += 1
            return True

    def reached_min_steps(self) -> bool:
        """True iff at least ``min_steps`` have been consumed."""
        with self._lock:
            return self._steps >= self._min_steps

    def exhausted(self) -> bool:
        """True iff either axis has run out."""
        with self._lock:
            return self._exhausted_locked()

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                steps_consumed=self._steps,
                max_steps=self._max_steps,
                elapsed_seconds=self._elapsed_locked(),
                max_wall_clock=self._max_wall_clock,
                min_steps=self._min_steps,
            )

    def reset(self) -> None:
        """Reset counters (test/operator escape hatch)."""
        with self._lock:
            self._steps = 0
            self._start = self._clock()

    # -- internals ----------------------------------------------------------

    def _exhausted_locked(self) -> bool:
        return (
            self._steps >= self._max_steps
            or self._elapsed_locked() >= self._max_wall_clock
        )

    def _elapsed_locked(self) -> float:
        return self._clock() - self._start


__all__ = ["SCHEMA", "BudgetGuard", "BudgetSnapshot"]
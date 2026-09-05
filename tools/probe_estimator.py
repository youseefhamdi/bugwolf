#!/usr/bin/env python3
"""
## Source: bugwolf readiness plan R2 -- pre-run request-count estimation
## Source: zero_fours zero_fours.py -- burst sizing heuristic
## License: bugwolf-internal + MIT (zero_fours)
## Port: 2026-09-05

Pre-run request-count estimator + budget gate.

The estimator walks a target spec + a list of scanners and returns the
total number of HTTP probes the run will issue. The gate
(:meth:`blocks_if_exceeds`) returns True if that count exceeds an
operator-set budget, so the orchestrator can refuse to start a run that
would burn the engagement budget.

The math is intentionally *linear*: each scanner advertises an
``estimate_per_target`` int (number of probes it issues per target),
and the estimator sums ``scanners * targets * multiplier``. The
``deadline`` helper computes a wall-clock budget from a target rate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional


@dataclass
class Scanner:
    """Minimal scanner descriptor consumed by :class:`ProbeEstimator`.

    ``estimate_per_target`` is the number of HTTP probes the scanner
    emits for one target. ``name`` is human-readable (for the report).
    """

    name: str
    estimate_per_target: int = 0
    metadata: dict = field(default_factory=dict)


class ProbeEstimator:
    """Pre-run request-count estimator + budget gate."""

    DEFAULT_RATE: int = 10        # requests per second
    DEFAULT_BUDGET: int = 50_000   # requests per mission

    def __init__(self, *, rate: int = DEFAULT_RATE):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate

    # -- estimation ----------------------------------------------------------

    def estimate(self, target: dict, *, scanners: List[Scanner]) -> int:
        """Estimate total request count for one target + scanner list.

        ``target`` is a dict (we do NOT inspect shape -- callers pass
        the mission target dict). The estimator scales each scanner by
        ``len(target_hosts)`` if the dict carries a ``hosts`` list,
        else by 1.
        """
        if not isinstance(target, dict):
            raise TypeError("target must be a dict")
        if not isinstance(scanners, (list, tuple)):
            raise TypeError("scanners must be a list/tuple")

        hosts = target.get("hosts") if isinstance(target, dict) else None
        n_hosts = len(hosts) if isinstance(hosts, (list, tuple)) else 1

        total = 0
        for sc in scanners:
            try:
                n = int(sc.estimate_per_target)
            except (TypeError, ValueError):
                n = 0
            if n < 0:
                n = 0
            total += n * n_hosts
        return int(total)

    def estimate_scanners(self, scanners: Iterable[Scanner]) -> int:
        """Sum the per-target estimates of every scanner (no host mult)."""
        if not isinstance(scanners, (list, tuple)):
            raise TypeError("scanners must be a list/tuple")
        total = 0
        for sc in scanners:
            try:
                n = int(sc.estimate_per_target)
            except (TypeError, ValueError):
                n = 0
            if n < 0:
                n = 0
            total += n
        return int(total)

    # -- budget gate ---------------------------------------------------------

    def blocks_if_exceeds(self, target: int, max_requests: int = DEFAULT_BUDGET) -> bool:
        """Return True if ``target`` exceeds ``max_requests``.

        Negative or non-int inputs are clamped to 0 / False.
        """
        try:
            target = int(target)
            max_requests = int(max_requests)
        except (TypeError, ValueError):
            return False
        if max_requests < 0:
            max_requests = 0
        return target > max_requests

    # -- deadline ------------------------------------------------------------

    def deadline(self, requests: int, *, rate: Optional[int] = None) -> float:
        """Return wall-clock seconds for ``requests`` at ``rate`` per second.

        Negative inputs are clamped to 0.
        """
        try:
            requests = int(requests)
        except (TypeError, ValueError):
            requests = 0
        if requests < 0:
            requests = 0
        r = int(rate) if rate and rate > 0 else self._rate
        return float(requests) / float(r)

    def rate(self) -> int:
        return self._rate
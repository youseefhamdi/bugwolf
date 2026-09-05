#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter model_scorecard.py:1-680 (1.5.m)
## Source: pass@k benchmarking paper (sister project)
## License: MIT (sister projects)
## Port: 2026-09-05

Wilson-bounded miss-rate for LLM judges + budget enforcement.

LLM judges predict PASS/FAIL on findings.  Their miss-rate (the
probability they FAIL a real finding) is bounded by the Wilson score
interval.  :class:`ModelScorecard` tracks every prediction vs the
ground truth, and decides when the model has enough samples to be
considered "calibrated".

Public surface:
  * :meth:`update`           — record (predicted_pass, actual_pass)
  * :meth:`is_calibrated`    — returns True after ``min_samples`` updates
                                AND the upper Wilson bound is below
                                ``max_miss_rate``
  * :meth:`score`            — Wilson upper bound on miss-rate
  * :meth:`remaining_budget` — how many more judgements are allowed
  * :meth:`summary`          — flat dict for telemetry
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


SCHEMA = "bugwolf-model-scorecard/v1"


@dataclass
class ModelScorecard:
    """Wilson-bounded miss-rate tracker for an LLM judge.

    Parameters:
        min_samples       — minimum judgements before calibration
        max_miss_rate     — max acceptable Wilson upper bound
        budget_total      — total judgements allowed before quarantine
        z                 — z-score for the Wilson interval (default 1.96
                            for 95% confidence)
    """

    SCHEMA = SCHEMA

    name: str = "default"
    min_samples: int = 20
    max_miss_rate: float = 0.10
    budget_total: int = 1000
    z: float = 1.96

    _true_pos: int = field(default=0, init=False)
    _false_neg: int = field(default=0, init=False)
    _true_neg: int = field(default=0, init=False)
    _false_pos: int = field(default=0, init=False)
    _judgements_used: int = field(default=0, init=False)
    _created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000),
                                init=False)

    def update(self, predicted_pass: bool, actual_pass: bool) -> None:
        """Record one judgement pair."""
        self._judgements_used += 1
        if predicted_pass and actual_pass:
            self._true_pos += 1
        elif predicted_pass and not actual_pass:
            self._false_pos += 1
        elif (not predicted_pass) and actual_pass:
            self._false_neg += 1
        else:
            self._true_neg += 1

    @property
    def judgements_used(self) -> int:
        return int(self._judgements_used)

    def remaining_budget(self) -> int:
        return max(0, self.budget_total - self._judgements_used)

    def miss_rate(self) -> float:
        """Naive point estimate of miss-rate = FN / (FN + TP)."""
        denom = self._false_neg + self._true_pos
        if denom == 0:
            return 0.0
        return float(self._false_neg) / float(denom)

    def wilson_upper(self) -> float:
        """Upper bound of the Wilson score interval on miss-rate.

        Uses the standard Wilson formula on the miss-rate Bernoulli trial
        (FN successes out of FN + TP trials).
        """
        n = self._false_neg + self._true_pos
        if n == 0:
            return 1.0  # no data → assume worst case
        phat = float(self._false_neg) / float(n)
        z = float(self.z)
        denom = 1.0 + (z * z) / n
        centre = phat + (z * z) / (2 * n)
        half = z * math.sqrt((phat * (1 - phat) + (z * z) / (4 * n)) / n)
        return min(1.0, (centre + half) / denom)

    def score(self) -> float:
        """Alias for :meth:`wilson_upper` (matches the public spec)."""
        return self.wilson_upper()

    def is_calibrated(self) -> bool:
        """True when sample count is sufficient AND miss-rate is acceptable."""
        if self._judgements_used < self.min_samples:
            return False
        return self.wilson_upper() <= self.max_miss_rate

    def summary(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "judgements_used": self._judgements_used,
            "budget_remaining": self.remaining_budget(),
            "true_pos": self._true_pos,
            "false_pos": self._false_pos,
            "true_neg": self._true_neg,
            "false_neg": self._false_neg,
            "miss_rate": round(self.miss_rate(), 4),
            "wilson_upper": round(self.wilson_upper(), 4),
            "is_calibrated": bool(self.is_calibrated()),
            "max_miss_rate": float(self.max_miss_rate),
            "min_samples": int(self.min_samples),
        }


def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> tuple:
    """Stand-alone Wilson interval helper.

    Returns ``(lower, upper)``.  Both bounds are clamped to [0, 1].
    """
    if total <= 0:
        return (0.0, 1.0)
    phat = float(successes) / float(total)
    denom = 1.0 + (z * z) / total
    centre = phat + (z * z) / (2 * total)
    half = z * math.sqrt((phat * (1 - phat) + (z * z) / (4 * total)) / total)
    lo = max(0.0, (centre - half) / denom)
    hi = min(1.0, (centre + half) / denom)
    return (lo, hi)


__all__ = ["SCHEMA", "ModelScorecard", "wilson_score_interval"]
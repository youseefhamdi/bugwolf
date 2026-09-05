#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter santa_loop.py:1-260 (1.5.p)
## Source: Adversarial-Review /santa-loop (sister project)
## License: MIT (sister projects)
## Port: 2026-09-05

/santa-loop dual-review convergence.

The ``/santa-loop`` pattern is a dual-review convention: two independent
reviewers (A and B) examine a candidate finding.  If both agree the
finding is real, the loop closes with ACCEPTED.  If they diverge, the
loop returns NEEDS_HUMAN so a human reviewer can arbitrate.

The :func:`santa_loop` function is the convergence point.  It is pure:
no network IO, no subprocess — just two dataclasses in, one decision
out.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping


SCHEMA = "bugwolf-santa-loop/v1"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReviewVerdict(str, Enum):
    """Each reviewer's verdict."""

    REAL = "real"
    BENIGN = "benign"
    UNCERTAIN = "uncertain"


class Convergence(str, Enum):
    """The loop's outcome."""

    ACCEPTED = "accepted"
    NEEDS_HUMAN = "needs_human"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Review + result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Review:
    """One reviewer's output."""

    reviewer: str
    verdict: ReviewVerdict
    confidence: float = 0.5  # 0..1
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "reviewer": self.reviewer,
            "verdict": self.verdict.value,
            "confidence": float(self.confidence),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ConvergenceResult:
    """Outcome of :func:`santa_loop`."""

    convergence: Convergence
    review_a: Review
    review_b: Review
    reason: str = ""
    agreement_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "convergence": self.convergence.value,
            "review_a": self.review_a.to_dict(),
            "review_b": self.review_b.to_dict(),
            "reason": self.reason,
            "agreement_score": float(self.agreement_score),
        }


# ---------------------------------------------------------------------------
# Convergence rules
# ---------------------------------------------------------------------------

def _agreement_score(a: Review, b: Review) -> float:
    """Return a 0..1 score (1 = perfect agreement)."""
    same_verdict = (a.verdict == b.verdict)
    if not same_verdict:
        return 0.0
    # Same verdict — score is the min confidence (conservative).
    return float(min(a.confidence, b.confidence))


def santa_loop(review_a: Review, review_b: Review) -> ConvergenceResult:
    """Apply the dual-review convergence rule.

      * both REAL with high confidence -> ACCEPTED
      * both BENIGN with high confidence -> REJECTED
      * both UNCERTAIN -> NEEDS_HUMAN
      * mixed (one REAL, one BENIGN, etc.) -> NEEDS_HUMAN
    """
    score = _agreement_score(review_a, review_b)
    high_threshold = 0.7
    if review_a.verdict == review_b.verdict:
        verdict = review_a.verdict
        if verdict is ReviewVerdict.REAL and score >= high_threshold:
            return ConvergenceResult(
                Convergence.ACCEPTED, review_a, review_b,
                reason="both-real-high-confidence",
                agreement_score=score,
            )
        if verdict is ReviewVerdict.BENIGN and score >= high_threshold:
            return ConvergenceResult(
                Convergence.REJECTED, review_a, review_b,
                reason="both-benign-high-confidence",
                agreement_score=score,
            )
        return ConvergenceResult(
            Convergence.NEEDS_HUMAN, review_a, review_b,
            reason=f"both-{verdict.value}-low-confidence",
            agreement_score=score,
        )
    return ConvergenceResult(
        Convergence.NEEDS_HUMAN, review_a, review_b,
        reason="mixed-verdicts",
        agreement_score=score,
    )


__all__ = [
    "SCHEMA", "ReviewVerdict", "Convergence",
    "Review", "ConvergenceResult", "santa_loop",
]
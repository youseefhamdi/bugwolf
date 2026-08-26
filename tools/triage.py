#!/usr/bin/env python3
"""Triage and disclosure gates for potentially novel candidates.

F0.5 precision-first mode (default, ``strict=True``): candidates whose
deterministic confidence score falls below ``STRICT_CONFIDENCE_THRESHOLD``
are not eligible for human review and are quarantined as candidate records
under ``state/learning/<target>.jsonl``.  ``strict=False`` preserves the
unscored legacy behavior.  The gate governs *reporting* — it never blocks
execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from tools.research_model import (
        CandidateStatus, NoveltyLabel, ResearchCandidate,
    )
except ImportError:
    from research_model import CandidateStatus, NoveltyLabel, ResearchCandidate

# F0.5 precision-first gate — sub-threshold candidates are quarantined.
STRICT_CONFIDENCE_THRESHOLD = 0.6


@dataclass
class TriageDecision:
    candidate_id: str
    eligible_for_human_review: bool
    reasons: List[str] = field(default_factory=list)
    confidence: float = 0.0
    recommended_severity: str = "info"


@dataclass
class DisclosureReport:
    report_id: str
    candidate_id: str
    title: str
    status: str
    target: str
    surface: str
    bug_class: str
    severity: str
    confidence: float
    summary: str
    impact: str
    reproduction: str
    remediation: str
    evidence_ids: List[str]
    novelty_note: str
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class CandidateTriage:
    """Enforce evidence, novelty, confidence, and human-review requirements."""

    def __init__(self, *, strict: bool = True,
                 project_root: Optional[str] = None):
        self.strict = strict
        self.project_root = project_root

    def evaluate(self, candidate: ResearchCandidate) -> TriageDecision:
        reasons: List[str] = []
        if not candidate.trigger_trace.strip():
            reasons.append("trigger trace is missing")
        if not candidate.impact_trace.strip():
            reasons.append("impact trace is missing")
        if not candidate.evidence:
            reasons.append("reproducible evidence is missing")
        if candidate.novelty == NoveltyLabel.EXACT_DUPLICATE:
            reasons.append("candidate has an exact local duplicate")
        if candidate.status not in {
            CandidateStatus.NOVELTY_PENDING, CandidateStatus.HUMAN_REVIEW,
        }:
            reasons.append(f"candidate status is {candidate.status.value}")
        eligible = not reasons
        confidence = self._confidence(candidate, eligible)
        # F0.5 precision gate: sub-threshold candidates never reach review.
        if self.strict and confidence < STRICT_CONFIDENCE_THRESHOLD:
            eligible = False
            reasons.append(
                f"confidence {confidence:.3f} below the F0.5 threshold "
                f"({STRICT_CONFIDENCE_THRESHOLD})")
        severity = candidate.severity if eligible else "info"
        return TriageDecision(
            candidate_id=candidate.candidate_id,
            eligible_for_human_review=eligible,
            reasons=reasons,
            confidence=confidence,
            recommended_severity=severity,
        )

    @staticmethod
    def _confidence(candidate: ResearchCandidate, eligible: bool) -> float:
        score = candidate.confidence
        if candidate.evidence:
            score += 0.15
        if candidate.trigger_trace:
            score += 0.15
        if candidate.impact_trace:
            score += 0.20
        if candidate.novelty == NoveltyLabel.POTENTIALLY_NOVEL:
            score += 0.10
        if candidate.novelty == NoveltyLabel.LIKELY_VARIANT:
            score -= 0.10
        if not eligible:
            score -= 0.20
        return round(max(0.0, min(1.0, score)), 3)

    def quarantine(self, candidate: ResearchCandidate,
                   reason: str) -> Dict[str, Any]:
        """Quarantine a low-confidence candidate to state/learning/<target>.jsonl.

        Reuses the adaptive-learning store (append-only, target-isolated,
        redacted, candidate-by-default) so the candidate survives for
        operator review instead of being silently dropped.
        """
        try:
            from tools.adaptive_learning import AdaptiveMemory
        except ImportError:
            from adaptive_learning import AdaptiveMemory
        memory = AdaptiveMemory(candidate.target, root=self.project_root)
        return memory.ingest(
            kind="low-confidence-candidate",
            title=str(candidate.title)[:120],
            summary=(f"F0.5 quarantined candidate: "
                     f"{reason[:200]}"),
            bug_classes=[candidate.bug_class] if candidate.bug_class else (),
            evidence_refs=[item.evidence_id for item in candidate.evidence],
            journey="f0.5-quarantine",
        )

    def enter_review(self, candidate: ResearchCandidate) -> TriageDecision:
        decision = self.evaluate(candidate)
        if not decision.eligible_for_human_review:
            # Sub-threshold candidates are quarantined (advisory) before the
            # gate rejects them — precision-first, never silently dropped.
            if self.strict and "F0.5" in " ".join(decision.reasons):
                try:
                    self.quarantine(candidate, "; ".join(decision.reasons))
                except Exception:
                    pass  # quarantine is advisory; the gate still stands
            raise ValueError("candidate is not ready for human review: "
                             + "; ".join(decision.reasons))
        if candidate.status == CandidateStatus.NOVELTY_PENDING:
            candidate.confidence = decision.confidence
            candidate.transition(CandidateStatus.HUMAN_REVIEW,
                                 reason="automated evidence and novelty gates passed")
        return decision

    def approve(self, candidate: ResearchCandidate, reviewer: str,
                note: str = "") -> ResearchCandidate:
        if candidate.status != CandidateStatus.HUMAN_REVIEW:
            raise ValueError("only human-review candidates can be approved")
        if not reviewer.strip():
            raise ValueError("reviewer identity is required")
        candidate.metadata["human_review"] = {
            "reviewer": reviewer,
            "note": note,
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }
        candidate.transition(CandidateStatus.CONFIRMED,
                             reason=f"approved by {reviewer}")
        return candidate

    def report(self, candidate: ResearchCandidate) -> DisclosureReport:
        """Generate a report only from a human-confirmed candidate."""
        if candidate.status != CandidateStatus.CONFIRMED:
            raise ValueError("only human-confirmed candidates can be disclosed")
        report_id = hashlib.sha256(
            f"{candidate.candidate_id}:{candidate.updated_at}".encode()).hexdigest()[:16]
        novelty_note = (
            "Potentially novel candidate; independent novelty review recorded."
            if candidate.novelty in {
                NoveltyLabel.POTENTIALLY_NOVEL, NoveltyLabel.NOVELTY_REVIEWED,
            }
            else "Candidate has known similarity; disclose only with reviewer context."
        )
        return DisclosureReport(
            report_id=report_id,
            candidate_id=candidate.candidate_id,
            title=candidate.title,
            status="human_confirmed_pending_disclosure",
            target=candidate.target,
            surface=candidate.surface.value,
            bug_class=candidate.bug_class,
            severity=candidate.severity,
            confidence=candidate.confidence,
            summary=candidate.hypothesis,
            impact=candidate.impact_trace,
            reproduction=candidate.trigger_trace,
            remediation=str(candidate.metadata.get("remediation", "")),
            evidence_ids=[item.evidence_id for item in candidate.evidence],
            novelty_note=novelty_note,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

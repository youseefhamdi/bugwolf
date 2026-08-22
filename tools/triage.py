#!/usr/bin/env python3
"""Triage and disclosure gates for potentially novel candidates."""

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
    """Enforce evidence, novelty, and human-review requirements."""

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

    def enter_review(self, candidate: ResearchCandidate) -> TriageDecision:
        decision = self.evaluate(candidate)
        if not decision.eligible_for_human_review:
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

#!/usr/bin/env python3
"""Shared data model for BugWolf's novel-vulnerability research track.

The model deliberately uses *potentially novel candidate* terminology. A
candidate is not called a zero-day until a human reviews the evidence and the
independent novelty workflow is complete.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "bugwolf-zero-day-research-v1"


class CandidateStatus(str, Enum):
    HYPOTHESIS = "hypothesis"
    OBSERVED = "observed"
    REPRODUCIBLE = "reproducible"
    IMPACT_BOUNDED = "impact_bounded"
    NOVELTY_PENDING = "novelty_pending"
    HUMAN_REVIEW = "human_review"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    DISCLOSED = "disclosed"


class NoveltyLabel(str, Enum):
    UNKNOWN = "unknown"
    EXACT_DUPLICATE = "exact_duplicate"
    LIKELY_VARIANT = "likely_variant"
    POTENTIALLY_NOVEL = "potentially_novel"
    NOVELTY_REVIEWED = "novelty_reviewed"


class Surface(str, Enum):
    WEB_API = "web_api"
    SMART_CONTRACT = "smart_contract"
    CLOUD_CICD = "cloud_cicd"
    LLM_AGENTIC = "llm_agentic"
    MOBILE_BINARY = "mobile_binary"


@dataclass
class EvidenceRef:
    evidence_id: str
    kind: str
    sha256: str
    path: str = ""
    note: str = ""


@dataclass
class MutationAttempt:
    attempt_id: str
    variable: str
    before: Any
    after: Any
    outcome: str = "unknown"
    evidence_ids: List[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


_ALLOWED_TRANSITIONS = {
    CandidateStatus.HYPOTHESIS: {
        CandidateStatus.OBSERVED, CandidateStatus.REJECTED,
    },
    CandidateStatus.OBSERVED: {
        CandidateStatus.REPRODUCIBLE, CandidateStatus.REJECTED,
    },
    CandidateStatus.REPRODUCIBLE: {
        CandidateStatus.IMPACT_BOUNDED, CandidateStatus.REJECTED,
    },
    CandidateStatus.IMPACT_BOUNDED: {
        CandidateStatus.NOVELTY_PENDING, CandidateStatus.REJECTED,
    },
    CandidateStatus.NOVELTY_PENDING: {
        CandidateStatus.HUMAN_REVIEW, CandidateStatus.DUPLICATE,
        CandidateStatus.REJECTED,
    },
    CandidateStatus.HUMAN_REVIEW: {
        CandidateStatus.CONFIRMED, CandidateStatus.DUPLICATE,
        CandidateStatus.REJECTED,
    },
    CandidateStatus.CONFIRMED: {CandidateStatus.DISCLOSED},
    CandidateStatus.DUPLICATE: set(),
    CandidateStatus.REJECTED: set(),
    CandidateStatus.DISCLOSED: set(),
}


@dataclass
class ResearchCandidate:
    target: str
    surface: Surface | str
    bug_class: str
    title: str
    hypothesis: str
    location: str = ""
    trigger_trace: str = ""
    impact_trace: str = ""
    map_path: str = ""
    severity: str = "info"
    confidence: float = 0.0
    status: CandidateStatus | str = CandidateStatus.HYPOTHESIS
    novelty: NoveltyLabel | str = NoveltyLabel.UNKNOWN
    novelty_score: float = 0.0
    candidate_id: str = ""
    evidence: List[EvidenceRef] = field(default_factory=list)
    mutations: List[MutationAttempt] = field(default_factory=list)
    known_matches: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        self.surface = Surface(self.surface)
        self.status = CandidateStatus(self.status)
        self.novelty = NoveltyLabel(self.novelty)
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.candidate_id:
            self.candidate_id = self.stable_id()
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.novelty_score = max(0.0, min(1.0, float(self.novelty_score)))

    def stable_id(self) -> str:
        raw = "|".join([
            str(self.target).strip().lower(), self.surface.value,
            self.bug_class.strip().lower(), self.location.strip().lower(),
            self.hypothesis.strip().lower(),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def transition(self, new_status: CandidateStatus | str,
                   *, reason: str = "") -> None:
        new_status = CandidateStatus(new_status)
        if new_status == self.status:
            return
        if new_status not in _ALLOWED_TRANSITIONS[self.status]:
            raise ValueError(
                f"illegal candidate transition: {self.status.value} -> "
                f"{new_status.value}")
        previous_status = self.status
        self.status = new_status
        if reason:
            self.metadata.setdefault("status_history", []).append({
                "from": previous_status.value,
                "to": new_status.value,
                "reason": reason,
                "at": datetime.now(timezone.utc).isoformat(),
            })
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, evidence: EvidenceRef) -> None:
        if not any(item.evidence_id == evidence.evidence_id for item in self.evidence):
            self.evidence.append(evidence)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_mutation(self, mutation: MutationAttempt) -> None:
        if any(item.attempt_id == mutation.attempt_id for item in self.mutations):
            raise ValueError(f"duplicate mutation attempt: {mutation.attempt_id}")
        self.mutations.append(mutation)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def has_impact_evidence(self) -> bool:
        return bool(self.impact_trace.strip()) and bool(self.evidence)

    def can_enter_human_review(self) -> bool:
        return (
            self.status == CandidateStatus.NOVELTY_PENDING
            and bool(self.trigger_trace.strip())
            and self.has_impact_evidence()
            and self.novelty != NoveltyLabel.EXACT_DUPLICATE
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        data["surface"] = self.surface.value
        data["status"] = self.status.value
        data["novelty"] = self.novelty.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResearchCandidate":
        raw = dict(data)
        raw.pop("schema", None)
        raw.pop("fingerprint", None)
        raw["evidence"] = [EvidenceRef(**item) for item in raw.get("evidence", [])]
        raw["mutations"] = [MutationAttempt(**item) for item in raw.get("mutations", [])]
        return cls(**raw)

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

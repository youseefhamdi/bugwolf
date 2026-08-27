#!/usr/bin/env python3
"""Deterministic Web/API workflow and race-signal analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class WebApiWorkflowAnalyzer:
    """Turn supplied workflow/race observations into reviewable candidates."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def analyze_workflow(
        self,
        workflow: Iterable[Dict[str, Any]],
        *,
        observed_sequences: Iterable[Dict[str, Any]] = (),
    ) -> List[ResearchCandidate]:
        """Find successful skip/reorder/repeat sequences against a declared flow."""
        steps = [dict(item) for item in workflow if item.get("step")]
        expected = {item["step"] for item in steps}
        candidates: List[ResearchCandidate] = []
        for observation in observed_sequences:
            kind = str(observation.get("kind") or "").strip().lower()
            step = str(observation.get("step") or "").strip()
            status = int(observation.get("status") or 0)
            if kind not in {"skip", "reorder", "repeat"} or step not in expected:
                continue
            if not 200 <= status < 300:
                continue
            candidates.append(ResearchCandidate(
                domain="web_api",
                target=self.target,
                bug_class="business_logic",
                title=f"Workflow {kind} accepted: {step}",
                endpoint=str(observation.get("endpoint") or ""),
                severity="high",
                behavior={
                    "sequence_kind": kind,
                    "step": step,
                    "status": status,
                    "sequence": observation.get("sequence") or [],
                    "expected_steps": [item["step"] for item in steps],
                },
                notes=["Workflow acceptance requires clean-state reproduction and state confirmation."],
            ))
        return self._deduplicate(candidates)

    def analyze_race_observations(
        self, observations: Iterable[Dict[str, Any]]
    ) -> List[ResearchCandidate]:
        """Find duplicate-success or unexpected state deltas in a race run."""
        candidates: List[ResearchCandidate] = []
        for observation in observations:
            requests = int(observation.get("requests") or 0)
            successes = int(observation.get("successful_responses") or 0)
            state_delta = observation.get("state_delta") or {}
            expected = str(observation.get("expected") or "").strip()
            if requests < 2 or successes <= 1:
                continue
            if expected and "one" in expected.lower() and successes <= 1:
                continue
            candidates.append(ResearchCandidate(
                domain="web_api",
                target=self.target,
                bug_class="race_condition_web",
                title=f"Concurrent action produced {successes} successes",
                endpoint=str(observation.get("endpoint") or ""),
                severity="high",
                behavior={
                    "method": observation.get("method") or "GET",
                    "requests": requests,
                    "duplicate_successes": successes,
                    "state_delta": state_delta,
                    "expected": expected,
                },
                notes=["Validate with alternating schedules, clean state, and server-side state evidence."],
            ))
        return self._deduplicate(candidates)

    def register(self, candidates: Iterable[ResearchCandidate]) -> bool:
        added = False
        for candidate in candidates:
            candidate.target = candidate.target or self.target
            if self.store.add(candidate):
                added = True
        return added

    @staticmethod
    def _deduplicate(candidates: Iterable[ResearchCandidate]) -> List[ResearchCandidate]:
        seen = set()
        result = []
        from tools.candidate_lifecycle import candidate_signature
        for candidate in candidates:
            signature = candidate_signature(candidate)
            if signature not in seen:
                seen.add(signature)
                result.append(candidate)
        return result

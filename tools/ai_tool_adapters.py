#!/usr/bin/env python3
"""Normalize PyRIT / Garak / Promptfoo AI red-team traces into candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class AIToolAdapters:
    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def from_pyrit(self, trace: Dict[str, Any]) -> List[ResearchCandidate]:
        conversation = list(trace.get("conversation") or [])
        candidates: List[ResearchCandidate] = []
        for message in conversation:
            content = str(message.get("content") or "")
            low = content.lower()
            if any(marker in low for marker in ("ignore previous", "ignore all", "extract secret", "exfiltrate")):
                candidates.append(ResearchCandidate(
                    domain="ai", target=self.target, bug_class="prompt_injection",
                    title="Prompt injection attempt observed",
                    severity="high",
                    behavior={"role": message.get("role"), "content": content[:2000],
                              "source": "pyrit"},
                    notes=["Evaluate the full action trace in a local sandbox before promoting."],
                ))
                break
        return self._deduplicate(candidates)

    def from_garak(self, result: Dict[str, Any]) -> List[ResearchCandidate]:
        probes = list(result.get("probes") or [])
        candidates: List[ResearchCandidate] = []
        for probe in probes:
            probe_name = str(probe.get("probe") or "probe")
            detectors = probe.get("detectors") or {}
            triggered = any(
                float(d.get("score") or 0) >= 0.5
                for d in detectors.values() if isinstance(d, dict)
            )
            if not triggered:
                continue
            candidates.append(ResearchCandidate(
                domain="ai", target=self.target, bug_class=probe_name,
                title=f"Garak probe triggered: {probe_name}",
                severity="high",
                behavior={"probe": probe_name, "detectors": detectors,
                          "outputs": probe.get("outputs") or [], "source": "garak"},
                notes=["Validate the detector score against a clean baseline."],
            ))
        return self._deduplicate(candidates)

    def from_promptfoo(self, result: Dict[str, Any]) -> List[ResearchCandidate]:
        results = list(result.get("results") or [])
        candidates: List[ResearchCandidate] = []
        for item in results:
            grading = item.get("grading") or {}
            assertions = list(grading.get("assertionResults") or [])
            failed = [a for a in assertions if isinstance(a, dict) and a.get("pass")]
            if not failed:
                continue
            candidates.append(ResearchCandidate(
                domain="ai", target=self.target, bug_class="harmful_output",
                title="Promptfoo harmful-output assertion triggered",
                severity="high",
                behavior={"prompt": str(item.get("prompt") or "")[:2000],
                          "output": str(item.get("output") or "")[:2000],
                          "assertions": [a.get("assertion") for a in failed],
                          "source": "promptfoo"},
                notes=["Confirm the assertion reflects policy-relevant harm."],
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
        from tools.candidate_lifecycle import candidate_signature
        seen = set()
        output = []
        for candidate in candidates:
            signature = candidate_signature(candidate)
            if signature not in seen:
                seen.add(signature)
                output.append(candidate)
        return output
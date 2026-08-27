#!/usr/bin/env python3
"""Normalize local smart-contract tool output into BugWolf candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class Web3ToolResultAdapter:
    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def from_slither(self, result: Dict[str, Any]) -> List[ResearchCandidate]:
        detectors = ((result.get("results") or {}).get("detectors") or [])
        candidates: List[ResearchCandidate] = []
        for detector in detectors:
            if not isinstance(detector, dict):
                continue
            check = str(detector.get("check") or "unknown")
            elements = detector.get("elements") or []
            locations = []
            for element in elements[:20]:
                mapping = element.get("source_mapping") if isinstance(element, dict) else {}
                if isinstance(mapping, dict):
                    filename = mapping.get("filename_relative") or mapping.get("filename_short") or ""
                    lines = mapping.get("lines") or []
                    if filename:
                        locations.append({"file": str(filename), "lines": list(lines)[:20]})
            description = str(detector.get("description") or "")
            candidates.append(ResearchCandidate(
                domain="web3", target=self.target, bug_class=check,
                title=f"Static analyzer finding: {check}",
                endpoint=str(locations[0].get("file") if locations else ""),
                severity=str(detector.get("impact") or "info").lower(),
                confidence=1.0 if str(detector.get("confidence") or "").lower() == "high" else 0.6,
                behavior={"description": description, "source": locations, "tool": "slither"},
                notes=["Static output is a hypothesis; validate dynamically in a clean local fixture."],
            ))
        return self._deduplicate(candidates)

    def from_property_runner(self, result: Dict[str, Any]) -> List[ResearchCandidate]:
        failures = result.get("failures") or result.get("failed_invariants") or []
        candidates: List[ResearchCandidate] = []
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            name = str(failure.get("test") or failure.get("name") or "invariant_failure")
            sequence = list(failure.get("trace") or failure.get("sequence") or [])[:128]
            candidates.append(ResearchCandidate(
                domain="web3", target=self.target, bug_class=name,
                title=f"Property failure: {name}",
                endpoint=str(failure.get("contract") or ""), severity="high",
                behavior={"reason": str(failure.get("reason") or ""),
                          "sequence": sequence, "tool": str(result.get("tool") or "property_runner")},
                notes=["Reproduce from a clean local-chain snapshot and minimize the failing sequence."],
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

#!/usr/bin/env python3
"""Phase 3 Web3 candidate adapter.

Consumes observations produced by local Hardhat/Foundry-style fixtures. It
never contacts a chain and never labels a candidate a confirmed zero-day.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class Web3ResearchAdapter:
    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def analyze_observations(self, observations: Iterable[Dict[str, Any]]) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for observation in observations:
            invariants = observation.get("invariants") or {}
            violated = [str(name) for name, holds in invariants.items() if not bool(holds)]
            if not violated:
                continue
            sequence = list(observation.get("sequence") or [])
            candidates.append(ResearchCandidate(
                domain="web3",
                target=self.target,
                bug_class="invariant_violation",
                title=f"Contract invariant violation: {', '.join(violated)}",
                endpoint=str(sequence[-1] if sequence else observation.get("contract") or ""),
                severity="high",
                behavior={
                    "sequence": sequence,
                    "caller": observation.get("caller") or "attacker",
                    "state_before": observation.get("state_before") or {},
                    "state_after": observation.get("state_after") or observation.get("state") or {},
                    "violated": violated,
                    "trace": observation.get("trace") or [],
                },
                notes=["Reproduce from a clean local-chain snapshot and minimize the transaction sequence."],
            ))
        return self._deduplicate(candidates)

    def analyze_trace_pairs(self, pairs: Iterable[Dict[str, Any]]) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for pair in pairs:
            left = pair.get("chain_a") or pair.get("left") or {}
            right = pair.get("chain_b") or pair.get("right") or {}
            if left == right:
                continue
            name = str(pair.get("name") or pair.get("function") or "trace")
            candidates.append(ResearchCandidate(
                domain="web3",
                target=self.target,
                bug_class="execution_trace_differential",
                title=f"Execution trace differs: {name}",
                endpoint=name,
                severity="medium",
                behavior={"trace_a": left, "trace_b": right, "operation": name},
                notes=["Compare the same transaction, caller, block state, and compiler/runtime configuration."],
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

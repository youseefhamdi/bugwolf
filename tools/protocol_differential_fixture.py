#!/usr/bin/env python3
"""Local HTTP/2·HTTP/3 differential and serverless/edge simulation fixtures.

These are deterministic in-memory fixtures for lab use. They do not perform
network I/O; they model protocol-version and cold/warm behavior so downstream
analysis can be tested offline and bounded.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class ProtocolDifferentialFixture:
    """Record per-protocol observations and report version deltas."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self._records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def record(self, protocol: str, endpoint: str, response: Dict[str, Any]) -> None:
        self._records.setdefault(endpoint, []).append({
            "protocol": str(protocol).lower(), "endpoint": endpoint,
            "response": dict(response),
        })

    def deltas(self) -> List[Dict[str, Any]]:
        deltas: List[Dict[str, Any]] = []
        for endpoint, records in self._records.items():
            by_protocol: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for record in records:
                by_protocol[record["protocol"]].append(record["response"])
            protocols = sorted(by_protocol)
            for index in range(len(protocols)):
                for other_index in range(index + 1, len(protocols)):
                    a = by_protocol[protocols[index]]
                    b = by_protocol[protocols[other_index]]
                    if not a or not b:
                        continue
                    a_last = a[-1]
                    b_last = b[-1]
                    if a_last == b_last:
                        continue
                    deltas.append({
                        "endpoint": endpoint,
                        "protocol": protocols[index],
                        "other_protocol": protocols[other_index],
                        "a": a_last,
                        "b": b_last,
                    })
        return deltas

    def candidates(self) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for delta in self.deltas():
            candidates.append(ResearchCandidate(
                domain="web_api", target=self.target,
                bug_class="protocol_differential",
                title=f"Protocol behavior delta on {delta['endpoint']}",
                endpoint=delta["endpoint"], severity="medium",
                behavior=delta,
                notes=["Replay the identical request over each protocol in a local fixture."],
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


class ServerlessEdgeFixture:
    """Model cold/warm/edge-region execution deltas."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self._records: List[Dict[str, Any]] = []
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def record(self, state: str, endpoint: str, response: Dict[str, Any]) -> None:
        self._records.append({
            "state": str(state).lower(), "endpoint": endpoint,
            "response": dict(response),
        })

    def candidates(self) -> List[ResearchCandidate]:
        by_endpoint: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        for record in self._records:
            by_endpoint[record["endpoint"]][record["state"]] = record["response"]
        candidates: List[ResearchCandidate] = []
        for endpoint, states in by_endpoint.items():
            cold = states.get("cold") or {}
            warm = states.get("warm") or {}
            if not cold or not warm:
                continue
            cold_ms = float(cold.get("elapsed_ms") or 0.0)
            warm_ms = float(warm.get("elapsed_ms") or 0.0)
            if cold_ms <= warm_ms * 4:
                continue
            candidates.append(ResearchCandidate(
                domain="web_api", target=self.target,
                bug_class="serverless_cold_start",
                title=f"Serverless cold-start delta on {endpoint}",
                endpoint=endpoint, severity="medium",
                behavior={
                    "endpoint": endpoint,
                    "elapsed_cold_ms": cold_ms,
                    "elapsed_warm_ms": warm_ms,
                    "cold_response": cold,
                    "warm_response": warm,
                },
                notes=["Confirm cold-start behavior is reproducible and not a transient effect."],
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
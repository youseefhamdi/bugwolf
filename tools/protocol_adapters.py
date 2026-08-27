#!/usr/bin/env python3
"""GraphQL / WebSocket / gRPC protocol observation adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


def graphql_observation(*, endpoint: str, query: str = "",
                        response: Optional[Dict[str, Any]] = None,
                        status: int = 0, aliases: int = 0, depth: int = 0,
                        batching: int = 0) -> Dict[str, Any]:
    signals = []
    if aliases >= 4:
        signals.append(f"aliases:{aliases}")
    if depth >= 5:
        signals.append(f"depth:{depth}")
    if batching >= 2:
        signals.append(f"batching:{batching}")
    return {
        "protocol": "graphql", "endpoint": endpoint, "query": str(query)[:2000],
        "response": response or {}, "status": status, "aliases": aliases,
        "depth": depth, "batching": batching, "signals": signals,
    }


def websocket_observation(*, endpoint: str, messages: Optional[List[Any]] = None,
                          status: int = 0) -> Dict[str, Any]:
    messages = list(messages or [])
    return {
        "protocol": "websocket", "endpoint": endpoint, "status": status,
        "message_count": len(messages), "messages": messages[:100],
        "signals": ["unauthenticated_upgrade"] if status == 101 and not messages else [],
    }


def grpc_observation(*, endpoint: str, method: str = "",
                     status: int = 0, trailers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    trailers = dict(trailers or {})
    signals = []
    if trailers.get("grpc-status") not in (None, "0"):
        signals.append(f"grpc-status:{trailers.get('grpc-status')}")
    return {
        "protocol": "grpc", "endpoint": endpoint, "method": method,
        "status": status, "trailers": trailers, "signals": signals,
    }


class ProtocolAdapter:
    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def analyze(self, observations: Iterable[Dict[str, Any]]) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for obs in observations:
            protocol = str(obs.get("protocol") or "").lower()
            signals = list(obs.get("signals") or [])
            if protocol == "graphql" and signals:
                candidates.append(ResearchCandidate(
                    domain="web_api", target=self.target, bug_class="graphql_abuse",
                    title=f"GraphQL abuse signal on {obs.get('endpoint', '')}",
                    endpoint=str(obs.get("endpoint") or ""), severity="medium",
                    behavior={"query": obs.get("query"), "signals": signals,
                              "aliases": obs.get("aliases"), "depth": obs.get("depth")},
                    notes=["Validate batching/aliasing/depth limits in a local fixture."],
                ))
            elif protocol == "websocket" and signals:
                candidates.append(ResearchCandidate(
                    domain="web_api", target=self.target, bug_class="websocket_auth",
                    title=f"WebSocket signal on {obs.get('endpoint', '')}",
                    endpoint=str(obs.get("endpoint") or ""), severity="medium",
                    behavior={"signals": signals, "message_count": obs.get("message_count")},
                    notes=["Confirm upgrade authorization and message-level access control."],
                ))
            elif protocol == "grpc" and signals:
                candidates.append(ResearchCandidate(
                    domain="web_api", target=self.target, bug_class="grpc_status",
                    title=f"gRPC status signal on {obs.get('method', '')}",
                    endpoint=str(obs.get("method") or obs.get("endpoint") or ""),
                    severity="medium",
                    behavior={"trailers": obs.get("trailers"), "signals": signals},
                    notes=["Validate error handling and authorization on the gRPC method."],
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
#!/usr/bin/env python3
"""ERC-4337 account-abstraction and L2 bridge fixture models.

Deterministic in-memory fixtures for local lab analysis. They model
UserOperation and bridge-message state so replay and domain-confusion signals
can be tested offline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


class AccountAbstractionFixture:
    """Track UserOperations and flag nonce/signature replays."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self._operations: List[Dict[str, Any]] = []
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def record_operation(self, operation: Dict[str, Any]) -> None:
        self._operations.append(dict(operation))

    def candidates(self) -> List[ResearchCandidate]:
        seen: Dict[tuple, List[Dict[str, Any]]] = {}
        for operation in self._operations:
            key = (str(operation.get("sender") or ""),
                   str(operation.get("nonce") or ""))
            seen.setdefault(key, []).append(operation)
        candidates: List[ResearchCandidate] = []
        for (sender, nonce), ops in seen.items():
            if len(ops) < 2:
                continue
            signatures = {str(op.get("signature") or "") for op in ops}
            if len(signatures) < 2:
                continue
            candidates.append(ResearchCandidate(
                domain="web3", target=self.target,
                bug_class="account_abstraction_replay",
                title=f"UserOperation nonce replay: sender={sender} nonce={nonce}",
                endpoint=sender, severity="high",
                behavior={"sender": sender, "nonce": nonce,
                          "operations": ops},
                notes=["Validate bundler nonce/entry-point enforcement in a local fixture."],
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


class BridgeFixture:
    """Track bridge messages and detect cross-chain replay/domain confusion."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self._messages: List[Dict[str, Any]] = []
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def record_message(self, message: Dict[str, Any]) -> None:
        self._messages.append(dict(message))

    def candidates(self) -> List[ResearchCandidate]:
        seen: Dict[str, List[Dict[str, Any]]] = {}
        for message in self._messages:
            key = str(message.get("id") or message.get("nonce") or "")
            if key:
                seen.setdefault(key, []).append(message)
        candidates: List[ResearchCandidate] = []
        for key, messages in seen.items():
            chains = {str(m.get("chain") or "") for m in messages}
            if len(chains) < 2:
                continue
            candidates.append(ResearchCandidate(
                domain="web3", target=self.target,
                bug_class="bridge_message_replay",
                title=f"Bridge message replayed across chains: {key}",
                endpoint=key, severity="high",
                behavior={"message_id": key, "chains": sorted(chains),
                          "messages": messages},
                notes=["Validate per-chain message uniqueness and domain separation in a local fixture."],
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
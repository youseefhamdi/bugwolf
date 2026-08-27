#!/usr/bin/env python3
"""Multi-agent delegation fixture for offline goal-hijack analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate

_SENSITIVE_TOOLS = ("send_email", "shell", "exec", "run_command", "transfer",
                    "payment", "delete", "deploy", "grant", "revoke", "upload")
_SUSPICIOUS_MARKERS = ("attacker", "evil", "exfil", "secret", "password",
                       "token", "ignore", "bypass", "steal", "all")


class MultiAgentFixture:
    """Track agents, their tools, and delegations."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._delegations: List[Dict[str, Any]] = []
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def add_agent(self, name: str, *, tools: Optional[List[str]] = None,
                  privileged: bool = False) -> None:
        self._agents[str(name)] = {
            "tools": list(tools or []), "privileged": bool(privileged),
        }

    def record_delegation(self, from_agent: str, to_agent: str, instruction: str) -> None:
        self._delegations.append({
            "from": str(from_agent), "to": str(to_agent),
            "instruction": str(instruction),
        })

    def candidates(self) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for delegation in self._delegations:
            to = delegation["to"]
            agent = self._agents.get(to)
            if not agent:
                continue
            instruction = delegation["instruction"].lower()
            has_sensitive_tool = any(
                marker in tool for tool in agent.get("tools", [])
                for marker in _SENSITIVE_TOOLS)
            suspicious = any(marker in instruction for marker in _SUSPICIOUS_MARKERS)
            if not (suspicious and (has_sensitive_tool or agent.get("privileged"))):
                continue
            candidates.append(ResearchCandidate(
                domain="ai", target=self.target, bug_class="multi_agent_goal_hijack",
                title=f"Delegation to privileged agent may hijack goals: {to}",
                endpoint=to, severity="high",
                behavior={
                    "from": delegation["from"], "to": to,
                    "instruction": delegation["instruction"][:2000],
                    "agent_tools": agent.get("tools"), "privileged": agent.get("privileged"),
                },
                notes=["Validate the delegated instruction against the agent's permission boundary in a local sandbox."],
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
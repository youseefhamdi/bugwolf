#!/usr/bin/env python3
"""Local deterministic LLM sandbox for offline agent testing.

The sandbox never calls an external model. It provides a deterministic fake
model and a trace object so agent prompts, tool calls, and tool results can
be recorded and analyzed without network access or real credentials.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LLMTrace:
    prompt: str = ""
    system: str = ""
    conversation: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now()
        if self.prompt and not self.conversation:
            self.conversation.append({"role": "user", "content": self.prompt})

    def record_tool_call(self, tool: str, arguments: Dict[str, Any]) -> None:
        self.tool_calls.append({"tool": str(tool), "arguments": dict(arguments or {}),
                                "at": _now()})

    def record_tool_result(self, result: Dict[str, Any]) -> None:
        self.tool_results.append(dict(result or {}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "bugwolf/llm-trace/v1",
            "prompt": self.prompt, "system": self.system,
            "conversation": self.conversation, "tool_calls": self.tool_calls,
            "tool_results": self.tool_results, "tool_count": len(self.tool_calls),
            "created_at": self.created_at,
        }


class LLMSandbox:
    """Deterministic fake model for offline prompt/tool testing."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self.trace = LLMTrace()
        from pathlib import Path
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def respond(self, prompt: str, *, system: str = "") -> Dict[str, Any]:
        """Return a deterministic echo-style response and record a trace."""
        trace = LLMTrace(prompt=str(prompt), system=str(system))
        output = f"Echo: {str(prompt)[:500]}"
        trace.conversation.append({"role": "assistant", "content": output})
        return {"output": output, "trace": trace}

    def analyze_trace(self, trace: LLMTrace) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for call in trace.tool_calls:
            tool = str(call.get("tool") or "")
            if tool.lower() in ("shell", "exec", "run_command", "bash", "subprocess"):
                candidates.append(ResearchCandidate(
                    domain="ai", target=self.target, bug_class="tool_misuse",
                    title=f"Sandbox tool invocation: {tool}", endpoint=tool,
                    severity="high", behavior=call,
                    notes=["Validate the tool call against the sandbox policy."],
                ))
        return self._deduplicate(candidates)

    def register(self, candidates: List[ResearchCandidate]) -> bool:
        added = False
        for candidate in candidates:
            candidate.target = candidate.target or self.target
            if self.store.add(candidate):
                added = True
        return added

    @staticmethod
    def _deduplicate(candidates: List[ResearchCandidate]) -> List[ResearchCandidate]:
        from tools.candidate_lifecycle import candidate_signature
        seen = set()
        output = []
        for candidate in candidates:
            signature = candidate_signature(candidate)
            if signature not in seen:
                seen.add(signature)
                output.append(candidate)
        return output
#!/usr/bin/env python3
"""MCP (Model Context Protocol) fixture models for offline tool-poisoning analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate


@dataclass
class MCPTool:
    name: str
    description: str = ""
    schema: Dict[str, Any] = field(default_factory=dict)
    original_description: str = ""

    def __post_init__(self) -> None:
        if not self.original_description:
            self.original_description = self.description


@dataclass
class MCPResource:
    uri: str
    description: str = ""
    content: str = ""


class MCPFixture:
    """Track MCP tool/resource metadata mutations and injected outputs."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        self.tools: Dict[str, MCPTool] = {}
        self.resources: Dict[str, MCPResource] = {}
        self._injected_outputs: Dict[str, str] = {}
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def register_tool(self, tool: MCPTool) -> None:
        self.tools[tool.name] = tool

    def register_resource(self, resource: MCPResource) -> None:
        self.resources[resource.uri] = resource

    def mutate_tool_description(self, name: str, description: str) -> None:
        tool = self.tools.get(name)
        if tool:
            tool.description = str(description)

    def inject_resource_output(self, uri: str, output: str) -> None:
        self._injected_outputs[uri] = str(output)

    def candidates(self) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for tool in self.tools.values():
            if tool.description != tool.original_description:
                candidates.append(ResearchCandidate(
                    domain="ai", target=self.target, bug_class="mcp_tool_poisoning",
                    title=f"MCP tool description mutated: {tool.name}",
                    endpoint=tool.name, severity="high",
                    behavior={"tool": tool.name,
                              "original": tool.original_description[:500],
                              "mutated": tool.description[:500]},
                    notes=["Validate tool-description trust and permission boundaries."],
                ))
        for uri, output in self._injected_outputs.items():
            candidates.append(ResearchCandidate(
                domain="ai", target=self.target, bug_class="mcp_resource_poisoning",
                title=f"MCP resource output injected: {uri}",
                endpoint=uri, severity="high",
                behavior={"uri": uri, "output": output[:2000]},
                notes=["Confirm the injected output can steer downstream tool selection."],
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
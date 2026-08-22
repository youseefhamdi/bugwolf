#!/usr/bin/env python3
"""Offline AI application defense analysis for BugWolf.

The analyzer turns source/config signals into findings and defense plans. It
does not call models, send prompts, connect to MCP servers, open URLs, replay
OAuth tokens, execute tools, or evaluate jailbreak payloads against a service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


@dataclass
class AIFinding:
    finding_id: str
    category: str
    title: str
    source: str
    line_number: int
    severity: str
    rationale: str
    evidence_hash: str
    status: str = "static_signal_human_review_required"


@dataclass
class AIDefensePlan:
    plan_id: str
    category: str
    title: str
    controls: List[str]
    validation_questions: List[str]
    evidence_required: List[str]
    status: str = "offline_plan_only"


Rule = Tuple[str, str, str, str, str]

RULES: Sequence[Rule] = (
    (r"(?i)(system_prompt|system_message|prompt)\s*[+f=].{0,180}(user_input|user_message|request|query)", "prompt_concatenation", "User input may be mixed with trusted instructions", "high", "Use structured prompt fields and treat user content as data rather than instructions."),
    (r"(?i)(retriev|document|email|webpage|html|search_result|external_content|tool_output).{0,160}(llm|chat|completion|generate|agent)", "indirect_content", "External content may reach model instructions", "high", "Mark, isolate, and constrain retrieved or tool-produced content before model processing."),
    (r"(?i)(ignore\s+(all\s+)?previous|reveal.*prompt|override.*instruction|bypass.*security)", "keyword_filter_only", "Prompt injection keyword filter signal", "medium", "Regex filters are advisory and cannot serve as the primary security boundary."),
    (r"(?i)(tool_call|function_call|call_tool|execute_tool).{0,160}(model|llm|assistant|output|response)", "model_selected_tool", "Model output may select a tool", "high", "Deterministic authorization must evaluate every tool call against the original user intent and session."),
    (r"(?i)(send_email|delete|update_database|write_file|shell|exec|transfer|payment).{0,100}(tool|function|agent|allow|execute)", "high_risk_tool", "High-risk agent capability requires an approval boundary", "critical", "Use least privilege, short-lived scopes, parameter validation, and human approval for consequential actions."),
    (r"(?i)(memory\.(write|append)|save_memory|conversation_history|long_term_memory).{0,120}(agent|model|user|content)", "memory_persistence", "Untrusted content may persist into agent memory", "high", "Require provenance, tenant binding, sanitization, expiry, and review before memory writes."),
    (r"(?i)(vector|embedding|retriev).{0,160}(tenant|organization|user).{0,80}(missing|none|false|optional)", "rag_isolation", "Retrieval may lack a tenant or principal boundary", "critical", "Enforce server-side tenant filters and information-flow labels independent of model instructions."),
    (r"(?i)(mcp|model context protocol).{0,180}(token|tool|server|client|oauth|scope)", "mcp_boundary", "MCP trust or authorization boundary requires review", "high", "Validate origin, audience, scopes, consent, transport, and tool capabilities."),
    (r"(?i)(redirect_uri|authorization_url|resource_metadata|token_endpoint).{0,120}(request|input|server|client)", "mcp_oauth_url", "OAuth/MCP URL is influenced by an input or remote server", "high", "Allow only validated HTTPS destinations, exact redirect matches, PKCE/state, and no shell URL opening."),
    (r"(?i)(token|access_token).{0,100}(passthrough|forward|downstream|proxy)", "token_passthrough", "Token may be forwarded without audience validation", "critical", "Accept only tokens issued for the current resource and validate issuer, audience, scopes, and expiry."),
    (r"(?i)(subprocess|child_process|shell|spawn).{0,120}(mcp|tool|server|command)", "local_mcp_execution", "Local tool/server process boundary requires sandboxing", "critical", "Require explicit consent, exact command display, sandboxing, restricted filesystem/network, and audit logs."),
    (r"(?i)(output|response).{0,100}(llm|model|assistant).{0,100}(send|execute|tool|database|email)", "output_to_action", "Model output may flow directly into an action sink", "high", "Validate output schema and policy before any downstream action; use HITL for high-risk operations."),
    (r"(?i)(plan|step|reasoning|trajectory).{0,100}(drift|monitor|critic|allow|policy)", "plan_drift_control", "Plan-drift or trajectory control is present or referenced", "medium", "Verify monitoring compares intended task, untrusted context, and proposed action at each step."),
)


def _id(source: str, line: int, category: str, text: str) -> tuple[str, str]:
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.sha256(f"{source}:{line}:{category}:{digest}".encode()).hexdigest()[:16], digest


def analyze_text(text: str, source: str = "artifact") -> List[AIFinding]:
    findings: List[AIFinding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, category, title, severity, rationale in RULES:
            if re.search(pattern, line):
                finding_id, digest = _id(source, line_number, category, line)
                findings.append(AIFinding(finding_id, category, title, source, line_number, severity, rationale, digest))
    return findings


def defense_plans(findings: Iterable[AIFinding]) -> List[AIDefensePlan]:
    categories = {finding.category for finding in findings}
    plans: List[AIDefensePlan] = []
    if categories.intersection({"prompt_concatenation", "indirect_content", "keyword_filter_only"}):
        plans.append(AIDefensePlan(
            "ai-plan-input-isolation", "input_isolation", "Separate instructions from untrusted content",
            ["Use structured prompt fields and data marking/spotlighting", "Quarantine remote content before privileged inference", "Normalize and inspect encoding without trusting a filter", "Keep system instructions outside user-controlled concatenation"],
            ["Can retrieved content alter the instruction hierarchy?", "Are direct, indirect, encoded, and multimodal content paths covered?", "Is a failed filter treated as a signal rather than authorization?"],
            ["Prompt/context provenance", "sanitized fixture", "input/output decision logs"],
        ))
    if categories.intersection({"model_selected_tool", "high_risk_tool", "output_to_action", "plan_drift_control"}):
        plans.append(AIDefensePlan(
            "ai-plan-tool-authorization", "tool_authorization", "Authorize actions outside the model",
            ["Allowlist tools per user/session", "Validate parameters deterministically", "Compare proposed action to original intent and plan", "Use short-lived least-privilege scopes", "Require HITL approval for delete, send, transfer, payment, shell, and database writes"],
            ["Can manipulated content cause a tool call the user did not request?", "Are tool outputs treated as untrusted input?", "Is approval bound to the exact action and parameters?"],
            ["tool registry", "policy decision log", "approval record", "redacted tool trace"],
        ))
    if categories.intersection({"memory_persistence", "rag_isolation"}):
        plans.append(AIDefensePlan(
            "ai-plan-memory-rag", "memory_and_rag", "Bind memory and retrieval to provenance and tenant",
            ["Attach source, tenant, and trust labels", "Enforce server-side retrieval filters", "Require review/expiry for persistent memory", "Use quarantined inference for untrusted documents"],
            ["Can one tenant's content enter another tenant's context?", "Can retrieved instructions persist into future sessions?", "Can the model bypass the filter by selecting a different retrieval path?"],
            ["retrieval policy", "tenant-bound fixture", "memory provenance record", "cross-tenant negative test"],
        ))
    if categories.intersection({"mcp_boundary", "mcp_oauth_url", "token_passthrough", "local_mcp_execution"}):
        plans.append(AIDefensePlan(
            "ai-plan-mcp", "mcp_security", "Harden MCP authorization and local transport",
            ["Require per-client consent and exact redirect URI matching", "Validate issuer, audience, resource, state, PKCE, and scopes", "Reject token passthrough", "Block private/metadata URL destinations and redirect chains", "Require explicit local server consent and sandboxing"],
            ["Can a client skip consent because a prior cookie exists?", "Can a token for another resource be forwarded?", "Can a remote server cause a local command or internal URL request?", "Are scopes minimized and step-up authorization explicit?"],
            ["OAuth metadata", "consent records", "scope policy", "URL validation logs", "stdio sandbox configuration"],
        ))
    return plans


def analyze_paths(paths: Iterable[Path]) -> tuple[List[AIFinding], List[AIDefensePlan]]:
    findings: List[AIFinding] = []
    for path in paths:
        if path.is_file():
            findings.extend(analyze_text(path.read_text(encoding="utf-8", errors="replace"), str(path)))
    return findings, defense_plans(findings)


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline AI defense analysis")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings, plans = analyze_paths(Path(path) for path in args.path)
    for name, rows in (("ai-findings.jsonl", findings), ("ai-defense-plans.jsonl", plans)):
        with (output / name).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    manifest = {"schema": "bugwolf-ai-defense-v1", "findings": len(findings), "plans": len(plans), "execution": "offline_static_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

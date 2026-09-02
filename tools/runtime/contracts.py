#!/usr/bin/env python3
"""BugWolf Runtime Contracts - Phase 1 of the orchestrator plan.

Canonical typed contracts for the BugWolf orchestrator (see
BUGWOLF_ORCHESTRATOR_PLAN_V2.md sections 4.1 and 5.5):

  * MissionSpec  - normalized operator mission, built on the existing
                   tools/harness_command.py NL intake parser (never a second parser).
  * TaskSpec     - one unit of orchestrator work (typed task-graph node).
  * TaskResult   - what a lane returns for a TaskSpec. Validation is strict:
                   a result claiming an insight without a lead reference, or
                   claiming evidence without evidence refs, is malformed.
  * ToolReceipt  - durable record of one deterministic tool invocation.
  * ArtifactRef  - content-addressed reference to a durable artifact.

Design rules from the plan:

  * Contracts are records, not gates - they validate shape, never restrict
    research depth or capability (mirrors tools/execution_semantics.py).
  * Malformed results fail explicitly: a ValidationIssue list, never silent repair.
  * Everything is JSON-serializable (append-only JSONL state plane, plan lever P5).
  * Lead enforcement (plan 5.5 R1/R6): results mentioning insights without lead
    refs are rejected; results holding open leads cannot be terminal.
  * Pre-flight enforcement (plan 4.5): results whose work needed an MCP binding
    (browser/burp) must record the binding ids used.
  * Anti-stalling (plan 5.6): a completed result with zero tool calls AND zero
    evidence refs is rejected - prose-only work is structurally impossible.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from tools.runtime_paths import runtime_path
except ImportError:  # direct script execution from tools/runtime/
    from runtime_paths import runtime_path  # type: ignore

SCHEMA = "bugwolf-runtime-contracts/v1"

# ---------------------------------------------------------------------------
# Status vocabularies (stable string identifiers, consistent with signal_bus)
# ---------------------------------------------------------------------------

RESULT_COMPLETED = "completed"
RESULT_PARTIAL = "agent_partial"
RESULT_FAILED = "agent_failed"
RESULT_TERMINAL_STATUSES = (RESULT_COMPLETED, RESULT_PARTIAL, RESULT_FAILED)

TASK_PENDING = "pending"
TASK_ACTIVE = "active"
TASK_DONE = "done"
TASK_BLOCKED = "blocked"
TASK_STATUSES = (TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED)

# Lead terminal states (plan 5.5 R2) - the ONLY closes allowed
LEAD_OPEN = "OPEN"
LEAD_PWNED = "PWNED"
LEAD_REFUTED = "REFUTED"
LEAD_BUDGET_EXHAUSTED = "BUDGET-EXHAUSTED"
LEAD_TERMINAL_STATES = (LEAD_PWNED, LEAD_REFUTED, LEAD_BUDGET_EXHAUSTED)
LEAD_STATUSES = (LEAD_OPEN, LEAD_PWNED, LEAD_REFUTED, LEAD_BUDGET_EXHAUSTED)

# Lead escalation tiers (plan 5.5 R5). T3/T4 ship in Phase 6 (R6 sequencing note).
LEAD_TIERS = ("T0", "T1", "T2", "T3", "T4")

# Pre-flight / MCP binding status values (plan 4.5 PF4)
MCP_UNKNOWN = "unknown"
MCP_CHECKING = "checking"
MCP_CONNECTED = "connected"
MCP_DEGRADED = "degraded"
MCP_BLOCKED = "blocked"
MCP_STATUSES = (MCP_UNKNOWN, MCP_CHECKING, MCP_CONNECTED, MCP_DEGRADED, MCP_BLOCKED)

# ArtifactRef origin kinds
ARTIFACT_TOOL = "tool"
ARTIFACT_AGENT = "agent"
ARTIFACT_RESEARCH = "research"
ARTIFACT_PREFLIGHT = "preflight"
ARTIFACT_KINDS = (ARTIFACT_TOOL, ARTIFACT_AGENT, ARTIFACT_RESEARCH, ARTIFACT_PREFLIGHT)

# Task domains - mirror zero_day_tracks / harness_command MODE_FLAGS
TASK_DOMAINS = (
    "web_api", "web", "auth", "business_logic", "smart_contract", "cloud_cicd",
    "llm_ai", "mobile", "recon", "fuzz", "verify", "chain", "report", "triage",
    "preflight",
)

# Task-graph node kinds
TASK_TYPES = (
    "recon", "analyze", "probe", "fuzz", "verify", "chain", "research",
    "report", "preflight", "triage", "crawl", "validate", "dispatch",
)

# Model profiles (model_router tiers + plan-v2 section 5 profiles)
MODEL_PROFILES = (
    "fast", "balanced", "deep", "reasoning", "synthesis",
    "deterministic", "local_slm", "frontier",
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ContractViolation(ValueError):
    """Raised when a contract object fails strict validation."""

    def __init__(self, issues: List[str]):
        self.issues = list(issues)
        super().__init__("contract violation: " + "; ".join(self.issues))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_str_list(value: Any, field_name: str, issues: List[str]) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or any(not isinstance(v, str) for v in value):
        issues.append(f"{field_name} must be a list of strings")
        return []
    return list(value)


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------


@dataclass
class ArtifactRef:
    """Content-addressed reference to a durable artifact on disk."""

    path: str
    sha256: str = ""
    kind: str = ARTIFACT_TOOL
    producer_task: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_json(self.to_dict())


def validate_artifact_ref(ref: Any) -> List[str]:
    issues: List[str] = []
    if not isinstance(ref, dict):
        return ["artifact ref must be an object"]
    if not str(ref.get("path") or "").strip():
        issues.append("artifact ref missing path")
    digest = str(ref.get("sha256") or "")
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        issues.append("artifact ref sha256 must be 64 hex chars")
    if ref.get("kind") is not None and ref.get("kind") not in ARTIFACT_KINDS:
        issues.append(f"artifact ref kind {ref.get('kind')!r} not in ARTIFACT_KINDS")
    return issues


@dataclass
class ToolReceipt:
    """Durable record of one deterministic tool invocation (plan layer E)."""

    tool: str
    command: str
    inputs: Dict[str, Any] = field(default_factory=dict)
    output_paths: List[str] = field(default_factory=list)
    exit_state: str = "ok"
    duration_ms: int = 0
    evidence_refs: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_json(self.to_dict())


def validate_tool_receipt(receipt: Any) -> List[str]:
    issues: List[str] = []
    if not isinstance(receipt, dict):
        return ["tool receipt must be an object"]
    if not str(receipt.get("tool") or "").strip():
        issues.append("tool receipt missing tool")
    if not str(receipt.get("command") or "").strip():
        issues.append("tool receipt missing command")
    _require_str_list(receipt.get("output_paths"), "output_paths", issues)
    if receipt.get("exit_state") is not None and not isinstance(receipt.get("exit_state"), str):
        issues.append("tool receipt exit_state must be a string")
    _require_str_list(receipt.get("evidence_refs"), "evidence_refs", issues)
    return issues


@dataclass
class TaskSpec:
    """One typed task-graph node (plan layer C)."""

    task_id: str
    task_type: str
    domain: str
    parent_id: str = ""
    mission_id: str = ""
    title: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)
    expected_artifacts: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    priority: int = 5
    model_profile: str = "balanced"
    retry_policy: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 900
    status: str = TASK_PENDING
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_json(self.to_dict())


def validate_task_spec(spec: Any) -> List[str]:
    issues: List[str] = []
    if not isinstance(spec, dict):
        return ["task spec must be an object"]
    if not str(spec.get("task_id") or "").strip():
        issues.append("task spec missing task_id")
    if spec.get("task_type") not in TASK_TYPES:
        issues.append(f"task type {spec.get('task_type')!r} not in TASK_TYPES")
    if spec.get("domain") not in TASK_DOMAINS:
        issues.append(f"task domain {spec.get('domain')!r} not in TASK_DOMAINS")
    if spec.get("status") not in TASK_STATUSES:
        issues.append(f"task status {spec.get('status')!r} not in TASK_STATUSES")
    profile = spec.get("model_profile")
    if profile is not None and profile not in MODEL_PROFILES:
        issues.append(f"model profile {profile!r} not in MODEL_PROFILES")
    _require_str_list(spec.get("dependencies"), "dependencies", issues)
    _require_str_list(spec.get("expected_artifacts"), "expected_artifacts", issues)
    prio = spec.get("priority")
    if prio is not None and (not isinstance(prio, int) or not 0 <= prio <= 10):
        issues.append("task priority must be an int in [0, 10]")
    return issues


@dataclass
class TaskResult:
    """What a lane returns for one TaskSpec (plan layer D contract)."""

    task_id: str
    agent_role: str
    status: str
    summary: str = ""
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    lead_refs: List[str] = field(default_factory=list)
    open_leads: List[str] = field(default_factory=list)
    artifact_refs: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    tool_receipts: List[Dict[str, Any]] = field(default_factory=list)
    mcp_bindings_used: List[str] = field(default_factory=list)
    next_tasks: List[Dict[str, Any]] = field(default_factory=list)
    model: str = ""
    prompt_hash: str = ""
    response_hash: str = ""
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return sha256_json(self.to_dict())


_INSIGHT_WORDS = (
    "insight", "anomaly", "hypothesis", "lead", "signal", "pattern",
    "differential", "suspicious", "interesting", "finding", "indicates",
    "suggests", "possible", "potential", "likely vulnerable", "looks like",
)


def validate_task_result(result: Any) -> List[str]:
    """Strict validation. Returns a list of issue strings (empty = valid).

    Enforces the plan's structural mandates:
      * R1 (5.5): an insight without a lead ref is malformed.
      * R6 (5.5): a terminal result cannot hold open leads.
      * 4.5: browser/burp MCP use must be recorded.
      * 5.6 anti-stalling: completed results need tool calls or evidence.
    """
    issues: List[str] = []
    if not isinstance(result, dict):
        return ["task result must be an object"]
    if not str(result.get("task_id") or "").strip():
        issues.append("task result missing task_id")
    if not str(result.get("agent_role") or "").strip():
        issues.append("task result missing agent_role")
    if result.get("status") not in RESULT_TERMINAL_STATUSES:
        issues.append(f"result status {result.get('status')!r} not in RESULT_TERMINAL_STATUSES")

    lead_refs = _require_str_list(result.get("lead_refs"), "lead_refs", issues)
    evidence_refs = _require_str_list(result.get("evidence_refs"), "evidence_refs", issues)
    mcp_used = _require_str_list(result.get("mcp_bindings_used"), "mcp_bindings_used", issues)

    for i, ref in enumerate(result.get("artifact_refs") or []):
        for sub in validate_artifact_ref(ref):
            issues.append(f"artifact_refs[{i}]: {sub}")
    for i, receipt in enumerate(result.get("tool_receipts") or []):
        for sub in validate_tool_receipt(receipt):
            issues.append(f"tool_receipts[{i}]: {sub}")

    # R1: every insight must reference a durable Lead.
    insights: List[str] = []
    for hyp in result.get("hypotheses") or []:
        if isinstance(hyp, dict) and hyp.get("text"):
            insights.append(str(hyp["text"]))
    summary = str(result.get("summary") or "")
    lowered = summary.lower()
    for word in _INSIGHT_WORDS:
        if word in lowered:
            insights.append(summary)
            break
    if insights and not lead_refs:
        issues.append(
            "R1 violation: result reports insights but carries no lead_refs - "
            "open a LeadSpec (tools/runtime/lead_protocol.py) before returning"
        )

    # R6: terminal results cannot hold open leads.
    open_leads = _require_str_list(result.get("open_leads"), "open_leads", issues)
    if open_leads and result.get("status") == RESULT_COMPLETED:
        issues.append(
            "R6 violation: completed result still holds open leads "
            f"({', '.join(open_leads)}) - use status agent_partial or close the leads"
        )

    # Pre-flight: MCP-backed work must be attributed.
    blob = json.dumps(result.get("tool_receipts") or [], default=str).lower()
    mentions_mcp = ("mcp" in blob) or ("browser" in blob) or ("burp" in blob)
    if mentions_mcp and not mcp_used:
        issues.append(
            "pre-flight violation: tool receipts reference browser/burp MCP work "
            "but mcp_bindings_used is empty"
        )

    # Anti-stalling (5.6): completed prose-only results are malformed.
    if result.get("status") == RESULT_COMPLETED:
        has_tool_calls = bool(result.get("tool_receipts"))
        if not has_tool_calls and not evidence_refs and not result.get("artifact_refs"):
            issues.append(
                "anti-stalling violation: completed result has zero tool receipts "
                "and zero evidence/artifact refs - prose-only work is rejected"
            )

    for key in ("prompt_hash", "response_hash"):
        val = result.get(key)
        if val and not re.fullmatch(r"[0-9a-f]{8,64}", str(val)):
            issues.append(f"{key} must be 8-64 hex chars")
    return issues


@dataclass
class MissionSpec:
    """Normalized operator mission (plan layer B).

    Built on tools/harness_command.parse_invocation - the existing NL intake
    parser - plus the target_intake provenance record (a record, not a gate)
    and the mission budget.
    """

    mission_id: str
    target: str
    objective: str = ""
    domains: List[str] = field(default_factory=list)
    operation_profile: str = "research"
    model_profile: str = "balanced"
    budget: Dict[str, Any] = field(default_factory=dict)
    intake_record: Dict[str, Any] = field(default_factory=dict)
    preflight_manifest_ref: Dict[str, Any] = field(default_factory=dict)
    source_invocation: str = ""
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        """Deterministic digest for dedup (plan lever P6): excludes created_at."""
        payload = {k: v for k, v in self.to_dict().items() if k != "created_at"}
        return sha256_json(payload)


def validate_mission_spec(mission: Any) -> List[str]:
    issues: List[str] = []
    if not isinstance(mission, dict):
        return ["mission spec must be an object"]
    if not str(mission.get("mission_id") or "").strip():
        issues.append("mission spec missing mission_id")
    if not str(mission.get("target") or "").strip():
        issues.append("mission spec missing target")
    domains = mission.get("domains") or []
    if not isinstance(domains, (list, tuple)):
        issues.append("mission domains must be a list")
    else:
        for d in domains:
            if d not in TASK_DOMAINS:
                issues.append(f"mission domain {d!r} not in TASK_DOMAINS")
    profile = mission.get("model_profile")
    if profile is not None and profile not in MODEL_PROFILES:
        issues.append(f"mission model profile {profile!r} not in MODEL_PROFILES")
    budget = mission.get("budget") or {}
    if not isinstance(budget, dict):
        issues.append("mission budget must be an object")
    else:
        for key in ("max_agents", "max_parallel_tasks", "max_runtime_seconds"):
            val = budget.get(key)
            if val is not None and (not isinstance(val, int) or val <= 0):
                issues.append(f"budget.{key} must be a positive int")
    ref = mission.get("preflight_manifest_ref")
    if ref and validate_artifact_ref(ref):
        issues.extend("preflight_manifest_ref: " + s for s in validate_artifact_ref(ref))
    return issues


# ---------------------------------------------------------------------------
# Mission intake - composition over the existing parser
# ---------------------------------------------------------------------------

_DEFAULT_BUDGET = {
    "max_agents": 12,
    "max_parallel_tasks": 8,
    "max_runtime_seconds": 3600,
}


def parse_mission(text: str, *, project_root: Optional[str] = None) -> MissionSpec:
    """Parse a conversational invocation into a MissionSpec.

    Delegates to tools/harness_command.parse_invocation (the existing intake
    parser) and attaches the operator's target_intake provenance record when
    one exists on disk. Records, never gates.
    """
    try:
        from tools.harness_command import parse_invocation
    except ImportError:
        from harness_command import parse_invocation  # type: ignore

    plan = parse_invocation(text)
    if not isinstance(plan, dict):
        plan = {"raw": str(plan)}

    target = ""
    for key in ("target", "target_id", "target_identifier"):
        if plan.get(key):
            target = str(plan[key])
            break

    domains: List[str] = []
    for key in ("domains", "modes"):
        raw = plan.get(key)
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, (list, tuple)):
            domains = [str(d) for d in raw]
            break
    if not domains and plan.get("mode"):
        domains = [str(plan["mode"])]
    # The intake parser emits sentinels like "all_applicable" when no mode flag
    # is given - that means "no domain restriction", not a domain.  Keep only
    # real domains in the validated field; the raw plan stays in source_invocation.
    domains = [d for d in domains if d in TASK_DOMAINS]

    mission_id = "bw-" + sha256_json({"t": target, "o": text})[:12]

    intake_record: Dict[str, Any] = {}
    try:
        root = Path(project_root) if project_root else Path.cwd()
        intake_path = root / "state" / "intake" / "latest.json"
        if intake_path.is_file():
            intake_record = json.loads(intake_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        intake_record = {}

    spec = MissionSpec(
        mission_id=mission_id,
        target=target,
        objective=str(plan.get("objective") or plan.get("request") or text)[:2000],
        domains=domains,
        model_profile=str(plan.get("model_profile") or "balanced"),
        budget=dict(_DEFAULT_BUDGET),
        intake_record=intake_record,
        source_invocation=text[:2000],
    )
    issues = validate_mission_spec(spec.to_dict())
    if issues:
        raise ContractViolation(issues)
    return spec


# ---------------------------------------------------------------------------
# Durable state plane helpers (plan lever P5: append-only JSONL)
# ---------------------------------------------------------------------------


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    """Atomically append one JSON line (the only write pattern the plan allows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True, default=str)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def result_log_path(mission_id: str, *, project_root: Optional[str] = None) -> Path:
    return Path(runtime_path("state", "orchestrator", mission_id, "results.jsonl",
                             root=project_root))


def record_task_result(result: TaskResult, *, project_root: Optional[str] = None) -> List[str]:
    """Validate, then durably record a TaskResult. Returns validation issues."""
    issues = validate_task_result(result.to_dict())
    if issues:
        return issues
    append_jsonl(result_log_path(result.task_id, project_root=project_root),
                 result.to_dict())
    return []


# ---------------------------------------------------------------------------
# CLI (smoke / self-test)
# ---------------------------------------------------------------------------


def main() -> int:
    sample = TaskResult(
        task_id="t-1", agent_role="web-api", status=RESULT_COMPLETED,
        summary="probe executed", evidence_refs=["evid-1"],
        tool_receipts=[ToolReceipt(tool="live_executor", command="execute_probe").to_dict()],
    )
    issues = validate_task_result(sample.to_dict())
    print(json.dumps({"schema": SCHEMA, "self_test": "ok" if not issues else issues}))
    return 0 if not issues else 1


if __name__ == "__main__":
    raise SystemExit(main())

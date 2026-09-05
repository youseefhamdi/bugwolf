#!/usr/bin/env python3
"""BugWolf orchestrator scheduler (plan v2, sections 3-4: task graph + lanes).

Turns a MissionSpec into a durable task graph and drives it to completion:

  * plan_mission        - builds the graph: a mandatory ``preflight`` gate
                          task first (plan section 4.5 -- no mission work of
                          any kind before pre-flight completes), then the
                          lane roots for the mission's domains, each with
                          model routing hints attached (plan lever P1).
  * runnable / dispatch - parallel dispatch within the mission budget
                          (max_parallel_tasks), dependencies and the
                          pre-flight gate respected.
  * record / tick       - task completion flows through the contracts
                          validators (R1/R6, anti-stalling) and the
                          append-only JSONL state plane (lever P5).
  * resume              - every mutation is persisted to
                          ``state/orchestrator/<mission>/graph.json``; a
                          killed process resumes with zero re-run of
                          finished work, and OPEN leads re-dispatch first
                          (plan R6: a context reset can never bury a lead).

Ordering rules (plan section 5.4 attack-first priority):
  priority field ascending (1 = first), then lead-carrying tasks, then
  FIFO by creation order.  No fair-share queuing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import threading
from contextlib import contextmanager

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility
    fcntl = None
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import workspace_root

try:  # single source of truth for statuses/domains
    from tools.runtime.contracts import (
        ContractViolation, MissionSpec, TaskSpec,
        TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED, TASK_FAILED,
        TASK_CANCELLED, TASK_BUDGET_EXHAUSTED, TASK_STATUSES,
        validate_task_spec, validate_task_result,
        result_log_path, append_jsonl,
    )
except ImportError:  # pragma: no cover - installed-skill fallback
    from contracts import (  # type: ignore
        ContractViolation, MissionSpec, TaskSpec,
        TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED, TASK_FAILED,
        TASK_CANCELLED, TASK_BUDGET_EXHAUSTED, TASK_STATUSES,
        validate_task_spec, validate_task_result,
        result_log_path, append_jsonl,
    )

SCHEMA = "bugwolf-scheduler/v1"
BUDGET_SCHEMA = "bugwolf-budget/v1"


class BudgetLedger:
    """Mission-wide, durable accounting for scheduler work.

    The ledger tracks reservations rather than trusting independent worker
    counters.  A reservation is made before dispatch and reconciled after the
    result, so parallel workers cannot each spend the full mission allowance.
    """

    def __init__(self, mission_id: str, budget: Optional[Dict[str, Any]] = None,
                 *, project_root: Optional[str] = None):
        self.mission_id = mission_id
        self.budget = dict(budget or {})
        self.project_root = project_root
        self.root = workspace_root(project_root) / "state" / "orchestrator" / mission_id
        self.path = self.root / "budget.json"
        self._lock_path = self.root / "budget.lock"
        self._mutex = threading.RLock()
        self.state = self._load()

    @contextmanager
    def _file_lock(self):
        """Serialize budget read-modify-write across worker processes."""
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self._lock_path.open("a+", encoding="utf-8")
        try:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def _load(self) -> Dict[str, Any]:
        if not self.path.is_file():
            return {"schema": BUDGET_SCHEMA, "mission_id": self.mission_id,
                    "reserved_tasks": 0, "completed_tasks": 0,
                    "failed_tasks": 0, "cancelled_tasks": 0,
                    "reserved_runtime_seconds": 0,
                    "runtime_seconds_used": 0.0,
                    "runtime_overrun": False,
                    "reserved_task_ids": [], "reconciled_task_ids": [],
                    "events": []}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if value.get("mission_id") != self.mission_id:
                raise ValueError("budget mission mismatch")
            value.setdefault("reserved_task_ids", [])
            value.setdefault("reconciled_task_ids", [])
            value.setdefault("runtime_seconds_used", 0.0)
            value.setdefault("runtime_overrun", False)
            return value
        except (OSError, ValueError, json.JSONDecodeError):
            raise ContractViolation(["budget ledger is missing, corrupt, or belongs to another mission"])

    def _save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(self.state, indent=2, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(self.path)

    def _max_tasks(self) -> int:
        """Return the explicit mission task cap, if configured.

        ``max_agents`` limits roster/concurrency; it is not a total task
        budget.  Falling back to it caused larger but valid graphs to fail
        after the first few lanes, so task count and parallelism remain
        independent controls.
        """
        return int(self.budget.get("max_tasks") or 0)

    def reserve(self, task_id: str, *, runtime_seconds: int = 0) -> None:
        """Reserve one task slot before side effects; raise if exhausted."""
        with self._mutex, self._file_lock():
            # Reload while holding the process lock so a second scheduler
            # process cannot reserve against stale state.
            self.state = self._load()
            if task_id in self.state["reserved_task_ids"]:
                return
            max_tasks = self._max_tasks()
            if max_tasks and self.state["reserved_tasks"] >= max_tasks:
                raise ContractViolation([f"budget exhausted: max tasks {max_tasks} reached"])
            max_runtime = int(self.budget.get("max_runtime_seconds") or 0)
            if max_runtime and self.state.get("runtime_seconds_used", 0.0) >= max_runtime:
                raise ContractViolation(["budget exhausted: runtime limit already consumed"])
            if max_runtime and (self.state["reserved_runtime_seconds"] + runtime_seconds > max_runtime):
                raise ContractViolation(["budget exhausted: runtime reservation exceeds mission limit"])
            self.state["reserved_tasks"] += 1
            self.state["reserved_task_ids"].append(task_id)
            self.state["reserved_runtime_seconds"] += max(0, int(runtime_seconds))
            self.state["events"].append({"event": "reserved", "task_id": task_id,
                                          "runtime_seconds": max(0, int(runtime_seconds))})
            self._save()

    def reconcile(self, task_id: str, result_status: str,
                  *, runtime_seconds: float = 0.0) -> None:
        with self._mutex, self._file_lock():
            self.state = self._load()
            if task_id in self.state["reconciled_task_ids"]:
                return
            self.state["reconciled_task_ids"].append(task_id)
            used = max(0.0, float(runtime_seconds))
            self.state["runtime_seconds_used"] += used
            max_runtime = int(self.budget.get("max_runtime_seconds") or 0)
            if max_runtime and self.state["runtime_seconds_used"] > max_runtime:
                self.state["runtime_overrun"] = True
            self.state["events"].append({"event": "reconciled", "task_id": task_id,
                                          "status": result_status,
                                          "runtime_seconds": round(used, 4)})
            if result_status in ("completed", "agent_partial"):
                self.state["completed_tasks"] += 1
            elif result_status in ("cancelled",):
                self.state["cancelled_tasks"] += 1
            else:
                self.state["failed_tasks"] += 1
            self._save()

    def snapshot(self) -> Dict[str, Any]:
        return dict(self.state)


def task_fingerprint(spec: Dict[str, Any]) -> str:
    """P6: stable task identity used for dedup-before-dispatch.

    Everything semantic (type, domain, title, inputs, model profile) is
    included; volatile fields (task_id, status, dependencies, timestamps)
    are excluded.  Same fingerprint + PENDING/ACTIVE = same work.
    """
    payload = {
        "task_type": spec.get("task_type"),
        "domain": spec.get("domain"),
        "title": spec.get("title"),
        "inputs": spec.get("inputs") or {},
        "model_profile": spec.get("model_profile"),
    }
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()

PREFLIGHT_TASK_ID = "pf-000"
PREFLIGHT_DOMAIN = "preflight"

# Lane roots per domain (plan section 4.3 lanes, registry-driven).  The lane
# executor binds these to real engines; the scheduler only needs ids.
_LANE_ROOT_TITLES = {
    "recon": "Recon lane: attack-surface inventory (hidden-endpoint engine)",
    "web": "Web lane: endpoint testing per surface model",
    "web_api": "Web/API lane: contract-driven endpoint testing",
    "auth": "Auth lane: session/privilege boundaries (A/B/C matrix)",
    "business_logic": "Business-logic lane: money/quantity/TOCTOU matrices",
    "smart_contract": "Web3 lane: multi-pass contract review",
    "cloud_cicd": "Cloud/CI-CD lane: IAM and pipeline exposure",
    "llm_ai": "LLM lane: prompt/injection/agentic surfaces",
    "mobile": "Mobile lane: deep links, storage, shadow APIs",
    "fuzz": "Fuzz lane: grammar-family payload scheduling",
    "verify": "Verify lane: independent refutation/replay",
    "chain": "Chain lane: cross-surface escalation assembly",
    "report": "Report lane: findings assembly with provenance",
    "triage": "Triage lane: candidate classification",
}


# ---------------------------------------------------------------------------
# Events (advisory; never raises)
# ---------------------------------------------------------------------------


def _publish(target: str, event_type: str, payload: Dict[str, Any]) -> None:
    try:
        from tools.core.signal_bus import SignalBus
        SignalBus(target).publish(event_type, "scheduler", payload)
    except Exception:  # noqa: BLE001 - bus is advisory, never a gate
        pass


# ---------------------------------------------------------------------------
# Graph node
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    spec: Dict[str, Any]           # validated TaskSpec dict
    unmet: List[str] = field(default_factory=list)   # dependencies not done
    lead_ids: List[str] = field(default_factory=list)  # re-dispatch priority
    seq: int = 0                   # creation order (FIFO tie-break)
    fingerprint: str = ""         # P6 dedup key (task identity sans id/status)

    @property
    def task_id(self) -> str:
        return self.spec["task_id"]

    @property
    def status(self) -> str:
        return self.spec["status"]

    def to_dict(self) -> Dict[str, Any]:
        return {"spec": self.spec, "unmet": self.unmet,
                "lead_ids": self.lead_ids, "seq": self.seq,
                "fingerprint": self.fingerprint}


def _redact_mission_credentials(mission_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Redact account credential values for persistence (product audit).

    ``MissionSpec.accounts`` entries carry operator passwords/tokens for
    live lane binding.  On disk each value becomes ``__redacted__:true``;
    :meth:`Scheduler.load` restores the placeholder so a resumed mission
    fails *safe*: the auth lane degrades to anon observations and logs a
    blocker instead of silently running with dead credentials.
    """
    accounts = mission_dict.get("accounts")
    if not accounts:
        return mission_dict
    redacted: List[Dict[str, Any]] = []
    for spec in accounts:
        if not isinstance(spec, dict):
            redacted.append(spec)
            continue
        scrubbed = dict(spec)
        for key in Scheduler._CREDENTIAL_FIELDS:
            if scrubbed.get(key):
                scrubbed[key] = "__redacted__"
        redacted.append(scrubbed)
    out = dict(mission_dict)
    out["accounts"] = redacted
    return out


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class Scheduler:
    """Durable, resumable task-graph scheduler for one mission."""

    # Mission fields that hold operator credentials: persisted as boolean
    # presence markers, never values (product audit fix).
    _CREDENTIAL_FIELDS = ("password", "token")

    def __init__(self, mission: MissionSpec, *, project_root: Optional[str] = None):
        self.mission = mission
        self.project_root = project_root
        self._graph_dir = workspace_root(project_root) / "state" / "orchestrator" / mission.mission_id
        self._graph_path = self._graph_dir / "graph.json"
        self._nodes: Dict[str, GraphNode] = {}
        self._seq = 0
        self.dedup_skipped = 0  # P6: duplicate dispatches avoided
        self.budget = BudgetLedger(mission.mission_id, mission.budget,
                                   project_root=project_root)

    # -- persistence --------------------------------------------------------

    def graph_path(self) -> Path:
        return self._graph_path

    def save(self) -> None:
        self._graph_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA,
            # Credential hygiene (product audit): account passwords/tokens
            # must never reach disk.  Redact at the persistence boundary;
            # the in-memory spec keeps them so live lanes still bind.
            "mission": _redact_mission_credentials(self.mission.to_dict()),
            "nodes": {tid: node.to_dict() for tid, node in self._nodes.items()},
        }
        tmp = self._graph_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str),
                       encoding="utf-8")
        tmp.replace(self._graph_path)  # atomic publish

    @classmethod
    def load(cls, mission_id: str, *, project_root: Optional[str] = None) -> "Scheduler":
        """Resume a mission from disk (zero re-run of finished work)."""
        path = (workspace_root(project_root) / "state" / "orchestrator"
                / mission_id / "graph.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        mission = MissionSpec(**raw["mission"])
        sched = cls(mission, project_root=project_root)
        for tid, node in raw["nodes"].items():
            sched._nodes[tid] = GraphNode(
                spec=node["spec"], unmet=list(node.get("unmet") or []),
                lead_ids=list(node.get("lead_ids") or []),
                seq=int(node.get("seq") or 0),
                fingerprint=str(node.get("fingerprint") or ""))
            sched._seq = max(sched._seq, int(node.get("seq") or 0))
        return sched

    # -- planning -----------------------------------------------------------

    def _add(self, spec_dict: Dict[str, Any], *, deps: Optional[List[str]] = None,
             lead_ids: Optional[List[str]] = None) -> GraphNode:
        # The graph is the only dependency authority.  ``deps`` is retained
        # only as a compatibility argument; canonical callers put the same
        # values in TaskSpec.dependencies and we derive readiness from there.
        issues = validate_task_spec(spec_dict)
        if issues:
            raise ContractViolation(issues)
        declared_deps = list(spec_dict.get("dependencies") or [])
        if deps:
            declared_deps = list(dict.fromkeys(declared_deps + list(deps)))
            spec_dict["dependencies"] = declared_deps
        missing = [dep for dep in declared_deps if dep not in self._nodes
                   and dep != spec_dict.get("task_id")]
        if missing:
            raise ContractViolation([
                f"task {spec_dict.get('task_id')!r} references missing dependencies: "
                + ", ".join(missing)
            ])
        # P6 dedup-before-dispatch: a task identical to an existing
        # PENDING/ACTIVE node (same fingerprint) is not re-created -- the
        # caller gets the existing node, so duplicate model work can never
        # be scheduled.  DONE/BLOCKED nodes do not dedup (re-work may be
        # intentional after a blocker).
        fingerprint = task_fingerprint(spec_dict)
        for existing in self._nodes.values():
            if (existing.fingerprint == fingerprint
                    and existing.status in (TASK_PENDING, TASK_ACTIVE)):
                self.dedup_skipped += 1
                return existing
        self._seq += 1
        node = GraphNode(spec=dict(spec_dict), unmet=declared_deps,
                         lead_ids=list(lead_ids or []), seq=self._seq)
        node.fingerprint = fingerprint
        self._nodes[node.task_id] = node
        return node

    def plan_mission(self) -> List[Dict[str, Any]]:
        """Build the initial graph: preflight gate + one root per domain."""
        specs: List[Dict[str, Any]] = []

        pre = TaskSpec(
            task_id=PREFLIGHT_TASK_ID,
            task_type="preflight",
            domain=PREFLIGHT_DOMAIN,
            mission_id=self.mission.mission_id,
            title="Mandatory pre-flight: capability inventory + MCP checks (PF1-PF4)",
            priority=0,
            model_profile="deterministic",
            timeout_seconds=120,
        )
        specs.append(pre.to_dict())

        domains = self.mission.domains or ["recon"]
        for i, domain in enumerate(domains, start=1):
            if domain == PREFLIGHT_DOMAIN:
                continue
            title = _LANE_ROOT_TITLES.get(domain, f"{domain} lane root")
            specs.append(TaskSpec(
                task_id=f"lane-{i:03d}-{domain}",
                task_type="dispatch",
                domain=domain,
                mission_id=self.mission.mission_id,
                title=title,
                dependencies=[PREFLIGHT_TASK_ID],
                priority=i,
            ).to_dict())

        for spec_dict in specs:
            domain = str(spec_dict.get("domain") or "")
            try:
                from tools.runtime.capabilities import get as get_capability
                capability = get_capability(domain)
            except Exception:  # registry failure is itself explicit metadata
                capability = None
            if capability is None:
                spec_dict.setdefault("inputs", {})["capability_status"] = "unknown"
                spec_dict["inputs"]["capability_reason"] = "no runtime capability registry entry"
            else:
                spec_dict.setdefault("inputs", {})["capability_status"] = capability.status
                if capability.limitation:
                    spec_dict["inputs"]["capability_reason"] = capability.limitation
            node = self._add(spec_dict)
            _publish(self.mission.target, "TASK_PLANNED",
                     {"task_id": node.task_id, "domain": node.spec["domain"],
                      "mission_id": self.mission.mission_id})
        self.save()
        return [n.spec for n in self._nodes.values()]

    # -- routing hints (plan lever P1) --------------------------------------

    def attach_agent_bindings(self) -> Dict[str, str]:
        """Bind each lane root to its specialized subagent (registry-backed).

        Writes ``inputs.agent_role`` / ``inputs.harness_role`` / tier
        preferences onto every dispatch node so the harness dispatches the
        lane to ``bugwolf:<role>`` instead of the bare session.  Selection
        is deterministic per domain; unknown domains degrade to the
        web-api generalist per the registry's fallback rules.
        """
        try:
            from tools.core.agent_registry import AgentRegistry
            registry = AgentRegistry()
        except Exception:  # noqa: BLE001 - bindings are advisory
            return {}
        bindings: Dict[str, str] = {}
        for node in self._nodes.values():
            if node.spec.get("task_type") != "dispatch":
                continue
            domain = str(node.spec.get("domain") or "")
            try:
                spec = registry.select(domain=domain, lane="hunt")
            except Exception:  # noqa: BLE001
                continue
            routing = node.spec.setdefault("inputs", {})
            routing["agent_role"] = spec.role
            routing["harness_role"] = spec.harness_role
            routing["tier_affinity"] = spec.tier_affinity
            bindings[node.task_id] = spec.role
        if bindings:
            self.save()
        return bindings

    def attach_routing(self, task_id: str) -> Dict[str, Any]:
        """Attach advisory model-routing hints to a task's inputs."""
        node = self._nodes[task_id]
        try:
            from tools.core.model_router import route, attach_hint
        except ImportError:  # pragma: no cover
            return {}
        decision = route(
            str(node.spec.get("title") or ""),
            task_id=task_id,
            available_tools=list(node.spec.get("inputs", {}).get("tools") or []),
            context={"current_state": node.spec.get("status", "")},
        )
        unit = {"objective": node.spec.get("title", ""),
                "bug_class": node.spec.get("domain", ""), "context": {}}
        attach_hint(unit)
        node.spec["inputs"]["model_preference"] = unit["context"]["model_preference"]
        node.spec["inputs"]["model_tier"] = unit["context"]["model_tier"]
        node.spec["inputs"]["model_fallback_preference"] = unit["context"].get(
            "model_fallback_preference", "")
        return decision.to_dict()

    # -- dispatch -----------------------------------------------------------

    def runnable(self) -> List[GraphNode]:
        """Tasks whose deps are done, not active/done/blocked, gate open."""
        pre = self._nodes.get(PREFLIGHT_TASK_ID)
        gate_open = pre is not None and pre.status == TASK_DONE
        out: List[GraphNode] = []
        for node in self._nodes.values():
            if node.status != TASK_PENDING:
                continue
            if (node.task_id != PREFLIGHT_TASK_ID
                    and PREFLIGHT_TASK_ID in (node.spec.get("dependencies") or [])
                    and not gate_open):
                continue
            # Missing dependencies are a graph-integrity error, not an
            # implicit pass.  ``_add`` rejects them for new graphs; this
            # branch protects resumed/legacy graphs.
            if any(d not in self._nodes for d in node.unmet):
                continue
            if any(self._nodes[d].status != TASK_DONE for d in node.unmet):
                continue
            out.append(node)
        # Attack-first ordering: priority asc, lead-carrying first, FIFO.
        out.sort(key=lambda n: (n.spec.get("priority", 5),
                                0 if n.lead_ids else 1, n.seq))
        max_parallel = int((self.mission.budget or {}).get("max_parallel_tasks") or 8)
        active = sum(1 for n in self._nodes.values() if n.status == TASK_ACTIVE)
        return out[: max(0, max_parallel - active)]

    def start(self, task_id: str) -> Dict[str, Any]:
        """Mark a task active only after graph and preflight barriers pass."""
        node = self._nodes[task_id]
        if node.status != TASK_PENDING:
            raise ContractViolation([f"task {task_id!r} is not pending"])
        if task_id != PREFLIGHT_TASK_ID:
            pre = self._nodes.get(PREFLIGHT_TASK_ID)
            if pre is None or pre.status != TASK_DONE:
                raise ContractViolation([
                    "preflight barrier: active work cannot start before "
                    "the preflight task is done"
                ])
        if any(dep not in self._nodes or self._nodes[dep].status != TASK_DONE
               for dep in node.unmet):
            raise ContractViolation([
                f"dependency barrier: task {task_id!r} has unmet dependencies"
            ])
        try:
            # Reserve the task slot before side effects.  A task timeout is a
            # ceiling, not guaranteed consumed runtime; reserving every full
            # timeout would reject valid missions whose aggregate runtime cap
            # is smaller than one worker timeout.  Actual duration is
            # reconciled when the result arrives.
            self.budget.reserve(task_id, runtime_seconds=0)
        except ContractViolation:
            node.spec["status"] = TASK_BUDGET_EXHAUSTED
            self.save()
            raise
        node.spec["status"] = TASK_ACTIVE
        node.spec.setdefault("inputs", {})["started_monotonic"] = time.monotonic()
        node.spec["inputs"]["started_at"] = time.time()
        decision = self.attach_routing(task_id)
        self.save()
        _publish(self.mission.target, "TASK_STARTED",
                 {"task_id": task_id, "mission_id": self.mission.mission_id,
                  "model_routing": decision})
        return decision

    def record_start_failure(self, task_id: str, issues: List[str]) -> List[str]:
        """Persist a dispatch-start failure without raising into the runner.

        Start failures happen before a worker result exists (for example, a
        budget reservation or policy barrier).  They still need a canonical
        mission result so dashboards, resume, and reports do not mistake an
        interrupted drain loop for a clean completion.
        """
        if task_id not in self._nodes:
            return [f"unknown task_id: {task_id}"]
        node = self._nodes[task_id]
        reasons = [str(issue) for issue in (issues or ["task dispatch start failed"])]
        budget_failure = any("budget" in issue.lower() for issue in reasons)
        result_status = "budget_exhausted" if budget_failure else "agent_failed"
        node.spec["status"] = (TASK_BUDGET_EXHAUSTED if budget_failure
                                else TASK_FAILED)
        node.spec.setdefault("inputs", {})["failure_reasons"] = reasons
        result = {
            "task_id": task_id,
            "mission_id": self.mission.mission_id,
            "attempt_id": f"{task_id}-start-failure-{int(time.time() * 1000)}",
            "agent_role": "scheduler",
            "status": result_status,
            "summary": "; ".join(reasons)[:1000],
            "tool_receipts": [{"tool": "scheduler", "command": "start",
                               "exit_state": result_status}],
            "evidence_refs": [],
            "mcp_bindings_used": [],
        }
        self.budget.reconcile(task_id, result_status)
        append_jsonl(self._results_path(), result)
        self.save()
        _publish(self.mission.target, "TASK_START_FAILED",
                 {"task_id": task_id, "mission_id": self.mission.mission_id,
                  "status": result_status, "issues": reasons})
        return reasons

    def mark_blocked(self, task_id: str, reason: str) -> None:
        node = self._nodes[task_id]
        node.spec["status"] = TASK_BLOCKED
        node.spec["inputs"]["blocked_reason"] = reason
        self.save()

    def reopen_blocked(self, connection: str) -> int:
        """PF4 auto-recovery: un-block tasks blocked on a restored connection."""
        reopened = 0
        for node in self._nodes.values():
            reason = str(node.spec.get("inputs", {}).get("blocked_reason") or "")
            if node.status == TASK_BLOCKED and connection in reason:
                node.spec["status"] = TASK_PENDING
                node.spec["inputs"]["blocked_reason"] = ""
                reopened += 1
        if reopened:
            self.save()
        return reopened

    # -- completion ---------------------------------------------------------

    def record(self, task_id: str, result: Dict[str, Any]) -> List[str]:
        """Record a TaskResult: contracts-validate, persist, update graph.

        Returns validation issues (empty = accepted).  Rejected results do
        not change task state -- the lane must fix and resubmit.
        Results append to the mission-scoped ``results.jsonl`` (plan lever
        P5: one append-only log per mission, every task in sequence).
        """
        if task_id not in self._nodes:
            return [f"unknown task_id: {task_id}"]
        # Bind result identity at the scheduler boundary.  Worker payloads
        # may omit mission_id for legacy compatibility, but they cannot claim
        # another mission or complete another task.
        canonical = dict(result)
        claimed_task = str(canonical.get("task_id") or task_id)
        if claimed_task != task_id:
            issues = [f"task result identity mismatch: expected {task_id}, got {claimed_task}"]
        else:
            canonical["task_id"] = task_id
            claimed_mission = str(canonical.get("mission_id") or self.mission.mission_id)
            issues = [] if claimed_mission == self.mission.mission_id else [
                "task result mission_id does not match scheduler mission"
            ]
            canonical["mission_id"] = claimed_mission
            canonical.setdefault("attempt_id", f"{task_id}-{int(time.time() * 1000)}")
            issues.extend(validate_task_result(canonical))
        if issues:
            append_jsonl(self._results_path(),
                         {"rejected": True, "issues": issues, "result": result,
                          "mission_id": self.mission.mission_id,
                          "task_id": task_id})
            # Once a worker has been dispatched, malformed output is a
            # terminal contract failure rather than an indefinitely ACTIVE
            # task.  Results rejected before start retain their original
            # state so callers can correct and resubmit safely.
            node = self._nodes[task_id]
            if node.status == TASK_ACTIVE:
                self.budget.reconcile(task_id, "agent_failed")
                node.spec["status"] = TASK_FAILED
                node.spec.setdefault("inputs", {})["failure_reasons"] = list(issues)
                self.save()
            return issues
        node = self._nodes[task_id]
        result = canonical
        result_status = str(result.get("status") or "")
        started = node.spec.get("inputs", {}).get("started_at")
        try:
            runtime_seconds = max(0.0, time.time() - float(started)) if started else 0.0
        except (TypeError, ValueError):
            runtime_seconds = 0.0
        result["runtime_seconds"] = round(runtime_seconds, 4)
        self.budget.reconcile(task_id, result_status,
                              runtime_seconds=runtime_seconds)
        terminal_map = {
            "blocked": TASK_BLOCKED,
            "agent_failed": TASK_FAILED,
            "cancelled": TASK_CANCELLED,
            "budget_exhausted": TASK_BUDGET_EXHAUSTED,
        }
        node.spec["status"] = terminal_map.get(result_status, TASK_DONE)
        node.lead_ids = list(result.get("open_leads") or [])
        append_jsonl(self._results_path(), result)
        self.save()
        _publish(self.mission.target, "TASK_COMPLETED",
                 {"task_id": task_id, "mission_id": self.mission.mission_id,
                  "status": result.get("status"),
                  "open_leads": node.lead_ids})
        return []

    def _results_path(self) -> Path:
        return self._graph_dir / "results.jsonl"

    def record_preflight(self, manifest: Dict[str, Any], *, strict: bool = False) -> List[str]:
        """Complete the pre-flight gate task from a preflight manifest.

        ``strict`` is used by live MissionRunner paths to bind the receipt to
        target, mission, and execution profile.  Legacy offline/perf callers
        may supply the historical minimal digest-only fixture.
        """
        if PREFLIGHT_TASK_ID not in self._nodes:
            return ["preflight task is not present in the mission graph"]
        sha = str(manifest.get("sha256", ""))
        if strict:
            try:
                from tools.runtime.preflight import validate_manifest_for_mission
                receipt_issues = validate_manifest_for_mission(
                    manifest, target=self.mission.target,
                    mission_id=self.mission.mission_id,
                    operation_profile=getattr(self.mission, "operation_profile", "governed"))
            except Exception as exc:  # malformed receipt is a hard failure
                receipt_issues = [f"preflight receipt validation error: {exc}"]
            if receipt_issues:
                return receipt_issues
            try:
                from tools.runtime.preflight import manifest_path
                receipt_path = manifest_path(project_root=self.project_root)
                if not receipt_path.is_file():
                    return ["preflight manifest artifact is missing"]
                persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
                persisted_issues = validate_manifest_for_mission(
                    persisted, target=self.mission.target,
                    mission_id=self.mission.mission_id,
                    operation_profile=getattr(self.mission, "operation_profile", "governed"))
                if persisted_issues or persisted.get("sha256") != sha:
                    return ["persisted preflight manifest does not match receipt"]
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return [f"preflight manifest artifact unreadable: {exc}"]
        try:
            self.budget.reserve(PREFLIGHT_TASK_ID, runtime_seconds=0)
        except ContractViolation as exc:
            return list(exc.issues)
        self._nodes[PREFLIGHT_TASK_ID].spec["inputs"]["manifest_sha256"] = sha
        self._nodes[PREFLIGHT_TASK_ID].spec["inputs"]["digest"] = \
            manifest.get("digest", "")
        try:
            from tools.runtime.preflight import manifest_path
            mpath = str(manifest_path(project_root=self.project_root))
        except Exception:  # noqa: BLE001 - path is advisory metadata
            mpath = "state/preflight/manifest.json"
        return self.record(PREFLIGHT_TASK_ID, {
            "task_id": PREFLIGHT_TASK_ID,
            "agent_role": "preflight",
            "status": "completed",
            "summary": manifest.get("digest", ""),
            "artifact_refs": [{"path": mpath, "kind": "preflight",
                               "sha256": sha,
                               "producer_task": PREFLIGHT_TASK_ID}],
            "evidence_refs": [sha] if sha else [],
            "tool_receipts": [{"tool": "preflight", "command": "run_preflight",
                               "exit_state": "ok"}],
            "mcp_bindings_used": [],  # checks are observations, not usage
        })

    # -- resume (plan R6) ---------------------------------------------------

    def resume(self) -> Dict[str, Any]:
        """Resume after restart: leads first, never re-run finished work.

        ``lead_first`` lists queued (pending/blocked) lead-carrying tasks --
        they jump the dispatch queue (R6).  ``open_leads`` lists every open
        lead in the graph including ones held by finished partial tasks
        (visibility: the escalation lane consumes them next).
        """
        pending = [n for n in self._nodes.values() if n.status == TASK_PENDING]
        active = [n for n in self._nodes.values() if n.status == TASK_ACTIVE]
        lead_tasks = [n for n in pending if n.lead_ids]
        blocked_leads = [n.task_id for n in self._nodes.values()
                         if n.status == TASK_BLOCKED and n.lead_ids]
        open_leads = sorted({lid for n in self._nodes.values()
                             for lid in n.lead_ids})
        return {
            "mission_id": self.mission.mission_id,
            "total": len(self._nodes),
            "done": sum(1 for n in self._nodes.values() if n.status == TASK_DONE),
            "active": [n.task_id for n in active],
            "lead_first": [n.task_id for n in lead_tasks],
            "blocked_leads": blocked_leads,
            "open_leads": open_leads,
            "runnable_next": [n.task_id for n in self.runnable()],
        }

    # -- introspection ------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for node in self._nodes.values():
            counts[node.status] = counts.get(node.status, 0) + 1
        return {
            "mission_id": self.mission.mission_id,
            "target": self.mission.target,
            "operation_profile": getattr(self.mission, "operation_profile", "governed"),
            "nodes": len(self._nodes),
            "counts": counts,
            "dedup_skipped": self.dedup_skipped,
            "budget": self.budget.snapshot(),
            "graph_path": str(self._graph_path),
        }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf orchestrator scheduler (plan/inspect a mission graph)")
    parser.add_argument("--target", default="demo.example.com")
    parser.add_argument("--mission-id", default="bw-demo")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    if args.status:
        path = (workspace_root() / "state" / "orchestrator"
                / args.mission_id / "graph.json")
        if not path.is_file():
            print(f"no such mission: {args.mission_id} "
                  f"(no graph at {path})")
            return 2
        sched = Scheduler.load(args.mission_id)
        print(json.dumps(sched.status(), indent=2))
        return 0
    mission = MissionSpec(mission_id=args.mission_id, target=args.target,
                          domains=["recon", "web"])
    sched = Scheduler(mission)
    sched.plan_mission()
    print(json.dumps(sched.status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

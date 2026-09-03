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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import workspace_root

try:  # single source of truth for statuses/domains
    from tools.runtime.contracts import (
        ContractViolation, MissionSpec, TaskSpec,
        TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED, TASK_STATUSES,
        validate_task_spec, validate_task_result,
        result_log_path, append_jsonl,
    )
except ImportError:  # pragma: no cover - installed-skill fallback
    from contracts import (  # type: ignore
        ContractViolation, MissionSpec, TaskSpec,
        TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED, TASK_STATUSES,
        validate_task_spec, validate_task_result,
        result_log_path, append_jsonl,
    )

SCHEMA = "bugwolf-scheduler/v1"


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
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

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


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


class Scheduler:
    """Durable, resumable task-graph scheduler for one mission."""

    def __init__(self, mission: MissionSpec, *, project_root: Optional[str] = None):
        self.mission = mission
        self.project_root = project_root
        self._graph_dir = workspace_root(project_root) / "state" / "orchestrator" / mission.mission_id
        self._graph_path = self._graph_dir / "graph.json"
        self._nodes: Dict[str, GraphNode] = {}
        self._seq = 0
        self.dedup_skipped = 0  # P6: duplicate dispatches avoided

    # -- persistence --------------------------------------------------------

    def graph_path(self) -> Path:
        return self._graph_path

    def save(self) -> None:
        self._graph_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA,
            "mission": self.mission.to_dict(),
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
        issues = validate_task_spec(spec_dict)
        if issues:
            raise ContractViolation(issues)
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
        node = GraphNode(spec=dict(spec_dict), unmet=list(deps or []),
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
            node = self._add(spec_dict)
            _publish(self.mission.target, "TASK_PLANNED",
                     {"task_id": node.task_id, "domain": node.spec["domain"],
                      "mission_id": self.mission.mission_id})
        self.save()
        return [n.spec for n in self._nodes.values()]

    # -- routing hints (plan lever P1) --------------------------------------

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
            if any(self._nodes[d].status != TASK_DONE
                   for d in node.unmet if d in self._nodes):
                continue
            out.append(node)
        # Attack-first ordering: priority asc, lead-carrying first, FIFO.
        out.sort(key=lambda n: (n.spec.get("priority", 5),
                                0 if n.lead_ids else 1, n.seq))
        max_parallel = int((self.mission.budget or {}).get("max_parallel_tasks") or 8)
        active = sum(1 for n in self._nodes.values() if n.status == TASK_ACTIVE)
        return out[: max(0, max_parallel - active)]

    def start(self, task_id: str) -> Dict[str, Any]:
        """Mark a task active and publish TASK_STARTED."""
        node = self._nodes[task_id]
        node.spec["status"] = TASK_ACTIVE
        decision = self.attach_routing(task_id)
        self.save()
        _publish(self.mission.target, "TASK_STARTED",
                 {"task_id": task_id, "mission_id": self.mission.mission_id,
                  "model_routing": decision})
        return decision

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
        issues = validate_task_result(result)
        if issues:
            append_jsonl(self._results_path(),
                         {"rejected": True, "issues": issues, "result": result})
            return issues
        node = self._nodes[task_id]
        node.spec["status"] = TASK_DONE
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

    def record_preflight(self, manifest: Dict[str, Any]) -> List[str]:
        """Complete the pre-flight gate task from a preflight manifest."""
        sha = str(manifest.get("sha256", ""))
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
        return {"mission_id": self.mission.mission_id,
                "target": self.mission.target,
                "nodes": len(self._nodes), "counts": counts,
                "dedup_skipped": self.dedup_skipped,
                "graph_path": str(self._graph_path)}


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

#!/usr/bin/env python3
"""BugWolf MCP bridge (orchestrator plan v2 section 4.4 — optional).

Exposes BugWolf's orchestrator tools over the Model Context Protocol
(JSON-RPC 2.0 over stdio) so any MCP client (Claude Code, browserMCP
hosts, Codex, Cursor) can drive missions directly:

    tools/list          -> mission status/plan/run, lead ledger, modes
    tools/call          -> dispatch one BugWolf operation, JSON result

Stdin/stdout only; one JSON-RPC message per line; never crashes -- a
failed call returns a JSON-RPC error object and the loop continues.

Run:  python3 bridge/bugwolf-mcp.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Make the BugWolf tree importable regardless of the caller's cwd
# (script-dir execution puts bridge/ on sys.path, not the repo root).
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

SCHEMA = "bugwolf/mcp-bridge/v1"


def _result(req_id: Any, value: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": value}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


# ---------------------------------------------------------------------------
# Tool implementations (thin wrappers over the real runtime modules)
# ---------------------------------------------------------------------------

def _project_root(args: Dict[str, Any]) -> str:
    return str(args.get("project_root")
               or os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")


def _mission(args: Dict[str, Any]) -> Any:
    from tools.runtime.contracts import MissionSpec
    mid = str(args.get("mission_id") or "bw-mcp")
    return MissionSpec(mission_id=mid,
                       target=str(args.get("target") or "operator-declared"),
                       domains=list(args.get("domains")
                                    or ["recon", "web_api", "verify",
                                        "report"]),
                       budget={"max_agents": 8, "max_parallel_tasks": 4,
                               "max_runtime_seconds": 600})


def tool_status(args: Dict[str, Any]) -> Dict[str, Any]:
    from tools.runtime.scheduler import Scheduler
    sched = Scheduler.load(str(args.get("mission_id")),
                           project_root=_project_root(args))
    from tools.runtime.lead_protocol import LeadStore
    leads = LeadStore(str(args.get("mission_id")),
                      project_root=_project_root(args)).load()
    counts: Dict[str, int] = {}
    for lead in leads.list_leads():
        counts[lead.status] = counts.get(lead.status, 0) + 1
    return {"schema": SCHEMA, "scheduler": sched.status(),
            "resume": sched.resume(), "lead_counts": counts}


def tool_plan(args: Dict[str, Any]) -> Dict[str, Any]:
    from tools.runtime.scheduler import Scheduler
    sched = Scheduler(_mission(args), project_root=_project_root(args))
    specs = sched.plan_mission()
    return {"schema": SCHEMA, "planned": [s["task_id"] for s in specs],
            "graph": sched.status()}


def tool_run(args: Dict[str, Any]) -> Dict[str, Any]:
    from tools.runtime.mission_runner import MissionRunner
    mission = _mission(args)
    runner = MissionRunner(
        mission, project_root=_project_root(args),
        base_url=str(args.get("target") or ""),
        paths=[str(p) for p in (args.get("paths") or [])])
    try:
        report = runner.run()
    finally:
        runner.close()
    return {"schema": SCHEMA, **report}


def tool_leads(args: Dict[str, Any]) -> Dict[str, Any]:
    from tools.runtime.lead_protocol import LeadStore
    store = LeadStore(str(args.get("mission_id")),
                      project_root=_project_root(args)).load()
    out = []
    for lead in store.list_leads():
        out.append({**lead.to_dict(),
                    "closeability": store.closeability(lead)})
    return {"schema": SCHEMA, "leads": out}


def tool_mode(args: Dict[str, Any]) -> Dict[str, Any]:
    from tools.runtime.modes import ModeEngine, MODES
    mode = str(args.get("mode") or "")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    engine = ModeEngine(_mission(args), project_root=_project_root(args),
                        budget_ticks=int(args.get("ticks") or 4))
    outcome = engine.run(mode)
    engine.stop()
    return {"schema": SCHEMA, **outcome}


TOOLS = {
    "bugwolf_status": (tool_status, "Scheduler status + resume plan + "
                       "lead counts for a mission"),
    "bugwolf_plan": (tool_plan, "Plan a mission task graph (no dispatch)"),
    "bugwolf_run": (tool_run, "Run/resume a mission end-to-end "
                    "(preflight included)"),
    "bugwolf_leads": (tool_leads, "Full lead ledger with closeability"),
    "bugwolf_mode": (tool_mode, "Run one persistent mode "
                     "(research/verify/deep-dive/coverage/report)"),
}


def dispatch(method: str, params: Dict[str, Any]) -> Any:
    if method == "initialize":
        return {"protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "bugwolf", "version": "1.0.0"}}
    if method == "tools/list":
        return {"tools": [{"name": name, "description": desc,
                           "inputSchema": {"type": "object"}}
                          for name, (_fn, desc) in TOOLS.items()]}
    if method == "tools/call":
        name = str(params.get("name") or "")
        if name not in TOOLS:
            raise ValueError(f"unknown tool {name!r}")
        fn, _desc = TOOLS[name]
        value = fn(dict(params.get("arguments") or {}))
        return {"content": [{"type": "text",
                             "text": json.dumps(value, default=str)}]}
    raise ValueError(f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            msg = json.loads(line)
            req_id = msg.get("id")
            value = dispatch(str(msg.get("method")),
                             dict(msg.get("params") or {}))
            print(json.dumps(_result(req_id, value), default=str),
                  flush=True)
        except Exception as exc:  # noqa: BLE001 - bridge never crashes
            print(json.dumps(_error(req_id, -32000, str(exc)[:300])),
                  flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

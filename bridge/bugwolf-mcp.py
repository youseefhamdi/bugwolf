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
from typing import Any, Dict, List, Optional

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


def tool_agents(args: Dict[str, Any]) -> Dict[str, Any]:
    """List the specialized subagent registry (roles, tiers, playbooks)."""
    from tools.core.agent_registry import AgentRegistry
    reg = AgentRegistry()
    if str(args.get("verify") or ""):
        bad = []
        for role in reg.all_roles():
            try:
                reg.load_prompt(role)
            except Exception as exc:  # noqa: BLE001
                bad.append({"role": role, "error": str(exc)[:200]})
        return {"schema": SCHEMA, "verified": not bad, "errors": bad}
    return {"schema": SCHEMA, **reg.inventory()}


def tool_team(args: Dict[str, Any]) -> Dict[str, Any]:
    """Multi-agent team surface: plan/status/resume (run needs a worker)."""
    from tools.runtime.team import TeamEngine
    from tools.runtime.contracts import MissionSpec
    action = str(args.get("action") or "status")
    mission_id = str(args.get("mission_id") or "")
    if not mission_id:
        raise ValueError("mission_id is required")
    root = _project_root(args)
    if action == "plan":
        mission = MissionSpec(mission_id=mission_id,
                              target=str(args.get("target") or ""),
                              domains=[d for d in (args.get("domains") or [])
                                       if d])
        engine = TeamEngine(mission, project_root=root)
        engine.plan(bug_classes=[b for b in (args.get("bug_classes") or [])
                                 if b])
        return {"schema": SCHEMA, **engine.status()}
    if action == "status":
        engine = TeamEngine.load(mission_id, project_root=root)
        return {"schema": SCHEMA, **engine.status()}
    if action == "resume":
        engine = TeamEngine.load(mission_id, project_root=root)
        outcome = engine.resume()
        return {"schema": SCHEMA, **outcome}
    if action == "preflight":
        try:  # persisted state when the mission exists; fresh otherwise
            engine = TeamEngine.load(mission_id, project_root=root)
        except FileNotFoundError:
            engine = TeamEngine(
                MissionSpec(mission_id=mission_id,
                            target=str(args.get("target") or "")),
                project_root=root)
        return {"schema": SCHEMA, **engine.preflight()}
    raise ValueError(f"action must be plan|status|resume|preflight, got {action!r} "
                     f"(dispatching agents requires a harness worker; use "
                     f"the run command with a bound worker)")


def tool_http_replay(args: Dict[str, Any]) -> Dict[str, Any]:
    """Structured replay: request text + field-level mutations, governed."""
    from tools.runtime.replay.engine import replay_request
    from tools.runtime.replay.governor import Governor
    from tools.runtime import scope as scope_mod
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("target is required")
    extra = [str(h) for h in (args.get("extra_hosts") or [])]
    denies = [str(h) for h in (args.get("exclude") or [])]
    if scope_mod.GATE.bound:
        scope_mod.GATE.bind(target, extra_hosts=extra, deny_entries=denies)
    else:
        scope_mod.GATE.bind(target, extra_hosts=extra,
                            deny_entries=denies)
    governor = Governor(rate_rps=float(args.get("rate") or 5.0),
                        budget=int(args.get("budget") or 5000))
    report = replay_request(
        str(args.get("request") or ""),
        host=target,
        mutations=list(args.get("mutations") or []) or None,
        compare_baseline=bool(args.get("compare")),
        markers=[str(m) for m in (args.get("markers") or [])],
        governor=governor)
    return {**report.to_dict(), "schema": "bugwolf-replay-mcp/v1"}


def tool_http_replay_raw(args: Dict[str, Any]) -> Dict[str, Any]:
    """Raw replay: verbatim bytes — smuggling, malformed framing, odd-case
    headers, Host override. Scope gate still authorizes."""
    from tools.runtime.replay.engine import replay_raw
    from tools.runtime.replay.governor import Governor
    from tools.runtime import scope as scope_mod
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("target is required")
    if scope_mod.GATE.bound:
        scope_mod.GATE.bind(target, deny_entries=list(args.get("exclude") or []))
    else:
        scope_mod.GATE.bind(target, deny_entries=list(args.get("exclude") or []))
    governor = Governor(rate_rps=float(args.get("rate") or 5.0),
                        budget=int(args.get("budget") or 5000))
    raw = str(args.get("raw") or "").encode("latin-1")
    report = replay_raw(raw, host=target,
                        markers=[str(m) for m in (args.get("markers") or [])],
                        governor=governor)
    return {**report.to_dict(), "schema": "bugwolf-replay-mcp/v1"}


def tool_capture_replay(args: Dict[str, Any]) -> Dict[str, Any]:
    """Capture→replay loop (2.4): load captures.jsonl, filter through the
    scope gate, replay through the governed raw engine, drift = facts."""
    from tools.runtime import capture_replay as capture_mod
    path = str(args.get("captures") or "")
    target = str(args.get("target") or "")
    if not path or not target:
        raise ValueError("captures and target are required")
    loaded = capture_mod.load_captures(path)
    summary = capture_mod.replay_captures(
        loaded.records, target=target,
        artifacts_dir=str(args.get("artifacts_dir") or "mission/captures"),
        rate_rps=float(args.get("rate") or 5.0),
        budget=int(args.get("budget") or 5000),
        markers=[str(m) for m in (args.get("markers") or [])] or None)
    return {
        "schema": "bugwolf-capture-replay-mcp/v1",
        "loaded": {"valid": loaded.schema_ok, "skipped": loaded.skipped,
                   "out_of_scope": loaded.out_of_scope},
        "summary": summary,
    }


def tool_http_replay_desync(args: Dict[str, Any]) -> Dict[str, Any]:
    """CL.TE / TE.CL detection pattern: ambiguous front request, pause,
    smuggled second request."""
    from tools.runtime.replay.engine import desync_probe
    from tools.runtime.replay.governor import Governor
    from tools.runtime import scope as scope_mod
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("target is required")
    scope_mod.GATE.bind(target, deny_entries=list(args.get("exclude") or []))
    governor = Governor(rate_rps=float(args.get("rate") or 5.0),
                        budget=int(args.get("budget") or 5000))
    front = str(args.get("front") or "").encode("latin-1")
    smuggled = str(args.get("smuggled") or "").encode("latin-1")
    result = desync_probe(target, front, smuggled, governor=governor)
    return {"schema": "bugwolf-replay-mcp/v1", **result}


def tool_browser_confirm(args: Dict[str, Any]) -> Dict[str, Any]:
    """Browser-confirmed client-side validation (master plan Phase 2.5).

    EXECUTION-CONFIRMED requires the payload signature observed in a REAL
    browser console/DOM (Playwright Chromium); body reflection alone is
    reported as reflection_only and never confirms.  No usable browser =>
    an honest blocked fact (with the exact install hint), never a verdict.
    """
    from tools.runtime.browser_driver import (
        validate_client_side, make_signature, load_default_driver,
        driver_status)
    from tools.runtime import scope as scope_mod
    url = str(args.get("url") or "")
    if not url:
        raise ValueError("url is required")
    # Authorize the mission target ONLY when explicitly declared; the
    # validator enforces the gate on the candidate URL either way (an
    # out-of-scope url comes back as a scope-blocked FACT, not a raise).
    bind_target = args.get("target")
    if bind_target:
        scope_mod.GATE.bind(str(bind_target),
                            extra_hosts=[str(h) for h in (args.get("extra_hosts") or [])],
                            deny_entries=[str(h) for h in (args.get("exclude") or [])])
    driver = load_default_driver()
    if driver is None:
        return {"schema": "bugwolf-browser-mcp/v1", "blocked": True,
                "blocker": "no browser driver available (playwright missing)",
                "driver_status": driver_status()}
    candidate = {"url": url,
                 "lead_id": str(args.get("lead_id") or url),
                 "dom_sink": str(args.get("dom_sink") or "")}
    signature = str(args.get("signature") or "") or make_signature(candidate["lead_id"])
    evidence = validate_client_side(candidate, driver, signature=signature)
    out = {**evidence.to_dict(), "schema": "bugwolf-browser-mcp/v1",
           "signature": signature}
    if args.get("screenshot") and evidence.navigated:
        try:
            out["screenshot"] = driver.screenshot()
        except Exception as exc:  # noqa: BLE001 - evidence failure is data
            out["screenshot_error"] = f"{type(exc).__name__}: {exc}"
    return out


def tool_sessions(args: Dict[str, Any]) -> Dict[str, Any]:
    """Session context model (master plan Phase 2.2): per-credential roles,
    JWT claim shape, object-ID inventory, identity matrix, and the crawl's
    differential paths.  Read-only; tokens are ALWAYS redacted here."""
    from tools.runtime.session_context import SessionContextStore
    mission_id = str(args.get("mission_id") or "")
    if not mission_id:
        raise ValueError("mission_id is required")
    store = SessionContextStore(mission_id,
                                project_root=args.get("project_root")).load()
    if not store.sessions:
        return {"schema": "bugwolf-sessions-mcp/v1", "mission_id": mission_id,
                "sessions": {}, "note": "no session context recorded "
                "(bind operator accounts to build one)"}
    model = store.to_model_dict()
    out = {"schema": "bugwolf-sessions-mcp/v1", **model,
           "sessions": {label: ctx.to_dict()
                        for label, ctx in sorted(store.sessions.items())}}
    crawl_path = store.root.parent / "crawl" / "access_matrix.json"
    if crawl_path.exists():
        try:
            crawl = json.loads(crawl_path.read_text(encoding="utf-8"))
            out["crawl"] = {"differential_paths":
                            crawl.get("differential_paths", []),
                            "labels": crawl.get("labels", [])}
        except (OSError, ValueError):
            pass
    return out


def tool_understand(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run the Understanding Layer (U1-U9) and return the Target Model.

    Deterministic: U1 pages are fetched through the replay engine (scope
    gate + governor inherited); the crawl/session model come from the
    mission's persisted artifacts when a mission_id is given.  Output:
    coverage gate (hunts vs parked-with-reason), ranked hypotheses, and
    the Hunting Brief text (also written to
    state/targets/<t>/model/hunting-brief.md).
    """
    from tools.runtime.understanding.pipeline import UnderstandingPipeline
    from tools.runtime.replay.engine import replay_raw
    from tools.runtime.replay.governor import Governor
    from tools.runtime import scope as scope_mod
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("target is required")
    root = _project_root(args)
    scope_mod.GATE.bind(target)

    # -- U1 pages: fetch the operator-declared business pages (+ the
    #    conventional OpenAPI locations, used as U2/U3/U5 input when valid).
    host = target.split("//")[-1].strip("/")
    fetch_paths = [p if p.startswith("/") else "/" + p
                   for p in (args.get("paths") or
                              ["/", "/pricing", "/signup", "/tos"])]
    pages: Dict[str, str] = {}
    openapi = None
    governor = Governor(rate_rps=10.0, budget=200)
    for path in fetch_paths + ["/openapi.json", "/swagger.json"]:
        if path in pages:
            continue
        raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: BugWolf-Understand/1\r\n"
               "Accept: text/html,application/json\r\n"
               "Connection: close\r\n\r\n").encode("latin-1")
        try:
            report = replay_raw(raw, host=target, governor=governor)
        except Exception:  # noqa: BLE001 - a dead page is a missing fact
            continue
        if report.status == 200 and report.body_preview:
            pages[path] = report.body_preview[:20000]
            if openapi is None and path.endswith((".json",)):
                try:
                    doc = json.loads(report.body_preview)
                    if isinstance(doc, dict) and (
                            "openapi" in doc or "swagger" in doc):
                        openapi = doc
                except ValueError:
                    pass

    # -- crawl + session model from the mission's persisted artifacts.
    crawl = None
    session_store = None
    mission_id = str(args.get("mission_id") or "")
    if mission_id:
        from tools.runtime.session_context import SessionContextStore
        store = SessionContextStore(mission_id, project_root=root).load()
        if store.sessions:
            session_store = store
        crawl = _load_crawl_adapter(mission_id, root)
    if openapi is None and str(args.get("openapi_path") or ""):
        try:
            doc = json.loads(Path(args["openapi_path"]).read_text(
                encoding="utf-8"))
            if isinstance(doc, dict):
                openapi = doc
        except (OSError, ValueError):
            pass

    pipeline = UnderstandingPipeline(target, project_root=root)
    result = pipeline.run(pages=pages, crawl=crawl,
                          session_store=session_store, openapi=openapi,
                          refresh=bool(args.get("refresh")))
    out = result.to_dict()
    brief_path = Path(result.brief_path)
    if brief_path.is_file():
        out["hunting_brief"] = brief_path.read_text(encoding="utf-8")
    out["fetched_pages"] = sorted(pages)
    out["schema"] = "bugwolf-understand-mcp/v1"
    return out


class _CrawlAdapter:
    """Duck-typed CrawlReport rebuilt from the mission's crawl artifacts."""

    def __init__(self, payload: Dict[str, Any], pages: Dict[str, Any]) -> None:
        self._payload = payload
        self.pages = pages
        self.labels = list(payload.get("labels") or [])

    def differential_paths(self):
        return list(self._payload.get("differential_paths") or [])

    def to_dict(self):
        return self._payload


def _load_crawl_adapter(mission_id: str, root) -> Optional[_CrawlAdapter]:
    crawl_dir = root / "state" / "orchestrator" / mission_id / "crawl"
    matrix_path = crawl_dir / "access_matrix.json"
    pages_path = crawl_dir / "pages.jsonl"
    if not matrix_path.is_file():
        return None
    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    class _Page:
        pass

    pages: Dict[str, Any] = {}
    if pages_path.is_file():
        try:
            for line in pages_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                page = _Page()
                page.path = rec.get("path", "")
                page.status_by_label = rec.get("status_by_label", {})
                page.title = rec.get("title", "")
                page.links = rec.get("links", [])
                page.forms = rec.get("forms", [])
                pages[page.path] = page
        except (OSError, ValueError):
            pass
    return _CrawlAdapter(payload, pages)


TOOLS = {
    "bugwolf_status": (tool_status, "Scheduler status + resume plan + "
                       "lead counts for a mission"),
    "bugwolf_plan": (tool_plan, "Plan a mission task graph (no dispatch)"),
    "bugwolf_run": (tool_run, "Run/resume a mission end-to-end "
                    "(preflight included)"),
    "bugwolf_leads": (tool_leads, "Full lead ledger with closeability"),
    "bugwolf_mode": (tool_mode, "Run one persistent mode "
                     "(research/verify/deep-dive/coverage/report)"),
    "bugwolf_agents": (tool_agents, "Specialized subagent registry "
                       "(roles, model tiers, playbook verification)"),
    "bugwolf_team": (tool_team, "Multi-agent team: plan/status/resume "
                     "(waves of bugwolf:<role> subagents)"),
    "bugwolf_http_replay": (tool_http_replay,
                            "Structured HTTP replay with field-level "
                            "mutations (scope-gated, governed; facts only)"),
    "bugwolf_http_replay_raw": (tool_http_replay_raw,
                                "Raw byte-exact HTTP replay — smuggling, "
                                "malformed framing, odd-case headers "
                                "(scope-gated, governed)"),
    "bugwolf_http_replay_desync": (tool_http_replay_desync,
                                   "CL.TE / TE.CL desync probe pair: "
                                   "ambiguous front request + smuggled second"),
    "bugwolf_browser_confirm": (tool_browser_confirm,
                                "Browser-confirmed client-side validation: "
                                "real Chromium console/DOM signature check — "
                                "reflection alone never confirms"),
    "bugwolf_sessions": (tool_sessions,
                         "Session context model: per-credential roles, JWT "
                         "claim shape, object IDs, identity matrix, crawl "
                         "differentials (tokens always redacted)"),
    "bugwolf_understand": (tool_understand,
                           "Understanding Layer U1-U9: Target Model + "
                           "coverage gate (hunts vs parked-with-reason) + "
                           "ranked hypotheses + Hunting Brief"),
    "bugwolf_capture_replay": (tool_capture_replay,
                               "Capture→replay loop (2.4): captures.jsonl "
                               "from the mitmproxy addon -> scope-filtered, "
                               "governed replay; status/body drift = facts"),
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

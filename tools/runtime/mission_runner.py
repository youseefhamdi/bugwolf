#!/usr/bin/env python3
"""BugWolf mission runner (orchestrator plan v2, Phase 4 exit criterion).

Executes one MissionSpec end-to-end through the real runtime:

    MissionSpec -> Scheduler.plan_mission() -> pre-flight gate (recorded)
    -> web/API lane (deterministic probes against the operator target)
    -> lead protocol (R1 open, R3 matrix, T0-T1 escalation, R2 closure)
    -> verify lane (independent replay of every PWNED lead)
    -> mission report (findings = replay-confirmed leads)

The lane executors here are the Phase 4 deterministic core: direct HTTP
probes for the BOLA/direct-access family, header-trust bypass, fuzz-batch
crash detection, and GraphQL introspection.  Reasoning-model hunting
(T3/T4 swarm) attaches later; the protocol and graph already carry it.

Usage:
  python3 tools/runtime/mission_runner.py --mission-id bw-e2e \
      --target http://127.0.0.1:8077 --domains web_api,verify --report
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime.lead_protocol import (
    LeadStore, LeadSpec, TIER_T0, TIER_T1, SIGNAL_ESCALATION,
)
from tools.runtime.scheduler import Scheduler
from tools.runtime.contracts import (
    MissionSpec, LEAD_PWNED, LEAD_REFUTED, RESULT_PARTIAL,
)

SCHEMA = "bugwolf-mission-runner/v1"

UA = "bugwolf-mission-runner/1.0"


# ---------------------------------------------------------------------------
# Deterministic HTTP probe (no model calls in the Phase 4 core)
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    status: int
    body: str
    latency_ms: int
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def http_probe(url: str, *, method: str = "GET", body: Optional[Dict] = None,
               headers: Optional[Dict[str, str]] = None,
               timeout: float = 8.0) -> ProbeResult:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    start = time.monotonic()

    def _headers(raw_headers) -> Dict[str, str]:
        # http.client header objects are lists of (name, value) tuples.
        try:
            return {str(k).lower(): str(v) for k, v in (raw_headers or [])}
        except (TypeError, ValueError):
            return {}

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4096)
            return ProbeResult(resp.status, raw.decode("utf-8", "replace"),
                               int((time.monotonic() - start) * 1000),
                               _headers(resp.getheaders()))
    except urllib.error.HTTPError as exc:
        raw = exc.read(4096) if exc.fp else b""
        return ProbeResult(exc.code, raw.decode("utf-8", "replace"),
                           int((time.monotonic() - start) * 1000),
                           _headers(exc.headers))
    except Exception as exc:  # noqa: BLE001 - network failure is a result
        return ProbeResult(0, f"{type(exc).__name__}: {exc}",
                           int((time.monotonic() - start) * 1000))


# ---------------------------------------------------------------------------
# Web/API lane executor: deterministic hunt families
# ---------------------------------------------------------------------------

# Each family gets: (probe_fn, bug_class, technique label).  A family that
# yields a signal opens a lead via the protocol (R1) and walks the ladder.


def _probe_direct_object_reference(base: str, paths: List[str]) -> List[Dict]:
    """BOLA family: unauthenticated direct object access."""
    signals = []
    for path in paths:
        result = http_probe(base + path)
        if result.ok and result.body.strip().startswith("{"):
            try:
                data = json.loads(result.body)
            except ValueError:
                continue
            if isinstance(data, dict) and any(
                    key in data for key in ("id", "email", "username", "balance")):
                signals.append({
                    "signal": "direct-object-reference",
                    "detail": f"{path} returned object data without auth",
                    "evidence": result.body[:400],
                    "path": path, "status": result.status,
                })
    return signals


def _probe_header_trust(base: str, paths: List[str]) -> List[Dict]:
    """Header-trust family: only a real differential opens a lead.

    Baseline first: a WAF-blocked surface (403) is the precondition.  Then
    the bypass headers on the SAME path -- 403 -> 200 is the signal.  A 200
    without a prior block proves nothing (that is the elite loop's
    differential rule, mechanized).
    """
    signals = []
    for path in paths:
        sep = "&" if "?" in path else "?"
        baseline = http_probe(f"{base}{path}{sep}q=probe")
        if baseline.status != 403:
            continue  # not blocked: nothing to bypass
        for header in ("X-Original-URL", "X-Rewrite-URL"):
            result = http_probe(base + path, headers={header: path})
            if result.ok:
                signals.append({
                    "signal": "waf_block",
                    "detail": (f"{path} blocked (403) -> {result.status} "
                               f"via {header}: differential bypass"),
                    "evidence": result.body[:400],
                    "path": path, "header": header,
                    "status": result.status,
                })
    return signals


def _probe_fuzz_batch(base: str, paths: List[str]) -> List[Dict]:
    """Fuzz family: boundary/grammar payloads; 5xx = crash signal."""
    payloads = ["A" * 65, "A" * 4096, "' OR '1'='1", "SLEEP(5)", "%s%s%s%n"]
    signals = []
    for path in paths:
        for payload in payloads:
            sep = "&" if "?" in path else "?"
            result = http_probe(f"{base}{path}{sep}q={payload}")
            if result.status >= 500:
                signals.append({
                    "signal": "anomaly",
                    "detail": f"{path} 5xx on payload len={len(payload)}",
                    "evidence": result.body[:400],
                    "path": path, "payload": payload[:64],
                    "status": result.status,
                })
    return signals


def _probe_graphql_introspection(base: str, paths: List[str]) -> List[Dict]:
    """GraphQL family: introspection exposure + input-type field harvest."""
    signals = []
    for path in paths:
        query = json.dumps({"query": "{ __schema { types { name kind } } }"})
        result = http_probe(base + path, method="POST", body=json.loads(query),
                            headers={"Content-Type": "application/json"})
        if result.ok and "__schema" in result.body:
            signals.append({
                "signal": "anomaly",
                "detail": f"{path} allows schema introspection",
                "evidence": result.body[:400],
                "path": path, "status": result.status,
            })
    return signals


LANE_FAMILIES = (
    (_probe_direct_object_reference, "access_control", "direct-attempt"),
    (_probe_header_trust, "waf_bypass", "header-original-url"),
    (_probe_fuzz_batch, "fuzzing", "boundary-length"),
    (_probe_graphql_introspection, "generic", "parameter-mutation"),
)


# ---------------------------------------------------------------------------
# Mission runner
# ---------------------------------------------------------------------------


class MissionRunner:
    """Drive one MissionSpec through scheduler + lanes + lead protocol."""

    def __init__(self, mission: MissionSpec, *, project_root: Optional[str] = None,
                 base_url: str = "", paths: Optional[List[str]] = None):
        self.mission = mission
        self.project_root = project_root
        self.base_url = base_url.rstrip("/")
        self.paths = paths or ["/api/users/1", "/api/users/2", "/api/gateway",
                               "/api/ingest", "/graphql"]
        self.scheduler = Scheduler(mission, project_root=project_root)
        self.leads = LeadStore(mission.mission_id,
                               project_root=project_root).load()
        self._events: List[Dict[str, Any]] = []

    # -- helpers -------------------------------------------------------------

    def _log(self, event: str, payload: Dict[str, Any]) -> None:
        self._events.append({"event": event, **payload})

    def run(self) -> Dict[str, Any]:
        """Execute the full mission; returns the mission report."""
        started = time.time()
        # 1. Plan (creates the preflight gate + lane roots).
        self.scheduler.plan_mission()
        self._log("planned", {"nodes": len(self.scheduler._nodes)})

        # 2. Pre-flight: run it, record through the gate task.
        from tools.runtime.preflight import run_preflight
        manifest = run_preflight(
            self.mission.target, project_root=self.project_root,
            probe_binaries=False)
        issues = self.scheduler.record_preflight(manifest)
        if issues:
            self._log("preflight_rejected", {"issues": issues})
        self._log("preflight", {"digest": manifest.get("digest", "")})

        # 3. Dispatch runnable tasks (the web/API lane is the Phase 4 lane).
        report_tasks: Dict[str, Any] = {}
        for _ in range(16):  # bounded drain loop
            runnable = self.scheduler.runnable()
            if not runnable:
                break
            for node in runnable:
                task_id = node.task_id
                self.scheduler.start(task_id)
                if node.spec.get("domain") == "web_api":
                    result = self._run_web_lane()
                elif node.spec.get("domain") == "recon":
                    result = self._run_recon_lane()
                elif node.spec.get("domain") == "verify":
                    result = self._run_verify_lane()
                elif node.spec.get("domain") == "report":
                    result = self._run_report_lane()
                else:
                    result = self._noop_lane(node)
                result["task_id"] = task_id  # contracts require it
                issues = self.scheduler.record(task_id, result)
                report_tasks[task_id] = {
                    "status": result.get("status"),
                    "issues": issues,
                    "open_leads": result.get("open_leads", []),
                }
                if issues:
                    self._log("result_rejected", {"task_id": task_id,
                                                  "issues": issues})
        self._log("drained", {"tasks": report_tasks})

        # 4. Mission report.
        return self._mission_report(started, report_tasks)

    # -- lanes ----------------------------------------------------------------

    def _run_web_lane(self) -> Dict[str, Any]:
        """Hunt the operator target with the deterministic families."""
        receipts, lead_ids = [], list(self.leads.open_lead_ids())
        evidence: List[str] = []
        for probe_fn, bug_class, technique in LANE_FAMILIES:
            signals = probe_fn(self.base_url, self.paths)
            for sig in signals:
                # R1: the signal becomes a durable lead immediately.
                lead = self.leads.open_lead(
                    title=f"{sig['signal']} on {sig.get('path', '')}",
                    mission_id=self.mission.mission_id,
                    target=self.mission.target,
                    bug_class=bug_class, surface=sig.get("path", ""),
                    evidence_refs=[], signal=sig["signal"])
                lead_ids.append(lead.lead_id)
                # T0 attempt for this family's own technique.
                self.leads.record_technique(
                    lead.lead_id, technique, "success" if sig.get("status", 0) == 200 else "signal",
                    detail=sig.get("detail", ""))
                evidence.append(f"evid-{lead.lead_id}")
                self._log("lead_opened", {"lead_id": lead.lead_id,
                                          "signal": sig["signal"],
                                          "detail": sig.get("detail", "")})
        status = "completed" if lead_ids else "completed"
        return {
            "task_id": "",  # filled by record()
            "agent_role": "web-api-lane",
            "status": "agent_partial" if lead_ids else "completed",
            "summary": (f"{len(lead_ids)} leads open; "
                        f"{len(evidence)} signals hunted deterministically"),
            "lead_refs": lead_ids,
            "open_leads": lead_ids,  # partial results keep leads open (R6)
            "tool_receipts": [{"tool": "mission_runner.web_lane",
                               "command": "hunt_families",
                               "inputs": {"base_url": self.base_url},
                               "exit_state": "ok"}],
            "evidence_refs": evidence,
            "mcp_bindings_used": [],
        }

    def _run_recon_lane(self) -> Dict[str, Any]:
        """Baseline recon: tech fingerprint + surface notes."""
        result = http_probe(self.base_url + "/tech.json")
        body = result.body[:800] if result.ok else ""
        return {
            "task_id": "", "agent_role": "recon-lane",
            "status": "completed" if result.ok else "agent_partial",
            "summary": f"tech.json HTTP {result.status}",
            "tool_receipts": [{"tool": "mission_runner.recon_lane",
                               "command": "fetch_tech",
                               "exit_state": "ok" if result.ok else "error"}],
            "evidence_refs": [f"tech-{result.status}"] if result.ok else [],
            "mcp_bindings_used": [],
        }

    def _run_verify_lane(self) -> Dict[str, Any]:
        """Independent replay of every PWNED-eligible lead (F0.5)."""
        verified, refuted = [], []
        for lead in self.leads.list_leads():
            if lead.status != "OPEN":
                continue
            replay = self._replay_lead(lead)
            if replay is True:
                self.leads.close_pwned(lead.lead_id,
                                       evidence_ref=f"replay-{lead.lead_id}")
                verified.append(lead.lead_id)
                self._log("lead_verified", {"lead_id": lead.lead_id})
            elif replay is False:
                self.leads.close_refuted(
                    lead.lead_id,
                    counter_evidence="deterministic replay did not reproduce")
                refuted.append(lead.lead_id)
                self._log("lead_refuted", {"lead_id": lead.lead_id})
        return {
            "task_id": "", "agent_role": "verify-lane",
            "status": "completed",
            "summary": f"verified {len(verified)}, refuted {len(refuted)}",
            "tool_receipts": [{"tool": "mission_runner.verify_lane",
                               "command": "replay_leads",
                               "exit_state": "ok"}],
            "lead_refs": verified + refuted,
            "mcp_bindings_used": [],
        }

    def _replay_lead(self, lead: LeadSpec) -> Optional[bool]:
        """Deterministic replay -> True (PWNED) / False (REFUTED) / None (undecidable)."""
        if lead.bug_class == "access_control":
            probe = http_probe(self.base_url + lead.surface)
            if probe.ok and '"id"' in probe.body:
                return True
            return False
        if lead.bug_class == "waf_bypass":
            # Replay the recorded differential: blocked path + bypass header.
            probe = http_probe(self.base_url + lead.surface,
                               headers={"X-Original-URL": lead.surface})
            if probe.ok and "token" in probe.body.lower():
                return True
            return False
        if lead.bug_class == "fuzzing":
            sep = "&" if "?" in lead.surface else "?"
            probe = http_probe(f"{self.base_url}{lead.surface}{sep}q={'A' * 65}")
            return probe.status >= 500
        return None  # generic leads need reasoning tiers (Phase 6)

    def _run_report_lane(self) -> Dict[str, Any]:
        pwned = [l for l in self.leads.list_leads() if l.status == LEAD_PWNED]
        refuted = [l for l in self.leads.list_leads()
                   if l.status == LEAD_REFUTED]
        return {
            "task_id": "", "agent_role": "report-lane",
            "status": "completed",
            "summary": (f"findings={len(pwned)} refuted={len(refuted)} "
                        f"open={len(self.leads.open_lead_ids())}"),
            "tool_receipts": [{"tool": "mission_runner.report_lane",
                               "command": "assemble_findings",
                               "exit_state": "ok"}],
            "evidence_refs": [l.lead_id for l in pwned],
            "lead_refs": [l.lead_id for l in pwned + refuted],
            "mcp_bindings_used": [],
        }

    def _noop_lane(self, node) -> Dict[str, Any]:
        return {
            "task_id": "", "agent_role": f"{node.spec['domain']}-lane",
            "status": "completed",
            "summary": "no Phase 4 executor for this domain yet",
            "tool_receipts": [{"tool": "mission_runner",
                               "command": "noop_lane",
                               "inputs": {"domain": node.spec["domain"]},
                               "exit_state": "ok"}],
            "mcp_bindings_used": [],
        }

    # -- report -----------------------------------------------------------------

    def _mission_report(self, started: float, tasks: Dict[str, Any]) -> Dict[str, Any]:
        leads = self.leads.list_leads()
        pwned = [l for l in leads if l.status == LEAD_PWNED]
        refuted = [l for l in leads if l.status == LEAD_REFUTED]
        open_leads = [l for l in leads if l.status == "OPEN"]
        return {
            "schema": SCHEMA,
            "mission_id": self.mission.mission_id,
            "target": self.mission.target,
            "base_url": self.base_url,
            "duration_seconds": round(time.time() - started, 2),
            "graph": self.scheduler.status(),
            "tasks": tasks,
            "findings": [{"lead_id": l.lead_id, "title": l.title,
                          "bug_class": l.bug_class, "surface": l.surface,
                          "evidence": l.evidence_refs}
                         for l in pwned],
            "counts": {"findings": len(pwned), "refuted": len(refuted),
                       "open": len(open_leads), "total_leads": len(leads)},
            "events": self._events,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf mission runner (scheduler + lanes + lead protocol)")
    parser.add_argument("--mission-id", required=True)
    parser.add_argument("--target", required=True,
                        help="operator target base URL")
    parser.add_argument("--domains", default="recon,web_api,verify,report")
    parser.add_argument("--paths", default="")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    mission = MissionSpec(
        mission_id=args.mission_id, target=args.target,
        domains=[d.strip() for d in args.domains.split(",") if d.strip()],
        budget={"max_agents": 8, "max_parallel_tasks": 4,
                "max_runtime_seconds": 600},
    )
    runner = MissionRunner(mission, base_url=args.target,
                           paths=[p for p in args.paths.split(",") if p])
    report = runner.run()
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        counts = report["counts"]
        print(f"mission {report['mission_id']}: "
              f"findings={counts['findings']} refuted={counts['refuted']} "
              f"open={counts['open']} in {report['duration_seconds']}s")
        for finding in report["findings"]:
            print(f"  [PWNED] {finding['lead_id']} {finding['surface']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

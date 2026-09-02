#!/usr/bin/env python3
"""Phase 3 tests: mandatory pre-flight (section 4.5) + task-graph scheduler.

Pre-flight contract under test:
  * PF1 inventory: binaries fingerprinted ready/missing, modules importable,
    manifest persisted with a stable sha256 + human digest;
  * PF2 connection checks in mandated order (browser first, burp second),
    DOWN -> BLOCKED for browser (no fallback), DOWN -> DEGRADED for burp
    (raw sends fall back) -- never silently skipped;
  * PF3 memory: run_preflight produces an ArtifactRef attachable to a
    MissionSpec.preflight_manifest_ref that passes contract validation;
  * PF4 state machine: UNKNOWN -> CHECKING -> CONNECTED/DEGRADED/BLOCKED,
    cached within the TTL, transitions counted.

Scheduler contract under test:
  * plan_mission creates the preflight gate task (priority 0) + lane roots
    depending on it -- no lane work before pre-flight completes;
  * runnable() respects the gate, the mission budget, dependencies, and
    attack-first ordering (priority, lead-first, FIFO);
  * record() enforces the contracts validators (rejected results leave the
    task untouched); accepted results flip to done and persist open leads;
  * record_preflight opens the gate;
  * blocked tasks re-open when their connection is restored (PF4);
  * resume() reports lead-first ordering and zero re-run of done work;
  * the graph round-trips through disk with no loss.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime import preflight as pf
from tools.runtime import scheduler as sch
from tools.runtime.contracts import (
    MCP_BLOCKED, MCP_CHECKING, MCP_CONNECTED, MCP_DEGRADED, MCP_UNKNOWN,
    MissionSpec, validate_mission_spec,
)


class _TempState:
    """Route runtime paths + bus into a temp dir for hermetic tests."""

    def __init__(self, testcase):
        self._tc = testcase

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        p_ws = mock.patch.object(pf, "workspace_root", return_value=self.root)
        p_ws.start()
        self._tc.addCleanup(p_ws.stop)
        p_pub = mock.patch.object(pf, "_publish_connection_change",
                                  lambda state: None)
        p_pub.start()
        self._tc.addCleanup(p_pub.stop)
        return self.root

    def __exit__(self, *exc):
        self._td.cleanup()
        return False


def _mission(domains=("recon", "web"), mission_id="bw-test-1",
             max_parallel=4):
    return MissionSpec(mission_id=mission_id, target="demo.example.com",
                       domains=list(domains),
                       budget={"max_agents": 8,
                               "max_parallel_tasks": max_parallel,
                               "max_runtime_seconds": 600})


class PreFlightTestBase(unittest.TestCase):
    """Inject a fake HTTP probe so tests never need a live endpoint."""

    def setUp(self):
        self._registry = pf.ConnectionRegistry()
        self._probe_results = {}
        # Fresh module-level registry: connection states must not leak
        # across tests through the 60s TTL cache.
        self._orig_registry = pf._REGISTRY
        pf._REGISTRY = self._registry
        self._state = _TempState(self)
        self._state.__enter__()

        def fake_probe(url, timeout=2.0):
            for name, reachable in self._probe_results.items():
                if pf.mcp_url(name) == url:
                    return (reachable, "fake probe", 1)
            return False, "fake probe (no mapping)", 1

        self._orig_probe = pf._probe_http
        pf._probe_http = fake_probe

    def tearDown(self):
        pf._probe_http = self._orig_probe
        pf._REGISTRY = self._orig_registry
        self._state.__exit__(None, None, None)

    def set_conn(self, name, reachable):
        self._probe_results[name] = reachable


class TestConnectionStateMachine(PreFlightTestBase):

    def test_down_browser_blocks_and_burp_degrades(self):
        self.set_conn(pf.BROWSER_MCP, False)
        self.set_conn(pf.BURP_MCP, False)
        browser = pf.check_connection(pf.BROWSER_MCP, force=True,
                                      registry=self._registry)
        burp = pf.check_connection(pf.BURP_MCP, force=True,
                                   registry=self._registry)
        self.assertEqual(browser.status, MCP_BLOCKED)
        self.assertEqual(burp.status, MCP_DEGRADED)

    def test_up_connections_connect(self):
        self.set_conn(pf.BROWSER_MCP, True)
        self.set_conn(pf.BURP_MCP, True)
        for name in pf.MCP_CONNECTIONS:
            state = pf.check_connection(name, force=True,
                                        registry=self._registry)
            self.assertEqual(state.status, MCP_CONNECTED)

    def test_order_is_browser_then_burp(self):
        self.assertEqual(pf.MCP_CONNECTIONS, (pf.BROWSER_MCP, pf.BURP_MCP))

    def test_unknown_to_checking_to_terminal(self):
        state = pf.ConnectionState(name=pf.BROWSER_MCP)
        self.assertEqual(state.status, MCP_UNKNOWN)
        changed, _ = self._registry.update(pf.BROWSER_MCP, MCP_CHECKING)
        self.assertTrue(changed)  # UNKNOWN -> CHECKING is a real transition

    def test_transitions_counted(self):
        self.set_conn(pf.BROWSER_MCP, True)
        pf.check_connection(pf.BROWSER_MCP, force=True,
                            registry=self._registry)
        _, state = self._registry.update(pf.BROWSER_MCP, MCP_DEGRADED)
        self.assertGreaterEqual(state.transitions, 1)

    def test_unknown_connection_name_rejected(self):
        with self.assertRaises(ValueError):
            pf.check_connection("nope_mcp", registry=self._registry)


class TestInventoryAndManifest(PreFlightTestBase):

    def test_inventory_reports_binaries_and_mcp(self):
        self.set_conn(pf.BROWSER_MCP, False)
        self.set_conn(pf.BURP_MCP, True)
        caps = pf.inventory(probe_binaries=True)
        kinds = {c["kind"] for c in caps}
        self.assertIn("binary", kinds)
        self.assertIn("module", kinds)
        self.assertIn("mcp", kinds)
        curl = next(c for c in caps if c["name"] == "curl")
        self.assertEqual(curl["status"], "ready")
        self.assertTrue(curl["invoke_path"])  # resolved on PATH
        browser = next(c for c in caps if c["name"] == pf.BROWSER_MCP)
        self.assertEqual(browser["status"], MCP_BLOCKED)

    def test_run_preflight_persists_manifest_and_digest(self):
        self.set_conn(pf.BROWSER_MCP, True)
        self.set_conn(pf.BURP_MCP, False)
        manifest = pf.run_preflight("demo.example.com", probe_binaries=False)
        path = pf.manifest_path()
        self.assertTrue(path.is_file())
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["schema"], "bugwolf-preflight/v1")
        self.assertEqual(loaded["sha256"], manifest["sha256"])
        self.assertTrue((path.parent / "preflight.jsonl").is_file())
        # Unprobed binaries count ready; burp down -> degraded; browser up.
        self.assertEqual(manifest["summary"]["degraded"], 1)
        self.assertEqual(manifest["summary"]["blocked"], 0)
        self.assertIn("degraded", manifest["digest"])
        self.assertIn("burp_mcp", manifest["digest"])

    def test_artifact_ref_validates_against_contracts(self):
        from tools.runtime.contracts import validate_artifact_ref
        self.set_conn(pf.BROWSER_MCP, True)
        self.set_conn(pf.BURP_MCP, True)
        manifest = pf.run_preflight("demo.example.com", probe_binaries=False)
        ref = pf.artifact_ref(manifest)
        self.assertEqual(validate_artifact_ref(ref), [])
        mission = _mission()
        mission.preflight_manifest_ref = ref
        self.assertEqual(validate_mission_spec(mission.to_dict()), [])


class SchedulerTestBase(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        p1 = mock.patch.object(sch, "workspace_root", return_value=self.root)
        p1.start()
        self.addCleanup(p1.stop)
        p2 = mock.patch.object(sch, "_publish", lambda *a, **k: None)
        p2.start()
        self.addCleanup(p2.stop)

    def tearDown(self):
        self.td.cleanup()

    def _sched(self, domains=("recon", "web"), mission_id="bw-test-1"):
        s = sch.Scheduler(_mission(domains, mission_id))
        s.plan_mission()
        return s


class TestPlanning(SchedulerTestBase):

    def test_preflight_gate_first(self):
        s = self._sched()
        pre = s._nodes[sch.PREFLIGHT_TASK_ID]
        self.assertEqual(pre.spec["priority"], 0)
        self.assertEqual(pre.spec["task_type"], "preflight")

    def test_lane_roots_depend_on_gate(self):
        s = self._sched(domains=("recon", "web", "auth"))
        lanes = [n for n in s._nodes.values()
                 if n.task_id != sch.PREFLIGHT_TASK_ID]
        self.assertEqual(len(lanes), 3)
        for lane in lanes:
            self.assertIn(sch.PREFLIGHT_TASK_ID, lane.spec["dependencies"])

    def test_lane_ids_follow_domain_order(self):
        s = self._sched(domains=("recon", "web"))
        self.assertIn("lane-001-recon", s._nodes)
        self.assertIn("lane-002-web", s._nodes)

    def test_invalid_domain_rejected_by_contracts(self):
        s = sch.Scheduler(_mission(domains=("not-a-domain",),
                                   mission_id="bw-bad"))
        # MissionSpec validation runs at plan time via the lane specs.
        with self.assertRaises(sch.ContractViolation):
            s.plan_mission()


class TestDispatch(SchedulerTestBase):

    def test_nothing_runnable_before_gate(self):
        s = self._sched()
        self.assertEqual([n.task_id for n in s.runnable()],
                         [sch.PREFLIGHT_TASK_ID])

    def test_gate_opens_lanes_within_budget(self):
        s = self._sched(domains=("recon", "web", "auth", "fuzz"),
                        mission_id="bw-gate")
        s.record_preflight({"sha256": "a" * 64, "digest": "capabilities: 3"})
        self.assertEqual(s._nodes[sch.PREFLIGHT_TASK_ID].status, "done")
        runnable_ids = [n.task_id for n in s.runnable()]
        self.assertEqual(len(runnable_ids), 4)  # budget max_parallel=4
        # Attack-first ordering: priority ascending (lane creation order).
        self.assertEqual(runnable_ids, ["lane-001-recon", "lane-002-web",
                                        "lane-003-auth", "lane-004-fuzz"])

    def test_budget_respected_when_active(self):
        s = self._sched(domains=("recon", "web", "auth"), mission_id="bw-cap")
        s.record_preflight({"sha256": "b" * 64})
        s.start("lane-001-recon")
        s.start("lane-002-web")
        runnable_ids = [n.task_id for n in s.runnable()]
        self.assertEqual(len(runnable_ids), 1)  # 4 - 2 active... budget=4
        # budget 4, active 2 -> 2 runnable, but only 1 pending lane left
        self.assertEqual(runnable_ids, ["lane-003-auth"])

    def test_lead_carrying_tasks_jump_the_queue(self):
        s = self._sched(domains=("recon", "web"), mission_id="bw-lead")
        s.record_preflight({"sha256": "c" * 64})
        # Same priority: the lead-carrying task beats FIFO sequence order.
        s._nodes["lane-001-recon"].spec["priority"] = 1
        s._nodes["lane-002-web"].spec["priority"] = 1
        s._nodes["lane-002-web"].lead_ids = ["LEAD-1"]
        ordered = [n.task_id for n in s.runnable()]
        self.assertEqual(ordered[0], "lane-002-web")


class TestRecording(SchedulerTestBase):

    def _good_result(self, task_id="lane-001-recon", open_leads=None):
        return {
            "task_id": task_id, "agent_role": "recon", "status": "completed",
            "summary": "ran probes",
            "tool_receipts": [{"tool": "live_executor",
                               "command": "execute_probe"}],
            "evidence_refs": ["evid-0001"],
            "open_leads": list(open_leads or []),
        }

    def test_valid_result_completes_task(self):
        s = self._sched(mission_id="bw-rec1")
        s.record_preflight({"sha256": "d" * 64})
        issues = s.record("lane-001-recon", self._good_result())
        self.assertEqual(issues, [])
        self.assertEqual(s._nodes["lane-001-recon"].status, "done")
        # Durable result log exists under the mission's orchestrator state.
        mission_dir = self.root / "state" / "orchestrator" / "bw-rec1"
        self.assertTrue(any(mission_dir.rglob("*.jsonl")))

    def test_rejected_result_leaves_task_untouched(self):
        s = self._sched(mission_id="bw-rec2")
        s.record_preflight({"sha256": "e" * 64})
        bad = self._good_result()
        # Anti-stalling: strip tool receipts AND evidence/artifacts so the
        # completed result is pure prose.
        bad.pop("tool_receipts")
        bad.pop("evidence_refs")
        issues = s.record("lane-001-recon", bad)
        self.assertTrue(issues)
        self.assertIn("anti-stalling", issues[0])
        self.assertEqual(s._nodes["lane-001-recon"].status, "pending")

    def test_open_leads_rejected_on_completed_result(self):
        s = self._sched(mission_id="bw-rec3")
        s.record_preflight({"sha256": "f" * 64})
        issues = s.record("lane-001-recon",
                          self._good_result(open_leads=["LEAD-9"]))
        self.assertTrue(any("R6" in i for i in issues))

    def test_partial_result_keeps_leads_open(self):
        s = self._sched(mission_id="bw-rec4")
        s.record_preflight({"sha256": "0" * 64})
        result = self._good_result(open_leads=["LEAD-7"])
        result["status"] = "agent_partial"
        issues = s.record("lane-001-recon", result)
        self.assertEqual(issues, [])
        self.assertEqual(s._nodes["lane-001-recon"].lead_ids, ["LEAD-7"])


class TestRecovery(SchedulerTestBase):

    def test_blocked_tasks_reopen_on_connection_restore(self):
        s = self._sched(domains=("web",), mission_id="bw-block")
        s.record_preflight({"sha256": "1" * 64})
        s.mark_blocked("lane-001-web",
                       "browser_mcp blocked: extension unreachable")
        self.assertEqual(s._nodes["lane-001-web"].status, "blocked")
        reopened = s.reopen_blocked("browser_mcp")
        self.assertEqual(reopened, 1)
        self.assertEqual(s._nodes["lane-001-web"].status, "pending")

    def test_resume_reports_lead_first_and_no_rerun(self):
        s = self._sched(domains=("recon", "web"), mission_id="bw-resume")
        s.record_preflight({"sha256": "2" * 64})
        s.start("lane-001-recon")
        partial = {"task_id": "lane-001-recon", "agent_role": "recon",
                   "status": "agent_partial", "summary": "progress",
                   "tool_receipts": [{"tool": "x", "command": "y"}],
                   "evidence_refs": ["evid-1"], "open_leads": ["LEAD-42"]}
        self.assertEqual(s.record("lane-001-recon", partial), [])
        # Simulate a restart: reload the graph from disk.
        s2 = sch.Scheduler.load("bw-resume")
        report = s2.resume()
        self.assertEqual(report["done"], 2)  # preflight + partial lane
        # Finished work is never re-run; the open lead is not buried --
        # it is reported for the escalation lane to pick up.
        self.assertNotIn("lane-001-recon", report["lead_first"])
        self.assertIn("LEAD-42", report["open_leads"])

    def test_graph_round_trips_through_disk(self):
        s = self._sched(domains=("recon", "web", "auth"),
                        mission_id="bw-round")
        s.record_preflight({"sha256": "3" * 64})
        s.mark_blocked("lane-003-auth", "burp_mcp degraded")
        s2 = sch.Scheduler.load("bw-round")
        self.assertEqual(s2._nodes["lane-003-auth"].status, "blocked")
        self.assertEqual(s2._nodes[sch.PREFLIGHT_TASK_ID].status, "done")
        self.assertEqual(s2.mission.mission_id, "bw-round")


if __name__ == "__main__":
    unittest.main()

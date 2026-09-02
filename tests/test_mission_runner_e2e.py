#!/usr/bin/env python3
"""Phase 4 end-to-end: lead protocol + first VulnBank mission.

Lead-protocol contract (plan v2 section 5.5):
  * R1: open_lead is the only way an insight becomes durable; every lead
    lands in the append-only journal immediately;
  * R2: close_exhausted raises while matrix/research/ladder blockers remain
    (a lead can never close as BUDGET-EXHAUSTED prematurely);
  * PWNED requires evidence; resume rebuilds state from the journal;
  * exhaustion_blockers()/closeability() are operator-visible.

E2E contract (Phase 4 exit criterion):
  MissionSpec -> Scheduler.plan_mission -> preflight gate recorded ->
  recon/web_api/verify/report lanes drained -> deterministic hunt families
  open leads -> verify lane replays them independently -> report carries
  replay-confirmed findings.  Runs against a live in-process VulnBank
  fixture (skips when lab/vulnbank/server.py is absent).
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec, validate_task_result
from tools.runtime.lead_protocol import (
    LeadStore, TIER_T0, TIER_T1, TIER_T2, TIER_T4,
)
from tools.runtime.mission_runner import MissionRunner, http_probe

ROOT = Path(__file__).resolve().parents[1]
LAB_SERVER = ROOT / "lab" / "vulnbank" / "server.py"


def _boot_lab():
    if not LAB_SERVER.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("vulnbank_server", LAB_SERVER)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["vulnbank_server.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/tech.json", timeout=2) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.1)
    return base, (lambda: (server.shutdown(), server.server_close()))


class LeadProtocolTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.store = LeadStore("bw-lp-test").load()

    def tearDown(self):
        # Restore before cleanup: tests after us must not inherit a
        # deleted temp dir (that poisoned the trigger-ledger suite).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        self._td.cleanup()

    def test_r1_open_lead_is_durable_and_reloadable(self):
        lead = self.store.open_lead(
            title="test anomaly", mission_id="bw-lp-test",
            target="lab", bug_class="waf_bypass", surface="/x",
            signal="waf_block")
        reloaded = LeadStore("bw-lp-test").load()
        self.assertEqual([l.lead_id for l in reloaded.list_leads()],
                         [lead.lead_id])

    def test_r2_exhaustion_guard_blocks_premature_closure(self):
        lead = self.store.open_lead(
            title="premature close", mission_id="bw-lp-test", target="lab",
            bug_class="auth_bypass", signal="anomaly")
        with self.assertRaises(ValueError) as ctx:
            self.store.close_exhausted(lead.lead_id)
        message = str(ctx.exception)
        self.assertIn("untried techniques", message)
        self.assertIn("research refresh", message)
        self.assertIn("ladder at T0", message)

    def test_r2_pwned_requires_and_keeps_evidence(self):
        lead = self.store.open_lead(
            title="evidence check", mission_id="bw-lp-test", target="lab",
            bug_class="generic", signal="verbose_error")
        self.store.close_pwned(lead.lead_id, evidence_ref="ev-42")
        stored = self.store.get(lead.lead_id)
        self.assertEqual(stored.status, "PWNED")
        self.assertIn("ev-42", stored.evidence_refs)

    def test_escalation_never_moves_down(self):
        lead = self.store.open_lead(
            title="ladder check", mission_id="bw-lp-test", target="lab",
            bug_class="generic", signal="gut_feeling")
        self.store.escalate(lead.lead_id, TIER_T2, reason="research")
        # escalating downward is a no-op (tier unchanged)
        self.store.escalate(lead.lead_id, TIER_T0, reason="should not move")
        self.assertEqual(self.store.get(lead.lead_id).tier, TIER_T2)

    def test_closeability_reports_blockers(self):
        lead = self.store.open_lead(
            title="closeability", mission_id="bw-lp-test", target="lab",
            bug_class="injection", signal="anomaly")
        report = self.store.closeability(self.store.get(lead.lead_id))
        self.assertFalse(report["can_close_pwned"])
        self.assertTrue(report["exhaustion_blockers"])
        self.store.close_pwned(lead.lead_id, evidence_ref="ev-1")
        report = self.store.closeability(self.store.get(lead.lead_id))
        self.assertTrue(report["can_close_pwned"])


class MissionE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base, cls._shutdown_lab = _boot_lab()

    @classmethod
    def tearDownClass(cls):
        if cls._shutdown_lab is not None:
            cls._shutdown_lab()
            cls._shutdown_lab = None

    def setUp(self):
        if self.base is None:
            self.skipTest("lab fixture not present (lab/vulnbank/server.py)")
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name

    def tearDown(self):
        # Restore before cleanup (see LeadProtocolTest.tearDown).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        self._td.cleanup()

    def _mission(self, mission_id="bw-e2e"):
        return MissionSpec(
            mission_id=mission_id, target="vulnbank.local",
            domains=["recon", "web_api", "verify", "report"],
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 300})

    def test_full_mission_finds_confirms_and_reports(self):
        runner = MissionRunner(self._mission(), base_url=self.base)
        report = runner.run()
        counts = report["counts"]
        # BOLA x2 + WAF bypass x2 (two headers) + fuzz x3 = 7 findings.
        self.assertEqual(counts["findings"], 7)
        self.assertEqual(counts["refuted"], 0)
        self.assertEqual(counts["open"], 1)  # GraphQL lead: honest, open
        self.assertEqual(counts["total_leads"], 8)
        # All 4 lane tasks drained through the scheduler with no rejections.
        self.assertEqual(len(report["tasks"]), 4)
        self.assertFalse([e for e in report["events"]
                          if e["event"] == "result_rejected"])
        # The WAF-bypass finding is differential-proven (403 -> 200).
        surfaces = {f["surface"] for f in report["findings"]}
        self.assertIn("/api/gateway", surfaces)
        for finding in report["findings"]:
            self.assertTrue(finding["evidence"])

    def test_open_graphql_lead_survives_resume(self):
        mission = self._mission("bw-e2e-resume")
        MissionRunner(mission, base_url=self.base).run()
        reloaded = LeadStore(mission.mission_id).load()
        open_leads = reloaded.open_lead_ids()
        self.assertEqual(len(open_leads), 1)
        self.assertIn("graphql", open_leads[0].lower())

    def test_probe_result_records_headers(self):
        result = http_probe(self.base + "/tech.json")
        self.assertEqual(result.status, 200)
        self.assertIn("content-type", result.headers)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Phase 4 end-to-end: lead protocol + full-lane mission (real-world plugin).

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
  replay-confirmed findings.

Real-world plugin policy: production hunting binds to operator-declared
surfaces only -- the runner has no shipped target defaults.  These tests
declare the surfaces explicitly against the deterministic stub target
(``tests/_stub_target.py``), which stands in for an operator target in CI.
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
STUB_TARGET = ROOT / "tests" / "_stub_target.py"

# Operator-declared surfaces for the e2e missions (as an operator would pass
# --paths / declare in intake): object refs, blocked gateway, fuzz endpoint,
# GraphQL, and two money-flow surfaces for the FIN lane.
OPERATOR_PATHS = [
    "/api/users/1", "/api/users/2", "/api/gateway", "/api/ingest",
    "/graphql", "/api/checkout", "/api/voucher/redeem",
]


def _boot_stub_target():
    if not STUB_TARGET.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("stub_target", STUB_TARGET)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["_stub_target.py"]
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
            target="stub-target.local", bug_class="waf_bypass", surface="/x",
            signal="waf_block")
        reloaded = LeadStore("bw-lp-test").load()
        self.assertEqual([l.lead_id for l in reloaded.list_leads()],
                         [lead.lead_id])

    def test_r2_exhaustion_guard_blocks_premature_closure(self):
        lead = self.store.open_lead(
            title="premature close", mission_id="bw-lp-test",
            target="stub-target.local",
            bug_class="auth_bypass", signal="anomaly")
        with self.assertRaises(ValueError) as ctx:
            self.store.close_exhausted(lead.lead_id)
        message = str(ctx.exception)
        self.assertIn("untried techniques", message)
        self.assertIn("research refresh", message)
        self.assertIn("ladder at T0", message)

    def test_r2_pwned_requires_and_keeps_evidence(self):
        lead = self.store.open_lead(
            title="evidence check", mission_id="bw-lp-test",
            target="stub-target.local", bug_class="generic",
            signal="verbose_error")
        self.store.close_pwned(lead.lead_id, evidence_ref="ev-42")
        stored = self.store.get(lead.lead_id)
        self.assertEqual(stored.status, "PWNED")
        self.assertIn("ev-42", stored.evidence_refs)

    def test_escalation_never_moves_down(self):
        lead = self.store.open_lead(
            title="ladder check", mission_id="bw-lp-test",
            target="stub-target.local", bug_class="generic",
            signal="gut_feeling")
        self.store.escalate(lead.lead_id, TIER_T2, reason="research")
        # escalating downward is a no-op (tier unchanged)
        self.store.escalate(lead.lead_id, TIER_T0, reason="should not move")
        self.assertEqual(self.store.get(lead.lead_id).tier, TIER_T2)

    def test_closeability_reports_blockers(self):
        lead = self.store.open_lead(
            title="closeability", mission_id="bw-lp-test",
            target="stub-target.local",
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
        cls.base, cls._shutdown_stub = _boot_stub_target()

    @classmethod
    def tearDownClass(cls):
        if cls._shutdown_stub is not None:
            cls._shutdown_stub()
            cls._shutdown_stub = None

    def setUp(self):
        if self.base is None:
            self.skipTest("stub target not present (tests/_stub_target.py)")
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
            mission_id=mission_id, target="stub-target.local",
            domains=["recon", "web_api", "verify", "report"],
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 300})

    def _runner(self, mission):
        return MissionRunner(mission, base_url=self.base,
                             paths=list(OPERATOR_PATHS))

    def test_full_mission_finds_confirms_and_reports(self):
        report = self._runner(self._mission()).run()
        counts = report["counts"]
        # BOLA template x1 (consolidated: one surface, full technique matrix)
        # + WAF gateway x1 + FIN checkout x1 + fuzz x3 = 6 findings;
        # GraphQL stays open (honest generic-class lead).
        self.assertEqual(counts["findings"], 6)
        self.assertEqual(counts["refuted"], 0)
        self.assertEqual(counts["open"], 1)
        self.assertEqual(counts["total_leads"], 7)
        # All 4 lane tasks drained through the scheduler with no rejections.
        self.assertEqual(len(report["tasks"]), 4)
        self.assertFalse([e for e in report["events"]
                          if e["event"] == "result_rejected"])
        # The WAF-bypass finding is differential-proven (403 -> 200).
        surfaces = {f["surface"] for f in report["findings"]}
        self.assertIn("/api/gateway", surfaces)
        self.assertIn("/api/checkout", surfaces)  # FIN lane fired
        for finding in report["findings"]:
            self.assertTrue(finding["evidence"])

    def test_bola_lead_is_consolidated_with_full_matrix(self):
        mission = self._mission("bw-e2e-bola")
        self._runner(mission).run()
        store = LeadStore(mission.mission_id).load()
        bola = [l for l in store.list_leads() if l.bug_class == "access_control"]
        # One lead per TEMPLATE (both /api/users/{id} hits collapse), not one
        # per ID -- the matrix lives on the template-level lead.
        self.assertEqual(len(bola), 1)
        lead = bola[0]
        self.assertEqual(lead.status, "PWNED")
        logged = {e["technique"] for e in lead.technique_log}
        self.assertEqual(logged, {"direct-object-reference", "id-enumeration",
                                  "role-override", "mass-assignment",
                                  "hidden-field", "scope-confusion"})
        winner = next(e for e in lead.technique_log
                      if e["outcome"] == "success")
        self.assertEqual(winner["technique"], "direct-object-reference")

    def test_waf_lead_carries_full_matrix_and_t1_escalation(self):
        mission = self._mission("bw-e2e-matrix")
        self._runner(mission).run()
        store = LeadStore(mission.mission_id).load()
        waf_leads = [l for l in store.list_leads()
                     if l.bug_class == "waf_bypass"]
        self.assertEqual(len(waf_leads), 1)
        lead = waf_leads[0]
        self.assertEqual(lead.status, "PWNED")
        # R3 depth: all six matrix techniques recorded-tried exactly once.
        logged = {e["technique"] for e in lead.technique_log}
        self.assertEqual(
            logged, {"header-original-url", "path-obfuscation",
                     "encoding-variants", "parser-differential",
                     "case-rotation", "payload-splitting"})
        winner = next(e for e in lead.technique_log
                      if e["outcome"] == "success")
        self.assertEqual(winner["technique"], "header-original-url")
        self.assertGreaterEqual(lead.tier, TIER_T1)
        self.assertTrue(any("pass@k" in h["reason"]
                            for h in lead.escalation_history))

    def test_fin_lead_carries_full_matrix_and_registry_ids(self):
        from tools.runtime.mission_runner import FIN_TECHNIQUES
        mission = self._mission("bw-e2e-fin")
        self._runner(mission).run()
        store = LeadStore(mission.mission_id).load()
        fin = [l for l in store.list_leads()
               if l.bug_class == "business_logic"]
        # One consolidated lead per money surface; the stub declares two.
        self.assertEqual(len(fin), 1)
        lead = fin[0]
        self.assertEqual(lead.status, "PWNED")
        self.assertIn("/api/checkout", lead.surface)
        # R3 depth: the full FIN technique set was tried on the lead.
        logged = {e["technique"] for e in lead.technique_log}
        self.assertTrue(set(FIN_TECHNIQUES) <= logged)
        self.assertIn("price-trust", logged)
        # Registry linkage: FIN-PARAM* ids land on the price-trust attempt.
        price = next(e for e in lead.technique_log
                     if e["technique"] == "price-trust")
        self.assertTrue(any(r.startswith("FIN-PARAM")
                            for r in price.get("registry_ids", [])))
        # T1 escalation with the pass@k reason.
        self.assertGreaterEqual(lead.tier, TIER_T1)
        self.assertTrue(any("pass@k" in h["reason"]
                            for h in lead.escalation_history))
        # A FIN-NUM anomaly was recorded by the format-mutation sweep.
        fmt = [e for e in lead.technique_log
               if e["technique"] == "format-mutation-matrix"]
        self.assertTrue(fmt and fmt[0]["outcome"] == "success")
        self.assertTrue(any(r.startswith("FIN-NUM")
                            for r in fmt[0].get("registry_ids", [])))

    def test_fin_replay_uses_winning_technique(self):
        from tools.runtime.mission_runner import replay_fin_technique
        mission = self._mission("bw-e2e-fin-replay")
        self._runner(mission).run()
        store = LeadStore(mission.mission_id).load()
        fin = next(l for l in store.list_leads()
                   if l.bug_class == "business_logic")
        winner = next(e["technique"] for e in reversed(fin.technique_log)
                      if e["outcome"] == "success")
        # Independent replay confirms the winning FIN technique...
        self.assertIs(replay_fin_technique(self.base, fin.surface, winner),
                      True)
        # ...and an absent technique is undecidable, never a fake verdict.
        self.assertIsNone(replay_fin_technique(self.base, fin.surface,
                                               "nonexistent-technique"))

    def test_waf_replay_uses_winning_technique(self):
        from tools.runtime.mission_runner import (
            replay_bypass_technique, WAF_BYPASS_TECHNIQUES,
        )
        self.assertEqual(len(WAF_BYPASS_TECHNIQUES), 6)
        hit = replay_bypass_technique(self.base, "/api/gateway",
                                      "header-original-url")
        self.assertIsNotNone(hit)
        self.assertTrue(hit.ok)
        self.assertIsNone(replay_bypass_technique(
            self.base, "/api/gateway", "path-obfuscation"))

    def test_open_graphql_lead_survives_resume(self):
        mission = self._mission("bw-e2e-resume")
        self._runner(mission).run()
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

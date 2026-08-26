#!/usr/bin/env python3
"""F0.5 strict-gate campaign wiring tests.

Covers:
  * completing a thread runs the strict gate automatically
  * low-confidence findings: DEMOTED + quarantined, never in the findings
    ledger, never counted report-eligible
  * evidence-rich findings: CONFIRMED, appended to findings.jsonl
    (chain_orchestrator-compatible schema), counted report-eligible
  * idempotency — a thread is evaluated exactly once
  * refuted threads skip the gate entirely
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.campaign as campaign_mod
from tools.harness_guard import initialize as initialize_contract


class TestF05CampaignGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"
        self.addCleanup(self._cleanup)

        from tools.campaign_orchestrator import CampaignOrchestrator
        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text("# BugWolf\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "vps"}))
        self.scope = self.root / "scope.json"
        self.scope.write_text(json.dumps({"authorized": True,
                                          "in_scope_domains": ["api.example.test"]}))
        self.orch = CampaignOrchestrator("api.example.test", mode="web")
        self.orch.initialize()
        self.orch.complete_workflow_stage("authorization",
                                          scope_file=str(self.scope))

    def _cleanup(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------

    def _spawn_thread(self):
        self.orch.register_discovered_assets(
            [{"hostname": "api.example.test", "type": "web_api"}])
        assets = self.orch.campaign.list_assets()
        self.orch.register_recon(
            assets[0].asset_id,
            endpoints=["https://api.example.test/v1/users"])
        unit = self.orch.get_next_research_unit()
        return unit["context"]["thread_id"]

    @property
    def learning_store(self):
        return self.root / "state" / "learning" / "api.example.test.jsonl"

    @property
    def findings_ledger(self):
        return self.root / "state" / "sessions" / "api.example.test" \
            / "findings.jsonl"

    def _complete_thread(self, tid, **kwargs):
        self.orch.register_thread_result(
            tid,
            action=kwargs.pop("action", "probe"),
            observation=kwargs.pop("observation", "signal observed"),
            conclusion=kwargs.pop("conclusion", "confirmed"),
            new_state="complete",
            confirmed_behavior=kwargs.pop("confirmed_behavior", ""),
            **kwargs)

    # -- tests -------------------------------------------------------------

    def test_low_confidence_finding_demoted_and_quarantined(self):
        tid = self._spawn_thread()
        self._complete_thread(tid)  # bare observation, no impact/evidence

        thread = self.orch.campaign.get_thread(tid)
        self.assertIn("final_verdict", thread.refutation)
        self.assertEqual(thread.refutation["final_verdict"], "demoted")
        self.assertFalse(thread.refutation["eligible_for_report"])
        self.assertTrue(thread.refutation["quarantined"])
        # Quarantined in the adaptive-learning store.
        records = [json.loads(line)
                   for line in self.learning_store.read_text().splitlines()]
        self.assertEqual(records[0]["kind"], "low-confidence-finding")
        self.assertEqual(records[0]["status"], "candidate")
        # Never entered the findings ledger, never counted report-eligible.
        self.assertFalse(self.findings_ledger.exists())
        state = self.orch.campaign.load()
        self.assertEqual(state.total_findings, 1)
        self.assertEqual(state.report_eligible_findings, 0)

    def test_rich_finding_confirmed_and_recorded(self):
        tid = self._spawn_thread()
        thread = self.orch.campaign.get_thread(tid)
        thread.evidence_ids = ["ev-1", "ev-2"]
        self.orch.campaign.save_thread(thread)
        self._complete_thread(
            tid,
            observation="sent id-swap payload and observed cross-account read",
            confirmed_behavior="read another user's profile via id manipulation")

        thread = self.orch.campaign.get_thread(tid)
        self.assertEqual(thread.refutation["final_verdict"], "confirmed")
        self.assertTrue(thread.refutation["eligible_for_report"])
        self.assertFalse(thread.refutation["quarantined"])
        self.assertGreaterEqual(thread.refutation["confidence"], 0.6)

        records = [json.loads(line)
                   for line in self.findings_ledger.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        finding = records[0]
        # chain_orchestrator-compatible schema.
        self.assertEqual(finding["state"], "FINDING")
        self.assertEqual(finding["bug_class"], thread.bug_class)
        self.assertEqual(finding["endpoint"], "https://api.example.test/v1/users")
        self.assertEqual(finding["refutation"]["final_verdict"], "confirmed")
        state = self.orch.campaign.load()
        self.assertEqual(state.report_eligible_findings, 1)
        # No quarantine record for an eligible finding.
        self.assertFalse(self.learning_store.exists())

    def test_gate_is_idempotent(self):
        tid = self._spawn_thread()
        thread = self.orch.campaign.get_thread(tid)
        thread.evidence_ids = ["ev-1"]
        self.orch.campaign.save_thread(thread)
        self._complete_thread(tid, observation="probe A triggered delay",
                              confirmed_behavior="time-based blind confirmed")
        # Re-registering the same completed thread changes nothing.
        self._complete_thread(tid, observation="again", confirmed_behavior="same")
        records = [json.loads(line)
                   for line in self.findings_ledger.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        state = self.orch.campaign.load()
        self.assertEqual(state.report_eligible_findings, 1)

    def test_refuted_thread_skips_the_gate(self):
        tid = self._spawn_thread()
        self.orch.register_thread_result(
            tid, observation="no signal", conclusion="not vulnerable",
            new_state="refuted")
        thread = self.orch.campaign.get_thread(tid)
        self.assertEqual(thread.refutation, {})
        self.assertFalse(self.learning_store.exists())
        self.assertFalse(self.findings_ledger.exists())
        self.assertEqual(self.orch.campaign.load().report_eligible_findings, 0)

    def test_status_surfaces_report_eligible_count(self):
        tid = self._spawn_thread()
        self._complete_thread(tid)  # low confidence -> not eligible
        status = self.orch.status()
        self.assertIn("report_eligible_findings", status["campaign"])
        self.assertEqual(status["campaign"]["report_eligible_findings"], 0)


if __name__ == "__main__":
    unittest.main()

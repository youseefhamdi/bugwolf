#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.campaign as campaign_mod
from tools.harness_guard import initialize as initialize_contract
from tools.stage_controller import WorkflowError
from tools.campaign_orchestrator import (
    CampaignOrchestrator, CampaignPhase, MAX_DISCOVERY_ROUNDS,
)

RESEARCH_SEQUENCE = [
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
]


class TestCampaignOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"

        # Pre-recon workflow artifacts (setup + environment-preflight).
        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text("# BugWolf\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "vps"}))
        scope = self.root / "scope.json"
        scope.write_text(json.dumps({
            "authorized": True, "in_scope_domains": ["example.test"]}))

        self.orch = CampaignOrchestrator("example.test", mode="web")
        self.orch.initialize()
        # Operator-declared authorization (never auto-completed).
        self.orch.complete_workflow_stage("authorization", scope_file=str(scope))

    def tearDown(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------

    def _register_assets(self, spec):
        self.orch.register_discovered_assets([
            {"hostname": host, "type": atype} for host, atype in spec])

    def _register_recon_for(self, hostname_or_id, endpoints=None):
        assets = self.orch.campaign.list_assets()
        asset = next((a for a in assets if a.asset_id == hostname_or_id), None)
        if asset is None:
            asset = next(a for a in assets if a.hostname == hostname_or_id)
        return self.orch.register_recon(
            asset.asset_id,
            endpoints=endpoints or [f"https://{asset.hostname}/"],
            tech=["test-stack 1.0"])

    def _exhaust_threads(self, *, max_steps=60):
        """Drive the campaign: handle recon units and refute thread units."""
        seen = []
        for _ in range(max_steps):
            unit = self.orch.get_next_research_unit()
            if unit is None:
                break
            phase = unit.get("campaign_phase")
            seen.append(phase)
            if phase == "recon":
                self._register_recon_for(unit["context"]["asset_id"])
            elif phase == "researching":
                tid = unit["context"].get("thread_id")
                if tid:
                    self.orch.register_thread_result(
                        tid, observation="no signal", conclusion="not vulnerable",
                        new_state="refuted")
                else:
                    break
            else:
                break  # discovery / research / chaining / workflow gate
        return seen

    def _write_sequence(self, *, latest_ready):
        seq_dir = self.root / "research" / "example.test"
        seq_dir.mkdir(parents=True, exist_ok=True)
        (seq_dir / "sequence.json").write_text(json.dumps({
            "latest_ready": latest_ready,
            "executions": [{
                "sequence": list(RESEARCH_SEQUENCE),
                "latest_ready": latest_ready,
                "runs": [] if latest_ready else [{"pending_searches": 3}],
            }],
        }))

    # -- tests -------------------------------------------------------------

    def test_initialize_records_workflow_manifest(self):
        wf = self.orch.workflow_status()
        self.assertEqual(wf["current_stage"], "passive-recon")
        self.assertTrue(wf["no_skip"])

    def test_recon_gate_blocks_threat_modeling_until_surface_registered(self):
        self._register_assets([("api.example.test", "web_api")])
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.RECON)
        asset = next(a for a in self.orch.campaign.list_assets()
                     if a.hostname == "api.example.test")
        self.assertEqual(asset.status.value, "queued")  # never auto-advanced

        self._register_recon_for("api.example.test",
                                 endpoints=["https://api.example.test/v1/users"])
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.RESEARCHING)
        self.assertIn("thread_id", unit["context"])
        # Threats must target the recon endpoint, not the bare hostname.
        self.assertEqual(unit.get("endpoint"), "https://api.example.test/v1/users")
        self.assertIn("https://api.example.test/v1/users", unit["objective"])

    def test_fallback_threats_cover_untyped_assets(self):
        self._register_assets([("bucket.example.test", "storage_bucket")])
        self._register_recon_for("bucket.example.test")
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.RESEARCHING)
        threads = self.orch.campaign.list_threads()
        bug_classes = {t.bug_class for t in threads}
        self.assertIn("public_bucket_access", bug_classes)
        self.assertGreaterEqual(len(threads), 1)

    def test_thread_result_registration_transitions_and_counts_findings(self):
        self._register_assets([("api.example.test", "web_api")])
        self._register_recon_for("api.example.test")
        unit = self.orch.get_next_research_unit()
        tid = unit["context"]["thread_id"]
        before = self.orch.campaign.load().total_findings
        thread = self.orch.register_thread_result(
            tid, observation="signal observed", conclusion="confirmed",
            new_state="complete", confirmed_behavior="auth bypass on /v1/admin")
        self.assertEqual(thread.state.value, "complete")
        self.assertEqual(thread.confirmed_behavior, "auth bypass on /v1/admin")
        self.assertEqual(self.orch.campaign.load().total_findings, before + 1)

    def test_assets_exhausted_exactly_once(self):
        self._register_assets([
            ("api.example.test", "web_api"),
            ("bucket.example.test", "storage_bucket"),
        ])
        self._exhaust_threads()
        state = self.orch.campaign.load()
        self.assertEqual(state.assets_exhausted, state.assets_discovered)
        # No double counting: exhausted never exceeds discovered.
        self.assertLessEqual(state.assets_exhausted, state.assets_discovered)

    def test_discovery_terminates_on_round_cap_then_research_gate(self):
        self._register_assets([("api.example.test", "web_api")])
        self._exhaust_threads()
        state = self.orch.campaign.load()
        self.assertEqual(state.discovery_rounds, 1)
        # Still under the cap -> another discovery round is offered.
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.DISCOVERING)
        self.assertLess(state.discovery_rounds, MAX_DISCOVERY_ROUNDS)

        self.orch.mark_discovery_complete()
        # All assets exhausted + discovery complete -> research gate fires
        # (no chaining until the 7-checkpoint sequence is fresh).
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.RESEARCH)

    def test_research_gate_blocks_chaining_until_sequence_fresh(self):
        self._register_assets([("api.example.test", "web_api")])
        self._exhaust_threads()
        self.orch.mark_discovery_complete()

        # Stale research (latest_ready false) -> refresh unit, not chaining.
        self._write_sequence(latest_ready=False)
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.RESEARCH)

        # Fresh research + workflow research stage complete -> chaining.
        self._write_sequence(latest_ready=True)
        current = self.orch.workflow_status().get("current_stage")
        if current == "research":
            self.orch.complete_workflow_stage("research")
        unit = self.orch.get_next_research_unit()
        self.assertEqual(unit["campaign_phase"], CampaignPhase.CHAINING)

    def test_workflow_stages_record_as_artifacts_appear(self):
        self._register_assets([("api.example.test", "web_api")])
        self._exhaust_threads()  # recon -> spawn -> refute -> exhaust (plan.jsonl)
        self.orch.mark_discovery_complete()
        self.orch.get_next_research_unit()  # auto-advance through maps

        # Research precedes coverage-plan in the pipeline and is never
        # auto-completed — it must be fresh (7-checkpoint sequence) first.
        stages = {s["name"]: s["status"] for s in
                  self.orch.workflow_status()["stages"]}
        self.assertEqual(stages["research"], "pending")
        self.assertEqual(stages["coverage-plan"], "pending")

        self._write_sequence(latest_ready=True)
        current = self.orch.workflow_status().get("current_stage")
        if current == "research":
            self.orch.complete_workflow_stage("research")
        self.orch.get_next_research_unit()  # auto-advance completes coverage-plan

        stages = {s["name"]: s["status"] for s in
                  self.orch.workflow_status()["stages"]}
        for stage in ("setup", "environment-preflight", "authorization",
                      "passive-recon", "asset-intelligence",
                      "technology-fingerprint", "maps", "research",
                      "coverage-plan"):
            self.assertEqual(stages[stage], "complete", stage)

    def test_register_recon_writes_stage_artifacts(self):
        self._register_assets([("api.example.test", "web_api")])
        self._register_recon_for("api.example.test")
        intel = list((self.root / "recon" / "example.test" / "asset-intel").glob("*.json"))
        self.assertEqual(len(intel), 1)
        tech = json.loads((self.root / "recon" / "example.test"
                           / "tech-fingerprint.json").read_text())
        self.assertIn("test-stack 1.0", tech["detected_tech"])

    def test_unknown_thread_result_raises(self):
        with self.assertRaises(ValueError):
            self.orch.register_thread_result("does-not-exist", observation="x")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.harness_guard import initialize as initialize_contract
from tools.stage_controller import STAGES, WorkflowController, WorkflowError


class TestStageController(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.target = "example.com"
        initialize_contract(str(self.project))
        (self.project / "BUGWOLF.md").write_text(
            "# BugWolf\n`BUGWOLF-HARNESS-CONTRACT-V2`\n")
        self.controller = WorkflowController(
            self.target, project_root=str(self.project), mode="web")
        self.controller.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def test_cli_start_emits_strict_json_and_setup_first(self):
        result = subprocess.run([
            sys.executable, "tools/stage_controller.py",
            "--project-root", str(self.project), "--target", self.target,
            "--mode", "web", "--start", "--json",
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["current_stage"], "setup")
        self.assertTrue(payload["no_skip"])

    def test_start_always_begins_at_setup(self):
        status = self.controller.status()
        self.assertEqual(status["current_stage"], "setup")
        self.assertEqual([stage["name"] for stage in status["stages"]], list(STAGES))
        self.assertTrue(status["no_skip"])
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("validation")

    def test_cannot_complete_later_stage_or_skip_artifacts(self):
        with self.assertRaises(WorkflowError):
            self.controller.complete("maps")
        self.controller.complete("setup")
        with self.assertRaises(WorkflowError):
            self.controller.complete("environment-preflight")
        # Completing a stage without its required artifact is refused.
        with self.assertRaises(WorkflowError):
            self.controller.complete("environment-preflight", artifacts=[])

    def _complete_to_maps(self):
        self.controller.complete("setup")
        env = self.project / "state" / "environment.json"
        env.parent.mkdir(parents=True)
        env.write_text(json.dumps({"location": "unknown"}))
        self.controller.complete("environment-preflight")

        scope = self.project / "scope.json"
        scope.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": [self.target],
        }))
        self.controller.complete("authorization", scope_file=str(scope))

        recon = self.project / "recon" / self.target
        recon.mkdir(parents=True)
        (recon / "recon-complete.json").write_text("{}")
        self.controller.complete("passive-recon")
        asset = recon / "asset-intel"
        asset.mkdir()
        (asset / "asset-inventory.json").write_text("{}")
        self.controller.complete("asset-intelligence")
        (recon / "tech-fingerprint.json").write_text("{}")
        self.controller.complete("technology-fingerprint")

    def test_paper_artifacts_are_automatically_ingested_and_required_by_maps(self):
        self.controller.complete("setup")
        env = self.project / "state" / "environment.json"
        env.parent.mkdir(parents=True)
        env.write_text(json.dumps({"location": "unknown"}))
        self.controller.complete("environment-preflight")
        scope = self.project / "scope.json"
        scope.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": [self.target],
        }))
        self.controller.complete("authorization", scope_file=str(scope))

        recon = self.project / "recon" / self.target
        recon.mkdir(parents=True)
        (recon / "recon-complete.json").write_text(json.dumps({"complete": True}))
        (recon / "https-traffic.json").write_text(json.dumps([
            {"session_id": "fixture", "direction": "out", "packet_length": 100,
             "uri_length": 100, "request_packet_length": 100},
        ]))
        audit = self.project / "audit"
        audit.mkdir()
        (audit / "agent-inventory.json").write_text(json.dumps({
            "agents": [{"id": "fixture-agent", "tools": [{"name": "read"}]}],
        }))

        status = self.controller.complete("passive-recon")
        paper_json = recon / "paper-intelligence" / "paper-intelligence.json"
        paper_map = self.project / "state" / "sessions" / self.target / "maps" / "paper-intelligence.md"
        self.assertTrue(paper_json.is_file())
        self.assertTrue(paper_map.is_file())
        payload = json.loads(paper_json.read_text())
        self.assertIn("https_fingerprint", payload)
        self.assertIn("agent_control_plane", payload)
        self.assertIn("paper-intelligence.md", paper_map.relative_to(self.project).as_posix())
        self.assertEqual(status["current_stage"], "asset-intelligence")

        asset = recon / "asset-intel"
        asset.mkdir()
        (asset / "asset-inventory.json").write_text("{}")
        self.controller.complete("asset-intelligence")
        (recon / "tech-fingerprint.json").write_text("{}")
        self.controller.complete("technology-fingerprint")
        maps = self.project / "state" / "sessions" / self.target / "maps"
        maps.mkdir(exist_ok=True)
        for name in ("asset.md", "trust.md", "authz.md", "state.md", "capability.md"):
            (maps / name).write_text(f"# {name}\n")
        maps_status = self.controller.complete("maps")
        maps_stage = next(item for item in maps_status["stages"] if item["name"] == "maps")
        self.assertIn("state/sessions/example.com/maps/paper-intelligence.md", maps_stage["artifacts"])
        self.assertIn("recon/example.com/paper-intelligence/paper-intelligence.json", maps_stage["artifacts"])

    def test_full_workflow_is_strictly_sequential(self):
        self._complete_to_maps()
        maps = self.project / "state" / "sessions" / self.target / "maps"
        maps.mkdir(parents=True)
        for name in ("asset.md", "trust.md", "authz.md", "state.md", "capability.md"):
            (maps / name).write_text(f"# {name}\n")
        self.controller.complete("maps")

        research = self.project / "research" / self.target
        research.mkdir(parents=True)
        research_manifest = {
            "latest_ready": False,
            "executions": [{"sequence": [
                "pre-hunt", "post-recon", "post-maps", "bypass",
                "post-findings", "escalation", "pre-report",
            ]}],
        }
        (research / "sequence.json").write_text(json.dumps(research_manifest))
        status = self.controller.complete("research")
        self.assertEqual(status["current_stage"], "coverage-plan")
        research_stage = next(item for item in status["stages"] if item["name"] == "research")
        self.assertEqual(research_stage["status"], "complete_pending")
        self.assertEqual(research_stage["quality"], "pending_latest")

        discovery = self.project / "recon" / self.target / "discovery"
        discovery.mkdir()
        (discovery / "plan.jsonl").write_text("{}\n")
        self.controller.complete("coverage-plan")
        self.assertEqual(self.controller.status()["current_stage"], "validation")
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("validation")

    def test_authorization_records_declared_scope_without_scope_enforcement(self):
        # UNCENSORED contract: authorization requires a declared scope file but
        # deliberately does NOT gate on target membership.
        self.controller.complete("setup")
        env = self.project / "state" / "environment.json"
        env.parent.mkdir(parents=True)
        env.write_text(json.dumps({"location": "unknown"}))
        self.controller.complete("environment-preflight")
        scope = self.project / "scope.json"
        scope.write_text(json.dumps({"authorized": True, "in_scope_domains": ["other.test"]}))
        status = self.controller.complete("authorization", scope_file=str(scope))
        self.assertEqual(status["current_stage"], "passive-recon")
        self.assertEqual(status["scope_file"], "scope.json")
        # Missing/unparseable scope files are still refused (artifact integrity).
        with self.assertRaises(WorkflowError):
            self.controller.complete("setup")
        fresh = WorkflowController(
            "missing-scope.test", project_root=str(self.project), mode="web")
        fresh.initialize()
        fresh.complete("setup")
        env.write_text(json.dumps({"location": "unknown"}))
        fresh.complete("environment-preflight")
        with self.assertRaises(WorkflowError):
            fresh.complete("authorization")
        bad = self.project / "bad-scope.json"
        bad.write_text("not json")
        with self.assertRaises(WorkflowError):
            fresh.complete("authorization", scope_file=str(bad))

    def test_manifest_is_append_only_by_history_and_atomic(self):
        self.controller.complete("setup")
        manifest = json.loads(self.controller.path.read_text())
        self.assertEqual(manifest["history"][0]["stage"], "setup")
        self.assertTrue(self.controller.path.is_file())
        self.assertFalse(self.controller.path.with_suffix(".json.tmp").exists())

    def test_complete_pending_research_can_be_upgraded_once_fresh(self):
        """Stale research records complete_pending; a fresh sequence upgrades it
        so validation is never permanently locked."""
        self._complete_to_maps()
        maps = self.project / "state" / "sessions" / self.target / "maps"
        maps.mkdir(parents=True)
        for name in ("asset.md", "trust.md", "authz.md", "state.md", "capability.md"):
            (maps / name).write_text(f"# {name}\n")
        self.controller.complete("maps")

        research = self.project / "research" / self.target
        research.mkdir(parents=True)
        seq = ["pre-hunt", "post-recon", "post-maps", "bypass",
               "post-findings", "escalation", "pre-report"]
        manifest = {"latest_ready": False, "executions": [{
            "sequence": seq, "latest_ready": False, "runs": [{"pending_searches": 2}]}]}
        (research / "sequence.json").write_text(json.dumps(manifest))
        status = self.controller.complete("research")
        research_stage = next(s for s in status["stages"] if s["name"] == "research")
        self.assertEqual(research_stage["status"], "complete_pending")
        # complete_pending must not record hashes (sequence.json will be rewritten)
        self.assertEqual(research_stage["artifact_hashes"], {})

        discovery = self.project / "recon" / self.target / "discovery"
        discovery.mkdir()
        (discovery / "plan.jsonl").write_text("{}\n")
        self.controller.complete("coverage-plan")
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("validation")

        # Fresh research run rewrites sequence.json -> upgrade re-completion.
        (research / "sequence.json").write_text(json.dumps({
            "latest_ready": True, "executions": [{
                "sequence": seq, "latest_ready": True, "runs": []}]}))
        status = self.controller.complete("research")
        research_stage = next(s for s in status["stages"] if s["name"] == "research")
        self.assertEqual(research_stage["status"], "complete")
        self.assertEqual(research_stage["quality"], "verified")
        # Validation now unblocked.
        self.controller.require_stage("validation")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Week 8 tests: self-eval harness + workflow integrity refresh.

Covers the two integration fixes from the final campaign validation:

1. self_eval_harness reads the workflow manifest from the canonical
   .bugwolf/workflows/<slug>.json (with state/workflows/ legacy fallback) and
   recognizes the manifest's ``name`` stage key — previously the eval scored
   workflow-12-stage 0/12 against a fully completed campaign because it looked
   in the wrong place and read the wrong key.

2. refresh_artifact_hashes skips integrity validation for the stage being
   refreshed: a legitimate campaign update (e.g. register_recon appending a
   per-asset record into the hashed asset-intel/ directory) can re-record its
   hashes and keep the gate satisfiable — while other completed stages still
   enforce integrity.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.harness_guard import initialize as initialize_contract
from tools.stage_controller import WorkflowController, WorkflowError
from tools.validation import self_eval_harness as evalh

TARGET = "synth.example"
MANDATORY = ["pre-hunt", "post-recon", "post-maps", "bypass",
             "post-findings", "escalation", "pre-report"]


def _make_workflow(project: Path, target: str = TARGET,
                   completed: int = 3) -> WorkflowController:
    """Start a workflow and complete ``completed`` stages with real artifacts."""
    initialize_contract(str(project))
    (project / "BUGWOLF.md").write_text(
        "# BugWolf\n`BUGWOLF-HARNESS-CONTRACT-V2`\n")
    controller = WorkflowController(target, project_root=str(project), mode="web")
    controller.initialize()
    controller.complete("setup")
    if completed >= 2:
        env = project / "state" / "environment.json"
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text(json.dumps({"location": "local"}))
        controller.complete("environment-preflight")
    if completed >= 3:
        scope = project / "scope.json"
        scope.write_text(json.dumps({"targets": [target]}))
        controller.complete("authorization", scope_file="scope.json")
    if completed >= 4:
        recon = project / "recon" / target / "recon-complete.json"
        recon.parent.mkdir(parents=True, exist_ok=True)
        recon.write_text(json.dumps({"complete": True}))
        controller.complete("passive-recon")
    return controller


class TestEvalHarnessWorkflowLocation(unittest.TestCase):
    """The eval must find the workflow in .bugwolf/workflows/ and read `name`."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.controller = _make_workflow(self.project, completed=3)

    def tearDown(self):
        self.tmp.cleanup()

    def test_canonical_workflow_location_scored(self):
        report = evalh.evaluate(TARGET, base_dir=str(self.project))
        tasks = {t.task_id: t for t in report.tasks}
        t1 = tasks["workflow-12-stage"]
        # setup / environment-preflight / authorization complete -> 3 milestones
        self.assertEqual(sum(1 for m in t1.milestones if m.passed), 3)
        self.assertFalse(t1.passed)  # 3/12 is not complete

    def test_legacy_state_workflows_fallback(self):
        # Move the manifest to the legacy location; eval must still find it.
        canonical = self.project / ".bugwolf" / "workflows"
        legacy = self.project / "state" / "workflows"
        legacy.mkdir(parents=True, exist_ok=True)
        for name in (f"{TARGET}.json", f"{TARGET}.chain.jsonl"):
            src = canonical / name
            if src.is_file():
                src.rename(legacy / name)
        report = evalh.evaluate(TARGET, base_dir=str(self.project))
        t1 = {t.task_id: t for t in report.tasks}["workflow-12-stage"]
        self.assertEqual(sum(1 for m in t1.milestones if m.passed), 3)

    def test_full_completion_scores_all_twelve(self):
        # Complete every stage with the deterministic default artifacts.
        c = self.controller
        recon_dir = self.project / "recon" / TARGET
        recon_dir.mkdir(parents=True, exist_ok=True)
        (recon_dir / "recon-complete.json").write_text(
            json.dumps({"complete": True}))
        (recon_dir / "tech-fingerprint.json").write_text(
            json.dumps({"stack": ["nginx"]}))
        intel = self.project / "recon" / TARGET / "asset-intel"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "history.jsonl").write_text("x\n")
        (intel / "delta.json").write_text("{}")
        maps = self.project / "state" / "sessions" / TARGET / "maps"
        maps.mkdir(parents=True, exist_ok=True)
        for name in ("asset.md", "trust.md", "authz.md", "state.md",
                     "capability.md"):
            (maps / name).write_text(f"# {name}\n")
        seq = self.project / "research" / TARGET / "sequence.json"
        seq.parent.mkdir(parents=True, exist_ok=True)
        seq.write_text(json.dumps({
            "schema": "research_execution/1.0",
            "executions": [{
                "sequence": MANDATORY,
                "latest_ready": True,
                "runs": [{"checkpoint": ck, "pending_searches": 0}
                         for ck in MANDATORY],
            }],
        }))
        discovery = self.project / "recon" / TARGET / "discovery"
        discovery.mkdir(parents=True, exist_ok=True)
        (discovery / "smuggling-plan.jsonl").write_text("{}\n")
        # Middle deterministic stages complete in order once artifacts exist.
        c.complete("passive-recon")
        c.complete("asset-intelligence")
        c.complete("technology-fingerprint")
        c.complete("maps")
        c.complete("research")
        c.complete("coverage-plan")
        for stage, artifact in (("validation", "cand.json"),
                                ("triage", "cand.json"),
                                ("report", "report.json")):
            path = self.project / artifact
            path.write_text("{}")
            c.complete(stage, artifacts=[artifact])
        report = evalh.evaluate(TARGET, base_dir=str(self.project))
        t1 = {t.task_id: t for t in report.tasks}["workflow-12-stage"]
        self.assertEqual(sum(1 for m in t1.milestones if m.passed), 12)
        self.assertTrue(t1.passed)

    def test_research_checkpoint_task_ordered(self):
        seq = self.project / "research" / TARGET / "sequence.json"
        seq.parent.mkdir(parents=True, exist_ok=True)
        seq.write_text(json.dumps({
            "executions": [{
                "sequence": MANDATORY + ["post-chain", "post-lab-verification"],
                "latest_ready": True,
            }],
        }))
        report = evalh.evaluate(TARGET, base_dir=str(self.project))
        t2 = {t.task_id: t for t in report.tasks}["research-7-checkpoint"]
        self.assertTrue(t2.passed)


class TestRefreshArtifactHashesIntegritySkip(unittest.TestCase):
    """A legit campaign update can refresh the affected stage's hashes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.controller = _make_workflow(self.project, completed=4)
        # Complete asset-intelligence with a real asset-intel/ directory.
        self.intel = self.project / "recon" / TARGET / "asset-intel"
        self.intel.mkdir(parents=True, exist_ok=True)
        (self.intel / "history.jsonl").write_text("snapshot1\n")
        (self.intel / "delta.json").write_text("{}")
        self.controller.complete("asset-intelligence")

    def tearDown(self):
        self.tmp.cleanup()

    def test_refresh_allows_campaign_update_then_advance(self):
        # The campaign appends a per-asset record into the hashed directory.
        (self.intel / "asset-abc.json").write_text(json.dumps(
            {"asset_id": "abc", "recon_complete": True}))
        # Without refresh this must now be refused…
        with self.assertRaises(WorkflowError):
            self.controller.refresh_artifact_hashes("technology-fingerprint")
        # …and a stale advance attempt must also refuse.
        with self.assertRaises(WorkflowError):
            self.controller.complete("technology-fingerprint")
        # The audited refresh of the affected stage succeeds.
        result = self.controller.refresh_artifact_hashes("asset-intelligence")
        self.assertEqual(result["current_stage"], "technology-fingerprint")
        # Advance now works (hashes re-recorded).
        fp = self.project / "recon" / TARGET / "tech-fingerprint.json"
        fp.write_text(json.dumps({"stack": ["nginx"]}))
        result = self.controller.complete("technology-fingerprint")
        self.assertEqual(result["current_stage"], "maps")

    def test_refresh_requires_completed_stage(self):
        with self.assertRaises(WorkflowError):
            self.controller.refresh_artifact_hashes("maps")

    def test_other_stages_still_enforce_integrity_after_refresh(self):
        (self.intel / "asset-abc.json").write_text("{}")
        self.controller.refresh_artifact_hashes("asset-intelligence")
        # Tamper with the tech-fingerprint artifact that is NOT yet recorded —
        # only recorded completed stages are protected; the point here is that
        # completing tech-fingerprint records hashes and later tampering is
        # caught even after an unrelated refresh.
        fp = self.project / "recon" / TARGET / "tech-fingerprint.json"
        fp.write_text(json.dumps({"stack": ["nginx"]}))
        self.controller.complete("technology-fingerprint")
        fp.write_text(json.dumps({"stack": ["apache"]}))  # tamper
        with self.assertRaises(WorkflowError):
            self.controller.refresh_artifact_hashes("maps")
        with self.assertRaises(WorkflowError):
            self.controller.complete("maps")


class TestEvalHarnessDeterminism(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        _make_workflow(self.project, completed=3)

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_workspace_scores_zero_not_error(self):
        report = evalh.evaluate("nope.example", base_dir=str(self.project))
        data = report.to_dict()
        self.assertEqual(data["task_count"], 6)
        self.assertEqual(data["tasks_passed"], 0)
        self.assertEqual(data["score_pct"], 0.0)

    def test_report_persisted(self):
        report = evalh.evaluate(TARGET, base_dir=str(self.project))
        out = evalh.write_report(report, base_dir=str(self.project))
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], evalh.SCHEMA)
        self.assertEqual(data["task_count"], 6)


if __name__ == "__main__":
    unittest.main()

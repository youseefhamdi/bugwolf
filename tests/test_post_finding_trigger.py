#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.post_finding_trigger import load_latest_trigger, trigger_after_finding
from tools.state import _state_dir, add_finding, get_findings


class TestPostFindingTrigger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = "trigger.example"
        self.state_root = self.root / "state"
        self.patcher = patch.multiple("tools.state", ROOT=self.root,
                                      STATE_ROOT=self.root / "state")
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def _finding(self, **overrides):
        value = {
            "title": "Observed authorization boundary signal",
            "endpoint": "/api/users/owned",
            "method": "GET",
            "bug_class": "idor",
            "severity": "high",
            "description": "redacted baseline and cross-account observation",
        }
        value.update(overrides)
        return value

    def test_add_finding_runs_hard_trigger_and_persists_queue(self):
        finding_id = add_finding(self.target, self._finding())
        directory = _state_dir(self.target)
        latest = load_latest_trigger(self.target, project_root=self.root)

        self.assertTrue(finding_id)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["status"], "finding")
        self.assertEqual(latest["finding_id"], finding_id)
        self.assertTrue(latest["queue"])
        self.assertTrue(all(item["automatic_execution"] is False
                            for item in latest["queue"]))
        self.assertTrue(all("human_review" in item["requires"]
                            for item in latest["queue"]))
        self.assertTrue((directory / "post-finding-triggers.jsonl").is_file())
        self.assertTrue((directory / "post-finding-queue.jsonl").is_file())
        self.assertEqual(len(get_findings(self.target)), 1)

    def test_missing_evidence_blocks_escalation_but_preserves_repair_queue(self):
        add_finding(self.target, self._finding(description=""))
        latest = load_latest_trigger(self.target, project_root=self.root)

        self.assertEqual(latest["status"], "blocked")
        self.assertIn("evidence_reference", latest["evidence"]["missing"])
        self.assertTrue(any(item["status"] == "blocked_missing_evidence"
                            for item in latest["queue"]))
        self.assertFalse(any(item["kind"] == "chain_review" and
                             item["status"] == "pending_review"
                             for item in latest["queue"]))
        self.assertEqual(len(get_findings(self.target)), 1)

    def test_add_finding_records_fallback_when_trigger_module_fails(self):
        with patch("tools.post_finding_trigger.trigger_after_finding",
                   side_effect=RuntimeError("trigger import path failed")):
            finding_id = add_finding(self.target, self._finding())
        latest = load_latest_trigger(self.target, project_root=self.root)
        self.assertTrue(finding_id)
        self.assertEqual(latest["status"], "error")
        self.assertTrue(any(item["status"] == "blocked_trigger_error"
                            for item in latest["queue"]))
        self.assertEqual(len(get_findings(self.target)), 1)

    def test_chain_failure_is_explicit_and_never_execution_permission(self):
        finding = self._finding(finding_id="F-FAIL")
        with patch("tools.post_finding_trigger.refresh_chain_target",
                   side_effect=RuntimeError("synthetic refresh failure")):
            result = trigger_after_finding(self.target, finding,
                                           project_root=self.root)

        self.assertEqual(result["status"], "error")
        self.assertIn("synthetic refresh failure", result["error"])
        self.assertTrue(any(item["status"] == "blocked_trigger_error"
                             for item in result["queue"]))
        self.assertTrue(all(item["automatic_execution"] is False
                            for item in result["queue"]))
        self.assertTrue(result["gates"]["human_review_required"])
        self.assertFalse(result["gates"]["automatic_execution"])
        saved = json.loads((self.root / "state" / "sessions" / self.target /
                            "post-finding-latest.json").read_text())
        self.assertEqual(saved["status"], "error")


if __name__ == "__main__":
    unittest.main()

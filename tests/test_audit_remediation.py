#!/usr/bin/env python3
"""Regression tests for the canonical BugWolf remediation contracts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.runtime import preflight
from tools.runtime import scheduler
from tools.runtime.contracts import (
    MissionSpec,
    PROFILE_GOVERNED,
    PROFILE_LAB_UNCENSORED,
    RESULT_COMPLETED,
    TASK_FAILED,
    TASK_BUDGET_EXHAUSTED,
    validate_mission_spec,
)
from tools.runtime.mission_runner import MissionRunner
from tools.reporting import ReportingGate


class ContractRemediationTests(unittest.TestCase):
    def test_execution_profile_is_explicit_and_validated(self):
        mission = MissionSpec(mission_id="m-profile", target="target.test")
        self.assertEqual(mission.operation_profile, PROFILE_GOVERNED)
        self.assertEqual(validate_mission_spec(mission.to_dict()), [])
        invalid = mission.to_dict()
        invalid["operation_profile"] = "implicit"
        self.assertTrue(any("operation profile" in issue
                            for issue in validate_mission_spec(invalid)))
        lab = MissionSpec(mission_id="m-lab", target="target.test",
                          operation_profile=PROFILE_LAB_UNCENSORED)
        self.assertEqual(validate_mission_spec(lab.to_dict()), [])

    def test_mission_result_log_is_not_task_scoped(self):
        from tools.runtime.contracts import TaskResult, record_task_result, result_log_path
        with tempfile.TemporaryDirectory() as root:
            result = TaskResult(task_id="task-a", agent_role="recon",
                                status=RESULT_COMPLETED,
                                summary="probe completed",
                                evidence_refs=["e-1"],
                                mission_id="mission-a")
            self.assertEqual(record_task_result(result, project_root=root), [])
            expected = Path(root) / "state" / "orchestrator" / "mission-a" / "results.jsonl"
            self.assertEqual(result_log_path("mission-a", project_root=root), expected)
            self.assertTrue(expected.is_file())
            self.assertFalse((Path(root) / "state" / "orchestrator" / "task-a").exists())

    def test_scheduler_rejects_wrong_task_and_wrong_mission(self):
        with tempfile.TemporaryDirectory() as root:
            mission = MissionSpec(mission_id="mission-a", target="target.test",
                                  domains=["recon"])
            sched = scheduler.Scheduler(mission, project_root=root)
            sched.plan_mission()
            sched.record_preflight({"sha256": "a" * 64})
            wrong_task = {"task_id": "other", "agent_role": "recon",
                          "status": RESULT_COMPLETED, "summary": "x",
                          "evidence_refs": ["e"], "tool_receipts": []}
            issues = sched.record("lane-001-recon", wrong_task)
            self.assertTrue(any("identity mismatch" in issue for issue in issues))
            wrong_mission = dict(wrong_task, task_id="lane-001-recon",
                                 mission_id="mission-b")
            issues = sched.record("lane-001-recon", wrong_mission)
            self.assertTrue(any("mission_id" in issue for issue in issues))

    def test_preflight_receipt_detects_tampering(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(preflight, "inventory", return_value=[]), \
                 mock.patch.object(preflight, "connection_snapshot", return_value={}):
                manifest = preflight.run_preflight(
                    "target.test", project_root=root, probe_binaries=False,
                    mission_id="mission-a", operation_profile=PROFILE_GOVERNED)
            self.assertEqual(preflight.validate_manifest_for_mission(
                manifest, target="target.test", mission_id="mission-a"), [])
            manifest["target"] = "other.test"
            issues = preflight.validate_manifest_for_mission(
                manifest, target="target.test", mission_id="mission-a")
            self.assertTrue(any("target mismatch" in issue for issue in issues))
            self.assertTrue(any("sha256" in issue for issue in issues))

    def test_explicit_evidence_reference_requires_real_hashed_artifact(self):
        with tempfile.TemporaryDirectory() as root:
            artifact = Path(root) / "evidence.json"
            artifact.write_text("proof", encoding="utf-8")
            digest = __import__("hashlib").sha256(b"proof").hexdigest()
            finding = {
                "finding_id": "finding-artifact",
                "title": "verified behavior",
                "review_decision": "confirmed",
                "reproduction": "replay",
                "impact_proof": "unauthorized access",
                "affected_versions": "1.0",
                "remediation": "authorize object",
                "evidence_refs": [{"path": "evidence.json", "sha256": digest}],
            }
            gate = ReportingGate("target.test", project_root=root)
            checked = gate.check(finding)
            self.assertTrue(checked["reportable"])
            self.assertTrue(checked["evidence_integrity"]["valid"])

            finding["evidence_refs"] = [{"path": "missing.json", "sha256": digest}]
            rejected = gate.check(finding)
            self.assertFalse(rejected["reportable"])
            self.assertTrue(any("not found" in reason
                                for reason in rejected["refusal_reasons"]))

    def test_unsupported_lane_is_blocked_not_completed(self):
        with tempfile.TemporaryDirectory() as root:
            mission = MissionSpec(mission_id="mission-mobile", target="http://127.0.0.1:1",
                                  domains=["mobile"])
            runner = MissionRunner(mission, project_root=root,
                                   base_url=mission.target, browser_driver=False)
            blocked = runner._unsupported_lane(type("Node", (), {
                "spec": {"domain": "mobile"}
            })())
            self.assertEqual(blocked["status"], "blocked")
            self.assertIn("no executable", blocked["summary"])


class SchedulerFailureTests(unittest.TestCase):
    def _scheduler(self, root: str, *, budget=None):
        mission = MissionSpec(
            mission_id="failure-mission", target="target.test",
            domains=["recon"], budget=budget or {
                "max_parallel_tasks": 2,
                "max_runtime_seconds": 60,
            })
        sched = scheduler.Scheduler(mission, project_root=root)
        sched.plan_mission()
        sched.record_preflight({"sha256": "a" * 64})
        return sched

    def test_start_budget_failure_is_durable_and_terminal(self):
        with tempfile.TemporaryDirectory() as root:
            sched = self._scheduler(root, budget={"max_tasks": 1})
            # The preflight consumes the sole task slot; the lane cannot start.
            with self.assertRaises(scheduler.ContractViolation):
                sched.start("lane-001-recon")
            node = sched._nodes["lane-001-recon"]
            self.assertEqual(node.status, TASK_BUDGET_EXHAUSTED)

            issues = sched.record_start_failure(
                "lane-001-recon", ["budget exhausted: max tasks 1 reached"])
            self.assertTrue(issues)
            result_log = Path(root) / "state" / "orchestrator" / \
                "failure-mission" / "results.jsonl"
            records = [json.loads(line) for line in result_log.read_text().splitlines()]
            self.assertTrue(any(r.get("status") == "budget_exhausted"
                                for r in records))
            self.assertEqual(sched.budget.snapshot()["failed_tasks"], 1)

    def test_active_malformed_result_becomes_failed_not_stuck(self):
        with tempfile.TemporaryDirectory() as root:
            sched = self._scheduler(root)
            sched.start("lane-001-recon")
            issues = sched.record("lane-001-recon", {
                "task_id": "lane-001-recon",
                "mission_id": "failure-mission",
                "agent_role": "recon",
                "status": RESULT_COMPLETED,
                "summary": "insight without lead",
            })
            self.assertTrue(issues)
            self.assertEqual(sched._nodes["lane-001-recon"].status, TASK_FAILED)
            self.assertEqual(sched.budget.snapshot()["failed_tasks"], 1)


if __name__ == "__main__":
    unittest.main()

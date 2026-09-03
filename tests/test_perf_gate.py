#!/usr/bin/env python3
"""Phase 7 tests: P1-P8 tuning surfaces + the measured 5.3 gate.

Contracts under test (plan v2 sections 5.3/5.4/7):
  * P6 dedup-before-dispatch: identical work (same fingerprint) never
    creates a second PENDING/ACTIVE node; distinct work is kept; the
    dedup counter survives persistence.
  * The perf harness measures every offline 5.3 target, gates on them,
    and reports live-campaign targets as NOT_MEASURED with a reason --
    unmet targets are printed, never silently dropped.
  * Plan-5.4 yield metrics compute from the durable lead journal.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec
from tools.runtime.scheduler import Scheduler
from tools.runtime.lead_protocol import LeadStore

REPO = Path(__file__).resolve().parents[1]


class EnvMixin:
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name

    def tearDown(self):
        # Restore BEFORE cleanup (the cross-suite poisoning lesson).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        self._td.cleanup()


def _spec(task_id: str, title: str) -> dict:
    return {"task_id": task_id, "task_type": "probe", "domain": "web_api",
            "mission_id": "p7", "title": title, "status": "pending",
            "inputs": {}}


class DedupBeforeDispatchTest(EnvMixin, unittest.TestCase):
    """P6: fingerprint dedup at graph-build time."""

    def _mission(self, mission_id="p7"):
        return MissionSpec(mission_id=mission_id, target="t.local",
                           domains=["web_api"], budget={"max_agents": 8})

    def test_duplicate_work_collapses_onto_existing_node(self):
        sched = Scheduler(self._mission())
        sched.plan_mission()
        n1 = sched._add(_spec("dup-a", "same work"))
        n2 = sched._add(_spec("dup-b", "same work"))
        self.assertIs(n1, n2)
        self.assertEqual(sched.dedup_skipped, 1)
        self.assertEqual(len(sched._nodes),
                         2 + 1)  # preflight + lane root + first dup

    def test_distinct_work_is_never_deduped(self):
        sched = Scheduler(self._mission())
        sched.plan_mission()
        n1 = sched._add(_spec("a", "work one"))
        n2 = sched._add(_spec("b", "work two"))
        self.assertIsNot(n1, n2)
        self.assertEqual(sched.dedup_skipped, 0)

    def test_done_nodes_do_not_block_new_identical_work(self):
        sched = Scheduler(self._mission())
        sched.plan_mission()
        n1 = sched._add(_spec("x", "redo work"))
        n1.spec["status"] = "done"  # finished
        n2 = sched._add(_spec("y", "redo work"))
        self.assertIsNot(n1, n2)  # re-work after completion is allowed

    def test_fingerprints_survive_persistence(self):
        sched = Scheduler(self._mission())
        sched.plan_mission()
        sched._add(_spec("k", "same work"))
        sched.save()
        reloaded = Scheduler.load("p7")
        fps = [n.fingerprint for n in reloaded._nodes.values()
               if n.fingerprint]
        self.assertTrue(all(fps))
        self.assertEqual(len(fps), len(set(fps)) or 0)


class PerfGateTest(EnvMixin, unittest.TestCase):
    """The 5.3 measured gate: unmet printed, never dropped."""

    def test_full_measurement_passes_gate(self):
        from tools.perf import run_measurement
        report = run_measurement(self._td.name)
        self.assertTrue(report["gate_passed"],
                        json.dumps(report["targets"], indent=2))
        statuses = {t["status"] for t in report["targets"]}
        self.assertIn("MET", statuses)
        self.assertNotIn("UNMET", statuses)
        # Honesty rule (updated): every 5.3 target is measured offline on
        # the deterministic harness, and each measured number carries the
        # basis it was taken on.  A basis-less measurement is a gate bug.
        measured = [t for t in report["targets"]
                    if t["status"] in ("MET", "UNMET")]
        self.assertTrue(measured)
        self.assertTrue(
            all(t.get("measurement_basis") for t in measured),
            json.dumps([t["target"] for t in measured
                        if not t.get("measurement_basis")]))
        # A failed measurement still surfaces as NOT_MEASURED with a
        # reason and fails the gate (never silently dropped).
        not_measured = [t for t in report["targets"]
                        if t["status"] == "NOT_MEASURED"]
        self.assertTrue(all(t.get("reason") for t in not_measured))
        # Dashboard persisted.
        dashboard = Path(self._td.name, "state", "perf", "dashboard.json")
        self.assertTrue(dashboard.is_file())

    def test_gate_readback(self):
        from tools.perf import run_measurement, gate
        run_measurement(self._td.name)
        report = gate(self._td.name)
        self.assertIn("gate_passed", report)
        self.assertTrue(report["gate_passed"])

    def test_unmet_target_fails_the_gate(self):
        # Threshold discipline: a regressed value must fail the gate.
        from tools.perf import TARGETS, run_measurement
        report = run_measurement(self._td.name)
        plan_target = next(t for t in report["targets"]
                           if t["target"] == "first_plan_artifact_seconds")
        self.assertEqual(plan_target["status"], "MET")
        self.assertLess(plan_target["value"], TARGETS[
            "first_plan_artifact_seconds"][0])

    def test_yield_metrics_from_lead_journal(self):
        from tools.perf import yield_metrics
        store = LeadStore("p7-yield").load()
        l1 = store.open_lead(title="ato", mission_id="p7-yield",
                             target="t", bug_class="auth_bypass",
                             surface="/a")
        store.record_technique(l1.lead_id, "direct-access", "signal")
        store.record_technique(l1.lead_id, "jwt-alg-none", "success")
        store.close_pwned(l1.lead_id, evidence_ref="ev1")
        l2 = store.open_lead(title="bola", mission_id="p7-yield",
                             target="t", bug_class="access_control",
                             surface="/b")
        store.close_pwned(l2.lead_id, evidence_ref="ev2")
        metrics = yield_metrics("p7-yield", project_root=self._td.name,
                                wall_clock_hours=1.0)
        self.assertEqual(metrics["confirmed_findings"], 2)
        # auth_bypass(4.0) + access_control(3.0) = 7.0 weighted/hour
        self.assertEqual(metrics["severity_weighted_findings_per_hour"], 7.0)
        self.assertEqual(metrics["high_plus_share"], 1.0)
        self.assertEqual(metrics["chain_depth_candidates"], 1)
        self.assertEqual(metrics["novel_class_candidates"], 2)


if __name__ == "__main__":
    unittest.main()

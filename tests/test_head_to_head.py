#!/usr/bin/env python3
"""Head-to-head harness tests (INTEGRATION_PLAN Phase C, v1.26).

Locked contract:

  * config schema pin + corpus references resolve;
  * deterministic judge parity: a task's verdict equals the benchmark
    signal semantics for its corpus case (same TP/TN on the same run);
  * fairness: both shipped contenders face identical task sets and caps,
    and their per-task verdicts are IDENTICAL (the judge is blind);
  * cost is recorded beside pass rate: the spray baseline pays 8x sends
    for the same verdicts — the published table's honesty column;
  * external runners (operator-configured) are recorded as skipped,
    never faked.
"""

import json
import tempfile
import unittest

from tools.head_to_head import (SCHEMA, load_config, run_head_to_head,
                                run_contender_task, _judge_from_corpus)
from tools.benchmark import load_manifest, probe_case, hermetic_probe, \
    _signal_status


class TestConfig(unittest.TestCase):
    def test_schema_and_corpus_references_resolve(self):
        config = load_config()
        self.assertEqual(config["schema"], SCHEMA)
        manifest = load_manifest()
        corpus = {c["case_id"] for c in manifest["cases"]}
        for task in config["tasks"]:
            self.assertIn(task["from_corpus"], corpus)
            self.assertIn("max_sends", task["budget_caps"])
        names = [c["name"] for c in config["contenders"]]
        self.assertIn("bugwolf", names)
        self.assertIn("ungoverned-baseline", names)


class TestJudges(unittest.TestCase):
    def test_judge_parity_with_benchmark_signals(self):
        manifest = load_manifest()
        cases = {c["case_id"]: c for c in manifest["cases"]}
        for task in load_config()["tasks"]:
            case = cases[task["from_corpus"]]
            result = probe_case(case, "http://x", probe=hermetic_probe)
            result["signal"] = _signal_status(case, result)
            judge = _judge_from_corpus(case)
            expected = bool(case.get("expected_finding"))
            # Parity: judge verdict == benchmark TP/TN semantics.
            self.assertEqual(judge(result), result["signal"] == expected,
                             task["task_id"])
            # And the hermetic pair actually agrees with ground truth.
            self.assertTrue(judge(result), task["task_id"])


class TestFairness(unittest.TestCase):
    def test_identical_verdicts_across_contenders(self):
        report = run_head_to_head()
        bw = report["contenders"]["bugwolf"]
        spray = report["contenders"]["ungoverned-baseline"]
        self.assertEqual(bw["pass_rate"], spray["pass_rate"])
        self.assertEqual(bw["tasks_run"], spray["tasks_run"])

    def test_cost_column_exposes_the_spray(self):
        report = run_head_to_head()
        bw = report["contenders"]["bugwolf"]
        spray = report["contenders"]["ungoverned-baseline"]
        self.assertEqual(bw["pass_rate"], 1.0)
        self.assertGreater(spray["sends"], bw["sends"] * 4)
        self.assertGreater(spray["cost_usd_est"], bw["cost_usd_est"] * 4)
        self.assertTrue(bw["cost_estimated"])

    def test_report_persists_with_schema(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            report = run_head_to_head(project_root=tmp)
            path = Path(tmp) / "state" / "benchmark" / "head_to_head.json"
            self.assertTrue(path.is_file())
            self.assertEqual(report["schema"], SCHEMA)


class TestExternalRunners(unittest.TestCase):
    def test_unknown_runner_is_skipped_not_faked(self):
        result = run_contender_task("raw-claude-code", {}, {"case_id": "x"},
                                    "http://stub.invalid", {})
        self.assertTrue(result["skipped"])
        self.assertIn("operator", result["reason"])

    def test_all_external_contender_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config()
            config["contenders"] = [
                {"name": "raw-claude-code", "runner": "subprocess",
                 "config": {}}]
            report = run_head_to_head(config=config, project_root=tmp)
            m = report["contenders"]["raw-claude-code"]
            self.assertEqual(m["tasks_run"], 0)
            self.assertEqual(m["tasks_skipped"], len(config["tasks"]))
            self.assertIsNone(m["pass_rate"])


if __name__ == "__main__":
    unittest.main()

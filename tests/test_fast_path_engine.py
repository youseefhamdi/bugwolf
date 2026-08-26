#!/usr/bin/env python3
"""Fast-Path Hypothesis Engine tests (U1).

Covers:
  * on_checkpoint hook fires once per checkpoint, in order, non-blocking
  * handler failures never abort the mandatory sweep
  * fast_path_signals — deterministic trigger detection
  * run_mandatory_research passes the hook through
  * default (no hook) behavior is unchanged
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.research_loop import (  # noqa: E402
    run_mandatory_research, fast_path_signals,
    MANDATORY_RESEARCH_SEQUENCE, mandatory_ordered_subsequence,
)


class TestOnCheckpointHook(unittest.TestCase):
    def _run(self, on_checkpoint=None):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_mandatory_research(
                "acme", "web", phase="full",
                base_dir=str(Path(tmp) / "research"),
                run_search=False, on_checkpoint=on_checkpoint)
            return result, tmp

    def test_hook_fires_once_per_checkpoint_in_order(self):
        seen = []

        def hook(result, context):
            seen.append(result["checkpoint"])

        result, _ = self._run(on_checkpoint=hook)
        current = result["current_execution"]["sequence"]
        # One callback per executed checkpoint, in sweep order.
        self.assertEqual(seen, current)
        self.assertEqual(len(seen), len(MANDATORY_RESEARCH_SEQUENCE))

    def test_hook_receives_context_and_result_dict(self):
        received = []

        def hook(result, context):
            received.append((result.get("checkpoint"), dict(context)))

        self._run(on_checkpoint=hook)
        self.assertTrue(received)
        for checkpoint, context in received:
            self.assertIn(checkpoint, MANDATORY_RESEARCH_SEQUENCE)
            self.assertIsInstance(context, dict)

    def test_hook_failure_never_aborts_sweep(self):
        calls = []

        def hook(result, context):
            calls.append(result["checkpoint"])
            if result["checkpoint"] == "post-recon":
                raise RuntimeError("fast-path engine exploded")

        result, _ = self._run(on_checkpoint=hook)
        # The sweep completed all checkpoints despite the failure.
        self.assertEqual(len(calls), len(MANDATORY_RESEARCH_SEQUENCE))
        self.assertTrue(
            mandatory_ordered_subsequence(
                result["current_execution"]["sequence"]))

    def test_default_hook_behavior_unchanged(self):
        result, _ = self._run()
        current = result["current_execution"]
        self.assertEqual(len(current["sequence"]),
                         len(MANDATORY_RESEARCH_SEQUENCE))
        self.assertFalse(result["latest_ready"])  # searches pending offline
        self.assertIn("executions", result)
        self.assertIn("sequence_file", result)


class TestFastPathSignals(unittest.TestCase):
    def test_waf_bypass_trigger_on_payloads_present(self):
        signals = fast_path_signals({
            "checkpoint": "bypass",
            "waf_payloads_present": True,
            "waf_payloads_expected": True,
            "records": [],
        })
        self.assertEqual(signals[0]["trigger"], "waf-bypass-payloads")
        self.assertEqual(signals[0]["checkpoint"], "bypass")

    def test_canonical_source_fresh_signal(self):
        signals = fast_path_signals({
            "checkpoint": "pre-hunt",
            "records": [
                {"task_type": "fetch", "source": "https://example.com/",
                 "status": 200},
                {"task_type": "fetch", "source": "https://example.org/",
                 "status": 0, "error": "timeout"},
            ],
        })
        self.assertEqual(signals[0]["trigger"], "canonical-source-fresh")
        self.assertEqual(len(signals[0]["payload"]["sources"]), 1)

    def test_search_signal(self):
        signals = fast_path_signals({
            "checkpoint": "post-recon",
            "records": [
                {"task_type": "search", "query": "next.js CVE",
                 "results": [{"title": "x"}]},
            ],
        })
        self.assertEqual(signals[0]["trigger"], "search-signal")

    def test_empty_result_yields_no_signals(self):
        self.assertEqual(fast_path_signals({}), [])
        self.assertEqual(fast_path_signals({"records": []}), [])

    def test_signal_order_is_stable(self):
        a = fast_path_signals({
            "checkpoint": "bypass",
            "waf_payloads_present": True,
            "records": [
                {"task_type": "fetch", "source": "u", "status": 200},
                {"task_type": "search", "query": "q", "results": [{"t": "1"}]},
            ],
        })
        b = fast_path_signals({
            "checkpoint": "bypass",
            "waf_payloads_present": True,
            "records": [
                {"task_type": "fetch", "source": "u", "status": 200},
                {"task_type": "search", "query": "q", "results": [{"t": "1"}]},
            ],
        })
        self.assertEqual([s["trigger"] for s in a],
                         [s["trigger"] for s in b])
        self.assertEqual(a[0]["trigger"], "waf-bypass-payloads")


if __name__ == "__main__":
    unittest.main()

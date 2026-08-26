#!/usr/bin/env python3
"""Tests for the Phase 3 coverage-guided/state-aware research substrate."""

import tempfile
import unittest

from tools.research_core import (
    CorpusManager,
    CoverageTracker,
    CrashRegistry,
    StateCoverage,
)


class TestCoverageTracker(unittest.TestCase):
    def test_record_is_idempotent_and_first_seen_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracker = CoverageTracker("example.test", tmp)
            first = tracker.record("GET:/api/users:id:object-reference",
                                   kind="idor", technique="object-reference")
            second = tracker.record("GET:/api/users:id:object-reference",
                                    kind="idor", technique="other")
            self.assertEqual(first["first_seen_at"], second["first_seen_at"])
            self.assertTrue(tracker.is_tried("GET:/api/users:id:object-reference"))
            self.assertEqual(tracker.report()["total_keys"], 1)

    def test_reload_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            CoverageTracker("t", tmp).record("POST:/api/users:role:over-binding",
                                             kind="mass_assignment")
            reloaded = CoverageTracker("t", tmp)
            self.assertTrue(reloaded.is_tried("POST:/api/users:role:over-binding"))


class TestCorpusManager(unittest.TestCase):
    def test_content_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = CorpusManager("t", tmp)
            a = manager.add("' OR '1'='1", name="sqli", source="benchmark")
            b = manager.add("' OR '1'='1", name="sqli-copy", source="manual")
            self.assertEqual(a.seed_id, b.seed_id)
            self.assertEqual(len(manager.seeds()), 1)

    def test_novelty_requires_uncovered_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            tracker = CoverageTracker("t", tmp)
            manager = CorpusManager("t", tmp)
            manager.add("payload", coverage_keys=["GET:/x:q:injection"])
            report = manager.novelty(tracker)
            self.assertEqual(report["novel_seeds"], 1)
            tracker.record("GET:/x:q:injection", kind="injection")
            report = manager.novelty(tracker)
            self.assertEqual(report["novel_seeds"], 0)

    def test_approve_then_replay_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = CorpusManager("t", tmp)
            seed = manager.add("seed-a")
            self.assertEqual(manager.replay_plan()["count"], 0)
            manager.approve(seed.seed_id, reviewer="operator")
            plan = manager.replay_plan()
            self.assertEqual(plan["count"], 1)
            self.assertEqual(plan["seeds"][0]["review_status"], "approved")


class TestCrashRegistry(unittest.TestCase):
    def test_signature_normalizes_addresses(self):
        sig_a = CrashRegistry.signature(
            input_hash="abc", kind="asan", stack_hint="read 0x7fff1000 +0x40")
        sig_b = CrashRegistry.signature(
            input_hash="abc", kind="asan", stack_hint="read 0x7fff9999 +0x40")
        self.assertEqual(sig_a, sig_b)

    def test_duplicate_registration_increments_occurrences(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = CrashRegistry("t", tmp)
            first = registry.register(input_hash="deadbeef", kind="asan",
                                      stack_hint="heap-buffer-overflow")
            second = registry.register(input_hash="deadbeef", kind="asan",
                                       stack_hint="heap-buffer-overflow")
            self.assertEqual(first["crash_id"], second["crash_id"])
            self.assertEqual(registry.crashes()[0]["occurrences"], 2)

    def test_minimization_uses_oracle(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = CrashRegistry("t", tmp)
            registry.register(input_hash="x", kind="crash", stack_hint="sig")
            crash_id = registry.crashes()[0]["crash_id"]
            inputs = ["a", "b", "c", "d"]
            result = registry.minimize(
                crash_id, inputs, reproduces=lambda cand: len(cand) >= 2)
            self.assertEqual(result["minimal_size"], 2)
            self.assertEqual(result["original_size"], 4)


class TestStateCoverage(unittest.TestCase):
    def test_illegal_transition_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            states = StateCoverage("t", tmp)
            states.record(role="user", action="pay", from_state="draft",
                          to_state="paid", expected=False)
            report = states.report()
            self.assertEqual(report["transitions"], 1)
            self.assertEqual(report["illegal_transitions_found"], 1)


if __name__ == "__main__":
    unittest.main()

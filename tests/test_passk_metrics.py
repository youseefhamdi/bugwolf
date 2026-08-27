#!/usr/bin/env python3
import unittest

from tools.passk_metrics import Attempt, aggregate, pass_at_k


class TestPassKMetrics(unittest.TestCase):
    def setUp(self):
        self.attempts = [
            Attempt("idor", "run-1", False),
            Attempt("idor", "run-2", True, True),
            Attempt("idor", "run-3", False),
            Attempt("xss", "run-1", True, False),
            Attempt("xss", "run-2", False),
        ]

    def test_pass_at_k_improves_with_attempts(self):
        self.assertEqual(pass_at_k(self.attempts, 1), 0.5)
        self.assertEqual(pass_at_k(self.attempts, 2), 1.0)

    def test_aggregate_contains_quality_metrics(self):
        result = aggregate(self.attempts, budget_units=10)
        self.assertEqual(result["schema"], "bugwolf/passk-metrics/v1")
        self.assertEqual(result["cases"], 2)
        self.assertEqual(result["confirmed"], 1)
        self.assertEqual(result["coverage_per_budget"], 0.2)


if __name__ == "__main__":
    unittest.main()

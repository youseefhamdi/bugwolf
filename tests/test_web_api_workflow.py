#!/usr/bin/env python3
import unittest

from tools.web_api_workflow import WebApiWorkflowAnalyzer


class TestWebApiWorkflowAnalyzer(unittest.TestCase):
    def test_detects_successful_illegal_workflow_transition(self):
        analyzer = WebApiWorkflowAnalyzer("lab.test")
        workflow = [
            {"step": "create", "endpoint": "/orders", "status": 201},
            {"step": "approve", "endpoint": "/orders/1/approve", "status": 200},
        ]
        candidates = analyzer.analyze_workflow(workflow, observed_sequences=[
            {"kind": "skip", "step": "approve", "status": 200},
        ])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "business_logic")
        self.assertIn("skip", candidates[0].behavior["sequence_kind"])

    def test_detects_non_idempotent_duplicate_action(self):
        analyzer = WebApiWorkflowAnalyzer("lab.test")
        candidates = analyzer.analyze_race_observations([{
            "endpoint": "/orders/1/pay",
            "method": "POST",
            "requests": 2,
            "successful_responses": 2,
            "state_delta": {"balance": -200},
            "expected": "one successful payment",
        }])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "race_condition_web")
        self.assertEqual(candidates[0].behavior["duplicate_successes"], 2)

    def test_ignores_expected_single_success(self):
        analyzer = WebApiWorkflowAnalyzer("lab.test")
        self.assertEqual(analyzer.analyze_race_observations([{
            "endpoint": "/orders/1/pay", "method": "POST",
            "requests": 2, "successful_responses": 1,
            "state_delta": {}, "expected": "one successful payment",
        }]), [])


if __name__ == "__main__":
    unittest.main()

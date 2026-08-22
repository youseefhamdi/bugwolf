"""Tests for the live sibling-differential runner."""

import unittest

from tools.surface_model import parse_openapi
from tools.observation import HttpObservation
from tools.differential_runner import (
    DifferentialRunner, score_divergence, SiblingRequest,
)


def _model():
    return parse_openapi({
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/v1/users/{id}": {
                "get": {"operationId": "getUserV1",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True,
                             "schema": {"type": "integer"}},
                            {"name": "expand", "in": "query",
                             "schema": {"type": "string", "enum": ["all", "none"]}},
                        ]},
            },
            "/v2/users/{id}": {
                "get": {"operationId": "getUserV2",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True,
                             "schema": {"type": "integer"}},
                        ]},
            },
        },
    }, "example.com")


def _obs(status=200, body="same", headers=None, timing=0.1):
    return HttpObservation(status=status, body=body,
                           headers=headers or {}, timing_seconds=timing)


class TestScoreDivergence(unittest.TestCase):
    def test_identical_is_zero(self):
        verdict = score_divergence(_obs(), _obs())
        self.assertEqual(verdict["score"], 0.0)
        self.assertFalse(verdict["diverged"])

    def test_status_divergence(self):
        verdict = score_divergence(_obs(200), _obs(403))
        self.assertAlmostEqual(verdict["score"], 0.25)
        self.assertTrue(verdict["diverged"])
        self.assertIn("status", verdict["deltas"])

    def test_body_divergence(self):
        verdict = score_divergence(_obs(200, "AAAA"), _obs(200, "BBBB"))
        self.assertAlmostEqual(verdict["score"], 0.35)
        self.assertTrue(verdict["diverged"])

    def test_combined_divergence(self):
        verdict = score_divergence(_obs(200, "AAAA", {"X": "1"}),
                                   _obs(403, "BBBB", {"Y": "2"}))
        self.assertGreater(verdict["score"], 0.5)


class TestDifferentialRunner(unittest.TestCase):
    def setUp(self):
        self.model = _model()
        self.runner = DifferentialRunner(base_url="https://api.example.com")

    def test_pair_requests_build_identical_requests(self):
        pairs = self.runner.pair_requests(self.model)
        self.assertEqual(len(pairs), 1)
        a, b = pairs[0]
        # Path param filled with default 1; query union applied to both sides.
        self.assertEqual(a.url, "https://api.example.com/v1/users/1?expand=all")
        self.assertEqual(b.url, "https://api.example.com/v2/users/1?expand=all")
        self.assertEqual(a.method, b.method)

    def test_run_identical_no_drift(self):
        def transport(req: SiblingRequest):
            return _obs(200, "same-body")
        results = self.runner.run(self.model, transport)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].diverged)
        self.assertEqual(results[0].score, 0.0)

    def test_run_status_drift_marks_weaker(self):
        def transport(req: SiblingRequest):
            return _obs(200) if "v1" in req.url else _obs(403)
        results = self.runner.run(self.model, transport)
        r = results[0]
        self.assertTrue(r.diverged)
        self.assertTrue(r.sibling_drift)
        self.assertEqual(r.weaker_side, "a")  # v1 allows, v2 denies
        self.assertIn("Sibling drift", r.hypothesis)

    def test_run_body_drift(self):
        def transport(req: SiblingRequest):
            return _obs(200, "v1-extra-field") if "v1" in req.url \
                else _obs(200, "v2-short")
        results = self.runner.run(self.model, transport)
        self.assertTrue(results[0].diverged)
        self.assertIn("body", results[0].deltas)


if __name__ == "__main__":
    unittest.main()

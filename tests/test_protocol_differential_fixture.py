#!/usr/bin/env python3
import unittest

from tools.protocol_differential_fixture import (
    ProtocolDifferentialFixture,
    ServerlessEdgeFixture,
)


class TestProtocolDifferentialFixture(unittest.TestCase):
    def test_models_protocol_version_deltas(self):
        fixture = ProtocolDifferentialFixture("lab")
        fixture.record("h2", "/api", {"status": 200, "body": "ok"})
        fixture.record("h3", "/api", {"status": 200, "body": "ok"})
        fixture.record("h2", "/api", {"status": 500, "body": "error"})
        deltas = fixture.deltas()
        self.assertTrue(any(
            d["protocol"] == "h2" and d["a"].get("status") == 500
            for d in deltas))

    def test_serverless_edge_cold_warm_delta(self):
        fixture = ServerlessEdgeFixture("lab")
        fixture.record("cold", "/fn", {"status": 200, "elapsed_ms": 1200})
        fixture.record("warm", "/fn", {"status": 200, "elapsed_ms": 40})
        candidates = fixture.candidates()
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "serverless_cold_start")
        self.assertGreater(candidates[0].behavior["elapsed_cold_ms"], 100)


if __name__ == "__main__":
    unittest.main()
#!/usr/bin/env python3
"""Unit tests for tools/core/fuzz_bridge.py — deterministic core coverage.

Covers: fuzz classification (crash/timeout/anomaly/clean/error), bounded
retry transport, campaign execution with an injectable transport, budget
bounding, evidence blocks, and advisory-only bus publishing.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.fuzz_bridge import (
    CRASH_STATUSES, TIMING_ANOMALY_MS, FuzzObservation, FuzzSummary,
    classify_fuzz, run_fuzzing_campaign, _evidence_block, _transport,
)


class FakeMutation:
    def __init__(self, mutation_id="m1", operation_id="op1", path="/api/users",
                 method="GET", kind="boundary", mutated=None):
        self.mutation_id = mutation_id
        self.operation_id = operation_id
        self.path = path
        self.method = method
        self.kind = kind
        self.mutated = mutated


class TestClassifyFuzz(unittest.TestCase):
    def test_crash_status_is_crash(self):
        state, signal = classify_fuzz(500, 10.0, "Internal Server Error")
        self.assertEqual(state, "crash")
        self.assertIn("500", signal)

    def test_clean_response_is_clean(self):
        state, signal = classify_fuzz(200, 50.0, "ok")
        self.assertEqual(state, "clean")
        self.assertEqual(signal, "")

    def test_timeout_status_zero_with_timeout_body(self):
        state, signal = classify_fuzz(0, 8100.0, "transport error: timeout")
        self.assertEqual(state, "timeout")
        self.assertIn("timed out", signal)

    def test_transport_error_is_error(self):
        state, _ = classify_fuzz(0, 5.0, "transport error: URLError")
        self.assertEqual(state, "error")

    def test_timing_anomaly_on_slow_success(self):
        state, signal = classify_fuzz(200, TIMING_ANOMALY_MS + 100, "ok")
        self.assertEqual(state, "anomaly")
        self.assertIn("timing anomaly", signal)

    def test_fast_5xx_is_crash_not_anomaly(self):
        # Crash precedence: 5xx wins even if fast.
        state, _ = classify_fuzz(503, 5.0, "boom")
        self.assertEqual(state, "crash")

    def test_bare_403_is_blocked_not_clean(self):
        state, signal = classify_fuzz(403, 5.0, "forbidden")
        self.assertEqual(state, "blocked")
        self.assertIn("403", signal)

    def test_waf_header_fingerprint_is_blocked(self):
        # Cloudflare fingerprints surface even on a 200.
        state, signal = classify_fuzz(
            200, 5.0, "ok", headers={"CF-Ray": "abc123"})
        self.assertEqual(state, "blocked")
        self.assertIn("cloudflare", signal)

    def test_blocked_wins_over_timing_anomaly(self):
        # A 403 with slow timing is still a block, not an anomaly.
        state, _ = classify_fuzz(403, TIMING_ANOMALY_MS + 100, "forbidden")
        self.assertEqual(state, "blocked")

    def test_normal_200_stays_clean_with_headers(self):
        state, signal = classify_fuzz(200, 5.0, "ok", headers={"Server": "nginx"})
        self.assertEqual(state, "clean")
        self.assertEqual(signal, "")

    def test_crash_statuses_cover_common_5xx(self):
        self.assertIn(500, CRASH_STATUSES)
        self.assertIn(503, CRASH_STATUSES)


class TestEvidenceBlock(unittest.TestCase):
    def test_evidence_is_replayable(self):
        ev = _evidence_block("http://x/api", "POST", {"a": 1},
                             {"Content-Type": "application/json"},
                             500, {"Server": "nginx"}, "boom", 123.4)
        self.assertIn("request", ev)
        self.assertIn("response", ev)
        self.assertEqual(ev["request"]["method"], "POST")
        self.assertEqual(ev["request"]["body"], {"a": 1})
        self.assertEqual(ev["response"]["status"], 500)
        self.assertEqual(ev["response"]["elapsed_ms"], 123.4)
        self.assertTrue(ev["replay_key"])

    def test_evidence_is_deterministic(self):
        a = _evidence_block("http://x/api", "GET", None, {}, 200, {}, "ok", 1.0)
        b = _evidence_block("http://x/api", "GET", None, {}, 200, {}, "ok", 1.0)
        self.assertEqual(a["replay_key"], b["replay_key"])
        self.assertEqual(a["request"], b["request"])


class TestTransport(unittest.TestCase):
    def test_retries_then_succeeds(self):
        calls = []

        def flaky(urlopen):
            def inner(req, timeout=None):
                calls.append(1)
                if len(calls) == 1:
                    raise TimeoutError("boom")
                class Resp:
                    status = 200
                    headers = {}

                    def read(self, n):
                        return b"ok"

                    def __enter__(self):
                        return self

                    def __exit__(self, *exc):
                        return False
                return Resp()
            return inner

        import urllib.request
        status, hdrs, body, ms = _transport(
            "http://x/", "GET", None, {}, retries=2,
            urlopen=flaky(urllib.request.urlopen))
        self.assertEqual(status, 200)
        self.assertEqual(len(calls), 2)

    def test_exhausts_retries_on_persistent_failure(self):
        calls = []

        def always_fail(urlopen):
            def inner(req, timeout=None):
                calls.append(1)
                raise TimeoutError("nope")
            return inner

        import urllib.request
        status, hdrs, body, ms = _transport(
            "http://x/", "GET", None, {}, retries=1,
            urlopen=always_fail(urllib.request.urlopen))
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 2)  # 1 + 1 retry


class TestRunCampaign(unittest.TestCase):
    def _fake_transport(self, script):
        """script: list of (status, headers, body, ms) consumed per call."""
        state = {"i": 0}

        def transport(url, method, body, headers):
            item = script[min(state["i"], len(script) - 1)]
            state["i"] += 1
            return item
        return transport

    def test_campaign_counts_outcomes(self):
        script = [(500, {}, "boom", 5.0),          # crash
                  (0, {}, "transport error: timeout", 9000.0),  # timeout
                  (200, {}, "ok", 2500.0),         # anomaly (slow success)
                  (403, {"CF-Ray": "abc"}, "forbidden", 5.0),  # blocked
                  (200, {}, "ok", 30.0),           # clean
                  (0, {}, "refused", 2.0)]         # error
        mutations = [FakeMutation(mutation_id=f"m{i}", path=f"/p{i}")
                     for i in range(6)]
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_fuzzing_campaign(
                "acme", base_url="http://acme", mutations=mutations,
                transport=self._fake_transport(script),
                project_root=tmp, publish=False)
        self.assertEqual(summary.mutations_run, 6)
        self.assertEqual(summary.crashes, 1)
        self.assertEqual(summary.timeouts, 1)
        self.assertEqual(summary.anomalies, 1)
        self.assertEqual(summary.blocked, 1)
        self.assertEqual(summary.clean, 1)
        self.assertEqual(summary.errors, 1)
        states = {o.state for o in summary.observations}
        self.assertEqual(states, {"crash", "timeout", "anomaly", "blocked",
                                  "clean", "error"})

    def test_blocked_observation_records_defense_name(self):
        script = [(403, {"CF-Ray": "abc"}, "forbidden", 5.0)]
        mutations = [FakeMutation(mutation_id="b1", path="/api/x")]
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_fuzzing_campaign(
                "acme", base_url="http://acme", mutations=mutations,
                transport=self._fake_transport(script),
                project_root=tmp, publish=False)
        obs = summary.observations[0]
        self.assertEqual(obs.state, "blocked")
        self.assertEqual(obs.evidence["waf"], "cloudflare")
        self.assertIn("blocked by cloudflare", obs.signal)

    def test_budget_bounds_mutations(self):
        mutations = [FakeMutation(mutation_id=f"m{i}") for i in range(20)]
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_fuzzing_campaign(
                "acme", base_url="http://acme", mutations=mutations,
                transport=lambda u, m, b, h: (200, {}, "ok", 1.0),
                budget=3, project_root=tmp, publish=False)
        self.assertEqual(summary.mutations_run, 3)

    def test_crash_carries_replayable_evidence(self):
        script = [(500, {"Server": "nginx"}, "boom", 5.0)]
        mutations = [FakeMutation(mutation_id="crash1", path="/api/x")]
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_fuzzing_campaign(
                "acme", base_url="http://acme", mutations=mutations,
                transport=self._fake_transport(script),
                project_root=tmp, publish=False)
        obs = summary.observations[0]
        self.assertEqual(obs.state, "crash")
        self.assertIn("evidence", obs.to_dict())
        self.assertEqual(obs.evidence["response"]["status"], 500)
        self.assertEqual(obs.evidence["request"]["method"], "GET")

    def test_run_summary_serializes_with_schema(self):
        data = FuzzSummary(target="acme").to_dict()
        self.assertEqual(data["schema"], "bugwolf/fuzz-bridge/v1")
        self.assertEqual(data["target"], "acme")


if __name__ == "__main__":
    unittest.main()

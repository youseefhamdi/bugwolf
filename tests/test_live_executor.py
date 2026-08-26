#!/usr/bin/env python3
"""Unit tests for tools/core/live_executor.py — deterministic logic only.

Uses an injectable fake transport so no live target is needed: probe
planning, WAF detection, classification, retry/backoff, evidence packaging,
exploit replay, and reproducibility are all covered deterministically.
"""

import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.live_executor import (  # noqa: E402
    build_probe_specs, classify_probe, detect_waf, execute_exploit,
    execute_probe, extract_signals, verify_reproducibility,
    _default_transport, ProbeSpec, ProbeResult, DEFAULT_RETRIES,
    RETRY_BACKOFF,
)


def fake_transport(*responses):
    """Build a deterministic transport returning canned (status, headers, body, ms)."""
    calls = []

    def transport(spec):
        calls.append(spec.to_dict())
        resp = responses[min(len(calls) - 1, len(responses) - 1)]
        if callable(resp):
            return resp(spec, calls)
        status, headers, body, ms = resp
        return status, dict(headers or {}), body, ms

    transport.calls = calls
    return transport


class TestProbePlanning(unittest.TestCase):
    def test_baseline_first_then_bounded_probes(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        specs = build_probe_specs(unit, "https://acme", max_probes=4)
        self.assertTrue(specs[0].is_baseline)
        self.assertGreaterEqual(len(specs), 2)
        self.assertLessEqual(len(specs), 1 + 4)

    def test_relative_endpoint_resolves_against_base_url(self):
        unit = {"endpoint": "/api/users/1", "bug_class": "idor"}
        specs = build_probe_specs(unit, "https://acme")
        self.assertTrue(specs[0].url.startswith("https://acme"))

    def test_idor_sweeps_object_id_space(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        specs = build_probe_specs(unit, "https://acme", max_probes=6)
        ids = {s.url.rsplit("/", 1)[-1] for s in specs if not s.is_baseline}
        self.assertIn("2", ids)
        self.assertIn("42", ids)

    def test_idor_sweep_never_rewrites_the_request_host(self):
        # Regression: a naive str.replace("/1", ...) matched the "//1"
        # inside http://127.0.0.1/... and rewrote the HOST to 227.0.0.1 /
        # 027.0.0.1 (octal -> 23.0.0.1, unroutable -> 30s transport hang).
        unit = {"endpoint": "http://127.0.0.1:8077/api/users/1",
                "bug_class": "idor"}
        specs = build_probe_specs(unit, "http://127.0.0.1:8077",
                                  max_probes=6)
        for s in specs:
            self.assertTrue(
                s.url.startswith("http://127.0.0.1:8077/"),
                f"idor probe rewrote request host: {s.url}")
        non_base = [s for s in specs if not s.is_baseline]
        self.assertEqual(
            {s.url.rsplit("/", 1)[-1] for s in non_base},
            {"1", "2", "42", "0", "-1", "999999"})

    def test_mass_assignment_probes_carry_admin_bodies(self):
        unit = {"endpoint": "https://acme/api/users", "bug_class": "mass_assignment"}
        specs = build_probe_specs(unit, "https://acme", max_probes=4)
        bodies = [s.body for s in specs if not s.is_baseline]
        self.assertIn({"role": "admin"}, bodies)

    def test_graphql_probe_sends_introspection(self):
        unit = {"endpoint": "https://acme/graphql", "bug_class": "graphql"}
        specs = build_probe_specs(unit, "https://acme")
        probe = [s for s in specs if not s.is_baseline][0]
        self.assertIn("__schema", probe.body["query"])

    def test_unknown_bug_class_falls_back_to_generic(self):
        unit = {"endpoint": "https://acme/x", "bug_class": "mystery_class"}
        specs = build_probe_specs(unit, "https://acme")
        self.assertEqual(len(specs), 2)  # baseline + generic

    def test_planning_is_deterministic(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        a = build_probe_specs(unit, "https://acme", max_probes=8)
        b = build_probe_specs(unit, "https://acme", max_probes=8)
        self.assertEqual([s.to_dict() for s in a], [s.to_dict() for s in b])


class TestWafDetection(unittest.TestCase):
    def test_cloudflare_header(self):
        detected, name = detect_waf(403, {"Cf-Ray": "abc123"},
                                    "blocked")
        self.assertTrue(detected)
        self.assertEqual(name, "cloudflare")

    def test_aws_waf_body_marker(self):
        detected, name = detect_waf(403, {}, "Request blocked by AWS WAF")
        self.assertTrue(detected)
        self.assertEqual(name, "aws-waf")

    def test_bare_403_is_unattributed_block(self):
        detected, name = detect_waf(403, {}, "forbidden for this resource")
        self.assertTrue(detected)
        self.assertEqual(name, "unattributed")

    def test_200_is_not_a_block(self):
        detected, _ = detect_waf(200, {"Server": "nginx"}, "ok")
        self.assertFalse(detected)

    def test_404_is_not_a_block(self):
        detected, _ = detect_waf(404, {}, "not found")
        self.assertFalse(detected)


class TestClassification(unittest.TestCase):
    def _result(self, status=200, body="", headers=None, elapsed=10.0,
                technique="probe:q", waf=False, waf_name=""):
        spec = {"method": "GET", "url": "https://acme/x", "headers": {},
                "body": None, "technique": technique, "bug_class": "sql_injection"}
        return ProbeResult(
            probe_id="p1", spec=spec, status=status,
            response_headers=dict(headers or {}), response_body=body,
            elapsed_ms=elapsed, waf_detected=waf, waf_name=waf_name)

    def test_blocked_when_waf(self):
        r = self._result(status=403, waf=True, waf_name="cloudflare")
        self.assertEqual(classify_probe(r, "sql_injection"), "blocked")

    def test_transport_error(self):
        r = ProbeResult(probe_id="p1", spec={}, status=0,
                        transport_error="connection refused")
        self.assertEqual(classify_probe(r, "sql_injection"), "error")

    def test_signal_on_sql_error_body(self):
        r = self._result(status=500, body="SQL syntax error near ' OR 1=1")
        self.assertEqual(classify_probe(r, "sql_injection"), "signal")

    def test_signal_on_idor_success(self):
        r = self._result(status=200, body="{\"username\": \"bob\"}")
        self.assertEqual(classify_probe(r, "idor"), "signal")

    def test_clean_on_baseline_match(self):
        r = self._result(status=200, body="hello")
        self.assertEqual(classify_probe(r, "sql_injection"), "clean")

    def test_timing_anomaly_signal(self):
        baseline = self._result(status=200, elapsed=10.0)
        r = self._result(status=200, elapsed=5000.0)
        signals = extract_signals(r, baseline, timing_threshold_ms=3000.0)
        self.assertIn("timing-anomaly:+4990ms", signals)
        self.assertEqual(classify_probe(r, "sql_injection", baseline), "signal")


class TestExecuteProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self.tmp.name
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env

    def test_execute_probe_returns_structured_result(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        transport = fake_transport((200, {"Server": "nginx"}, "{\"id\":1}", 5.0),
                                   (200, {"Server": "nginx"}, "{\"id\":2}", 5.0))
        result = execute_probe(unit, "https://acme", transport=transport)
        self.assertEqual(result.status, 200)
        self.assertTrue(result.probe_id)  # deterministic hash id
        self.assertIn("request", result.evidence)
        self.assertIn("response", result.evidence)
        self.assertIn("replay_key", result.evidence)
        # Baseline probe ran first, then the primary.
        self.assertGreaterEqual(len(transport.calls), 2)

    def test_execute_probe_marks_blocked_on_waf(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        transport = fake_transport((403, {"Cf-Ray": "x"}, "Attention required", 5.0),
                                   (403, {"Cf-Ray": "x"}, "Attention required", 5.0))
        result = execute_probe(unit, "https://acme", transport=transport)
        self.assertTrue(result.blocked)
        self.assertEqual(result.waf_name, "cloudflare")

    def test_execute_probe_persists_evidence(self):
        unit = {"endpoint": "https://acme/api/users/1", "bug_class": "idor"}
        transport = fake_transport((200, {}, "ok", 5.0), (200, {}, "data", 5.0))
        execute_probe(unit, "https://acme", transport=transport)
        probes = (Path(self.tmp.name) / "state" / "sessions" / "acme"
                  / "probes.jsonl")
        self.assertTrue(probes.is_file())
        first = json.loads(probes.read_text().splitlines()[0])
        self.assertIn("evidence", first)

    def test_transport_error_surfaces(self):
        unit = {"endpoint": "https://acme/x", "bug_class": "web"}
        transport = fake_transport((0, {}, "transport error: ConnectionRefusedError", 0.0))
        result = execute_probe(unit, "https://acme", transport=transport)
        self.assertEqual(result.status, 0)
        self.assertIn("transport failure", result.transport_error)

    def test_empty_unit_falls_back_to_generic_probe(self):
        # An empty unit still derives a generic probe (baseline suppressed).
        transport = fake_transport((200, {}, "ok", 5.0))
        result = execute_probe({}, "https://acme", transport=transport,
                               include_baseline=False)
        self.assertEqual(result.status, 200)
        self.assertIn("generic", result.spec["technique"])


class TestExploitAndReproducibility(unittest.TestCase):
    def _finding(self, status=200):
        return {
            "finding_id": "f1",
            "evidence": {
                "request": {"method": "GET",
                            "url": "https://acme/api/users/2",
                            "headers": {}, "body": None,
                            "technique": "id", "bug_class": "idor"},
                "response": {"status": status, "headers": {},
                             "body": "{\"id\":2}", "elapsed_ms": 5.0},
            },
        }

    def test_execute_exploit_replays_recorded_request(self):
        finding = self._finding()
        transport = fake_transport((200, {}, "{\"id\":2}", 5.0))
        result = execute_exploit(finding, "https://acme", transport=transport)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.spec["url"], "https://acme/api/users/2")
        self.assertEqual(result.evidence["replay_of"], "f1")
        self.assertTrue(result.evidence["reproduced"])

    def test_execute_exploit_without_evidence_fails(self):
        result = execute_exploit({"finding_id": "f2"}, "https://acme")
        self.assertEqual(result.status, 0)
        self.assertIn("no recorded request", result.transport_error)

    def test_verify_reproducibility_matches(self):
        transport = fake_transport((200, {}, "{\"id\":2}", 5.0))
        self.assertTrue(verify_reproducibility(self._finding(200), "https://acme",
                                               transport=transport))

    def test_verify_reproducibility_mismatch_fails(self):
        # Recorded response said 200, replay returns 403 -> not reproducible.
        transport = fake_transport((403, {}, "denied", 5.0))
        self.assertFalse(verify_reproducibility(self._finding(200), "https://acme",
                                                transport=transport))

    def test_verify_reproducibility_without_recorded_status_is_not_proof(self):
        finding = {"finding_id": "f3", "evidence": {"request": {
            "method": "GET", "url": "https://acme/x", "headers": {},
            "body": None}}}
        transport = fake_transport((200, {}, "ok", 5.0))
        # No recorded status to compare — this is insufficient proof.
        self.assertFalse(verify_reproducibility(finding, "https://acme",
                                                transport=transport))


class TestRetries(unittest.TestCase):
    def test_default_transport_retries_then_succeeds(self):
        # urlopen fails twice (URLError), succeeds on the third attempt.
        attempts = {"n": 0}

        class _Resp:
            status = 200
            headers = {}

            def read(self, *a):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def flaky_urlopen(req, timeout=10):
            attempts["n"] += 1
            if attempts["n"] <= 2:
                raise urllib.error.URLError("connection reset")
            return _Resp()

        spec = ProbeSpec(probe_id="r1", method="GET", url="https://acme/x")
        status, _, body, _ = _default_transport(spec, retries=DEFAULT_RETRIES,
                                                urlopen=flaky_urlopen)
        self.assertEqual(status, 200)
        self.assertEqual(body, "ok")
        self.assertEqual(attempts["n"], 3)  # 1 initial + 2 retries

    def test_default_transport_gives_up_after_retries(self):
        attempts = {"n": 0}

        def always_fail(req, timeout=10):
            attempts["n"] += 1
            raise urllib.error.URLError("down")

        spec = ProbeSpec(probe_id="r2", method="GET", url="https://acme/x")
        status, _, body, _ = _default_transport(spec, retries=2,
                                                urlopen=always_fail)
        self.assertEqual(status, 0)
        self.assertIn("transport error", body)
        self.assertEqual(attempts["n"], 3)


if __name__ == "__main__":
    unittest.main()

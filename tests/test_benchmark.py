#!/usr/bin/env python3
"""Tests for the Phase 4 deterministic benchmark laboratory."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.benchmark import load_manifest, run_benchmark


def _fake_probe(responses):
    """Return a probe function serving the given {path: (status, body)} map."""

    def probe(url, method, body, headers):
        from urllib.parse import urlparse

        path = urlparse(url).path
        if path.startswith("/api/users/"):
            user_id = path.rsplit("/", 1)[-1]
            if user_id == "999":
                return 404, '{"error": "not found"}'
            return 200, json.dumps({"id": user_id, "role": "user"})
        if path == "/api/users" and method == "POST":
            return 201, json.dumps({"role": "admin", "isAdmin": True})
        if path == "/api/ingest":
            return 500, '{"error": "ingest parser failure"}'
        if path == "/api/gateway":
            return 200, '{"gateway": "open"}'
        if path == "/login":
            return 200, '{"token": "t"}'
        return responses.get(path, (404, "{}"))

    return probe


class TestBenchmark(unittest.TestCase):
    def test_manifest_loads(self):
        manifest = load_manifest()
        self.assertEqual(manifest["schema"], "bugwolf/benchmark/v1")
        self.assertGreaterEqual(len(manifest["cases"]), 7)

    def test_full_run_passes_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://lab",
                                   probe=_fake_probe(None), project_root=tmp)
            self.assertTrue(report["passed"], report)
            self.assertEqual(report["true_positives"], 4)   # bola x2 + mass + crash
            self.assertEqual(report["false_positives"], 0)  # negatives stay negative
            self.assertEqual(report["false_negatives"], 0)
            self.assertEqual(report["duplicate_rate"], 0.0)
            self.assertEqual(report["precision"], 1.0)
            self.assertEqual(report["recall"], 1.0)
            # Results persisted for the gate.
            out = Path(tmp) / "state" / "benchmark" / "latest.json"
            self.assertTrue(out.is_file())

    def test_false_positive_fails_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            # A broken detector reports the 404 negative control as a finding.
            def bad_probe(url, method, body, headers):
                if "/999" in url:
                    return 200, '{"id": "999", "role": "user"}'
                return _fake_probe(None)(url, method, body, headers)
            report = run_benchmark(manifest, base_url="http://lab",
                                   probe=bad_probe, project_root=tmp)
            self.assertFalse(report["passed"])
            self.assertEqual(report["false_positives"], 1)
            self.assertLess(report["precision"], 1.0)

    def test_missed_finding_fails_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            def blind_probe(url, method, body, headers):
                return 404, "{}"
            report = run_benchmark(manifest, base_url="http://lab",
                                   probe=blind_probe, project_root=tmp)
            self.assertFalse(report["passed"])
            self.assertEqual(report["false_negatives"], 4)
            self.assertEqual(report["recall"], 0.0)


if __name__ == "__main__":
    unittest.main()

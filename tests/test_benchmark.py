#!/usr/bin/env python3
"""Tests for the Phase 4 deterministic benchmark laboratory."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.benchmark import load_manifest, run_benchmark


def _fake_probe(responses=None):
    """Return a probe function serving the stub-target behaviors.

    ``responses`` optionally overrides the final {path: (status, body)} map
    (None behaves as an empty override).
    """
    responses = responses or {}

    def probe(url, method, body, headers):
        from urllib.parse import urlparse

        path = urlparse(url).path
        body_text = body if isinstance(body, str) else json.dumps(body or {})
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
        if path == "/api/checkout":
            # FIN-PARAM-02: the client-supplied price is trusted verbatim.
            try:
                payload = json.loads(body_text)
            except ValueError:
                payload = {}
            price = payload.get("price", 100)
            try:
                total = float(price) * float(payload.get("quantity", 1))
            except (TypeError, ValueError):
                total = 100.0
            gateway = ("test" if str(payload.get("payment_type", "")) == "99"
                       else "live")
            return 200, json.dumps({"order_id": "ord-1", "status": "pending",
                                    "total": total, "gateway": gateway})
        if path == "/api/payment/callback":
            # FIN-REPLAY-01: identical callback acked every time.
            return 200, '{"callback": "acknowledged"}'
        if path == "/api/voucher/redeem":
            # FIN-VOUCHER: single-use codes are never marked used.
            return 200, '{"code": "SAVE10", "discount": 10, "applied": true}'
        if path == "/api/checkout/confirm":
            # FIN-TOCTOU: paid-order confirm re-accepts a changed price.
            return 200, '{"order_id": "ord-1", "status": "paid", "total": 0.01}'
        return responses.get(path, (404, "{}"))

    return probe


class TestBenchmark(unittest.TestCase):
    def test_manifest_loads(self):
        manifest = load_manifest()
        self.assertEqual(manifest["schema"], "bugwolf/benchmark/v2")
        self.assertIsNone(manifest["lab"])  # real-world plugin: no shipped lab
        self.assertGreaterEqual(len(manifest["cases"]), 7)

    def test_full_run_passes_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp)
            self.assertTrue(report["passed"], report)
            # bola x2 + mass-assignment + fuzz crash + 4 FIN cases.
            self.assertEqual(report["true_positives"], 8)
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
                return _fake_probe()(url, method, body, headers)
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=bad_probe, project_root=tmp)
            self.assertFalse(report["passed"])
            self.assertEqual(report["false_positives"], 1)
            self.assertLess(report["precision"], 1.0)

    def test_missed_finding_fails_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            def blind_probe(url, method, body, headers):
                return 404, "{}"
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=blind_probe, project_root=tmp)
            self.assertFalse(report["passed"])
            self.assertEqual(report["false_negatives"], 8)
            self.assertEqual(report["recall"], 0.0)


if __name__ == "__main__":
    unittest.main()

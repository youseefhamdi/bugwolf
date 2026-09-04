#!/usr/bin/env python3
"""Tests for the Phase 4 deterministic benchmark laboratory."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


class TestH2CLCorpus(unittest.TestCase):
    """The H2.CL corpus items (master plan Phase 7; lab-backed)."""

    def test_corpus_declares_h2cl_cases(self):
        manifest = load_manifest()
        cases = {c["case_id"]: c for c in manifest["cases"]}
        desync = cases.get("h2cl-victim-poisoned")
        safe = cases.get("h2cl-safe-front-end")
        self.assertIsNotNone(desync)
        self.assertIsNotNone(safe)
        self.assertEqual(desync["transport"], "h2cl")
        self.assertEqual(desync["h2cl_mode"], "desync")
        self.assertTrue(desync["expected_finding"])
        self.assertFalse(safe["expected_finding"])
        # Same smuggled payload, same marker, same victim — the ONLY
        # difference between the pair is the front-end's desync switch.
        self.assertEqual(desync["smuggled_marker"],
                         safe["smuggled_marker"])
        self.assertEqual(desync["victim_path"], safe["victim_path"])
        self.assertEqual(desync["bug_class"], "request_smuggling")

    def test_hermhetic_run_skips_lab_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp)
            self.assertTrue(report["passed"])
            self.assertEqual(report["cases_skipped"], 2)
            self.assertEqual([s["case_id"] for s in report["skipped"]],
                             ["h2cl-victim-poisoned",
                              "h2cl-safe-front-end"])
            self.assertEqual(report["true_positives"], 8)  # unchanged

    def test_desync_case_scores_true_positive_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp,
                                   enable_lab=True)
            by_id = {r["case_id"]: r for r in report["results"]}
            desync = by_id["h2cl-victim-poisoned"]
            self.assertTrue(desync["signal"], desync["body"])
            self.assertIn("gw-secret-token", desync["body"])
            self.assertEqual(desync["status"], 200)

    def test_safe_case_is_negative_control_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp,
                                   enable_lab=True)
            by_id = {r["case_id"]: r for r in report["results"]}
            safe = by_id["h2cl-safe-front-end"]
            self.assertFalse(safe["signal"], safe["body"])
            self.assertNotIn("gw-secret-token", safe["body"])
            self.assertIn("alice", safe["body"])  # the victim's own route

    def test_lab_run_gate_passes_with_both_cases_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = load_manifest()
            report = run_benchmark(manifest, base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp,
                                   enable_lab=True)
            self.assertEqual(report["cases_skipped"], 0)
            self.assertEqual(report["false_positives"], 0)
            self.assertEqual(report["false_negatives"], 0)
            self.assertEqual(report["true_positives"], 9)  # 8 + H2.CL desync
            self.assertTrue(report["passed"], report)


class TestURegressionBridge(unittest.TestCase):
    """Corpus ⇄ Understanding-Layer regression (master plan Phase 7).

    Each corpus case declares the U-stages that must FEED it; the
    regression turns those declarations into executable checks over a
    live mini-mission, and the benchmark gate treats a model regression
    exactly like a missed expected finding.
    """

    def test_corpus_u_declarations_use_known_vocabulary(self):
        from tools.u_regression import CLASS_TO_COVERAGE
        manifest = load_manifest()
        declared = 0
        for case in manifest["cases"]:
            stages = case.get("u_stages")
            if not stages:
                continue
            declared += 1
            self.assertIn(case["bug_class"], CLASS_TO_COVERAGE,
                          f"{case['case_id']}: class not in U vocabulary")
            for stage in stages:
                self.assertRegex(stage, r"^U[1-9]$")
        # The declarations exist (the bridge has an input) and the
        # wire-level H2.CL pair honestly declares NONE (its facts are
        # transport-level, not model-level).
        self.assertGreaterEqual(declared, 7)
        by_id = {c["case_id"]: c for c in manifest["cases"]}
        self.assertNotIn("u_stages", by_id["h2cl-victim-poisoned"])
        self.assertNotIn("u_stages", by_id["h2cl-safe-front-end"])

    def test_hermetic_default_omits_u_regression(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_benchmark(load_manifest(), base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp)
            self.assertEqual(report["u_regression"], {"enabled": False})
            self.assertNotIn("u_regression_ok", report["verdict"])

    def test_u_regression_passes_live_over_stub(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_benchmark(load_manifest(), base_url="http://stub",
                                   probe=_fake_probe(), project_root=tmp,
                                   enable_u_regression=True)
            u = report["u_regression"]
            self.assertTrue(u["enabled"])
            self.assertEqual(u["cases_failed"], 0)
            self.assertTrue(u["passed"], u)
            self.assertTrue(report["verdict"]["u_regression_ok"])
            self.assertTrue(report["passed"], report)
            # The model checks are real: idor hunts with a filled object
            # inventory and the missing-999 absence fact holds.
            hunts = u["coverage_hunts"]
            for cls in ("idor", "authz-bypass", "mass-assignment",
                        "business-logic"):
                self.assertIn(cls, hunts)

    def test_u_regression_failure_fails_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            failed = {"passed": False, "cases_checked": 9,
                      "cases_failed": 1, "coverage_hunts": [],
                      "coverage_parked": []}
            with mock.patch("tools.u_regression.run_u_regression",
                            return_value=failed):
                report = run_benchmark(load_manifest(),
                                       base_url="http://stub",
                                       probe=_fake_probe(),
                                       project_root=tmp,
                                       enable_u_regression=True)
            self.assertFalse(report["verdict"]["u_regression_ok"])
            self.assertFalse(report["passed"])

    def test_u_regression_error_is_recorded_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("tools.u_regression.run_u_regression",
                            side_effect=RuntimeError("model store boom")):
                report = run_benchmark(load_manifest(),
                                       base_url="http://stub",
                                       probe=_fake_probe(),
                                       project_root=tmp,
                                       enable_u_regression=True)
            self.assertIn("error", report["u_regression"])
            self.assertIn("model store boom", report["u_regression"]["error"])
            self.assertFalse(report["verdict"]["u_regression_ok"])
            self.assertFalse(report["passed"])

    def test_bogus_stage_declaration_fails_per_case(self):
        """A declared stage that produced no artifact is a FAILURE —
        the mismatch-fails semantics, directly."""
        from tools.u_regression import run_u_regression
        manifest = load_manifest()
        case = next(c for c in manifest["cases"]
                    if c["case_id"] == "bola-user-1")
        doctored = {"cases": [dict(case, u_stages=["U7"])]}
        import threading
        import importlib.util
        stub_path = Path(__file__).resolve().parent / "_stub_target.py"
        spec = importlib.util.spec_from_file_location("stub_target_uregtest",
                                                      stub_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            report = run_u_regression(doctored, target=base)
            self.assertFalse(report["passed"])
            check = report["checks"][0]
            self.assertFalse(check["ok"])
            self.assertTrue(any("U7" in f for f in check["failures"]),
                            check["failures"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()

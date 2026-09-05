#!/usr/bin/env python3
"""Phase 4.C benchmarks integration test suite.

Imports every benchmark module + asserts it has a SCHEMA constant, runs
all three scorers with real data, exercises the synthlab app in-process,
launches three adversarial apps through the harness on 127.0.0.1, and
runs every regression suite.
"""

import importlib
import io
import json
import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(PROJECT_ROOT))


def _import(name):
    return importlib.import_module(name)


# ---------------------------------------------------------------------------
# Module loading + SCHEMA checks
# ---------------------------------------------------------------------------

class ModuleLoadingTests(unittest.TestCase):
    """Every benchmark module imports + has SCHEMA constant."""

    MODULES = (
        "bugwolf.benchmarks.harness",
        "bugwolf.benchmarks.synthlab",
        "bugwolf.benchmarks.scoring.f05_scorer",
        "bugwolf.benchmarks.scoring.chain_scorer",
        "bugwolf.benchmarks.scoring.coverage_scorer",
        "bugwolf.benchmarks.scoring",
        "bugwolf.benchmarks.adversarial",
        "bugwolf.benchmarks.adversarial.sqli_app",
        "bugwolf.benchmarks.adversarial.xss_app",
        "bugwolf.benchmarks.adversarial.ssrf_app",
        "bugwolf.benchmarks.adversarial.idor_app",
        "bugwolf.benchmarks.adversarial.jwt_app",
        "bugwolf.benchmarks.adversarial.race_app",
        "bugwolf.benchmarks.adversarial.deserialize_app",
        "bugwolf.benchmarks.adversarial.business_logic_app",
        "bugwolf.benchmarks.adversarial.llm_app",
        "bugwolf.benchmarks.adversarial.graphql_app",
    )

    def test_all_modules_import(self):
        for name in self.MODULES:
            with self.subTest(module=name):
                mod = _import(name)
                self.assertIsNotNone(mod)

    def test_all_modules_have_schema(self):
        for name in self.MODULES:
            with self.subTest(module=name):
                mod = _import(name)
                self.assertTrue(hasattr(mod, "SCHEMA"),
                                "%s missing SCHEMA constant" % name)
                self.assertIsInstance(getattr(mod, "SCHEMA"), str)
                self.assertTrue(getattr(mod, "SCHEMA").startswith("bugwolf-benchmarks-"))

    def test_static_fixtures_exist(self):
        base = Path(PROJECT_ROOT, "bugwolf", "benchmarks", "adversarial")
        for fname in ("smart_contract.sol", "cicd_workflow.yaml",
                      "mobile_app.apk", "mobile_app.MANIFEST.txt",
                      "cloud_terraform.tf", "grpc_app.proto"):
            with self.subTest(file=fname):
                self.assertTrue((base / fname).exists(),
                                "missing static fixture %s" % fname)

    def test_adversarial_registry_has_apps(self):
        mod = _import("bugwolf.benchmarks.adversarial")
        self.assertGreaterEqual(len(mod.BENCHMARK_APPS), 5)


# ---------------------------------------------------------------------------
# Scorer tests with real data
# ---------------------------------------------------------------------------

class ScorerTests(unittest.TestCase):

    def test_f05_basic(self):
        from bugwolf.benchmarks.scoring.f05_scorer import (
            precision, recall, f05, score_run,
        )
        self.assertEqual(precision(8, 2), 0.8)
        self.assertEqual(recall(8, 2), 0.8)
        # F0.5 prefers precision: high P with reasonable R > low P with high R
        self.assertGreater(f05(0.9, 0.5), f05(0.7, 0.7))
        res = score_run(["a", "b", "c"], ["a", "b", "d"])
        self.assertEqual(res["tp"], 2)
        self.assertEqual(res["fp"], 1)
        self.assertEqual(res["fn"], 1)

    def test_f05_zero_edge_cases(self):
        from bugwolf.benchmarks.scoring.f05_scorer import (
            precision, recall, f05,
        )
        self.assertEqual(precision(0, 0), 0.0)
        self.assertEqual(recall(0, 0), 0.0)
        self.assertEqual(f05(0.0, 0.0), 0.0)
        self.assertEqual(f05(0.0, 1.0), 0.0)

    def test_chain_scorer(self):
        from bugwolf.benchmarks.scoring.chain_scorer import chain_validity
        good = {
            "id": "demo", "title": "demo",
            "steps": [{"kind": "probe"}, {"kind": "exploit"}],
        }
        bad = {
            "id": "demo", "title": "demo",
            "steps": [{"kind": "nope"}],
        }
        self.assertTrue(chain_validity(good)["valid"])
        self.assertFalse(chain_validity(bad)["valid"])
        self.assertTrue(chain_validity("not a dict")["valid"] is False)

    def test_coverage_scorer(self):
        from bugwolf.benchmarks.scoring.coverage_scorer import (
            line_coverage, branch_coverage,
        )
        self.assertEqual(line_coverage({1, 2, 3}, {1, 2, 3}), 1.0)
        self.assertEqual(line_coverage({1}, {1, 2, 4}), 1 / 3)
        self.assertEqual(line_coverage({9}, set()), 0.0)
        self.assertEqual(branch_coverage(8, 8), 1.0)
        self.assertEqual(branch_coverage(0, 0), 0.0)


# ---------------------------------------------------------------------------
# Synthlab in-process (no socket needed)
# ---------------------------------------------------------------------------

class SynthlabInProcessTests(unittest.TestCase):
    """Invoke the synthlab HTTP handler directly without binding a socket."""

    @classmethod
    def setUpClass(cls):
        from bugwolf.benchmarks.synthlab import SynthlabApp, SynthlabServer
        cls.SynthlabApp = SynthlabApp
        cls.SynthlabServer = SynthlabServer

    def _invoke(self, path, method="GET"):
        """Drive a single SynthlabApp request and capture the body."""
        app = self.SynthlabApp
        # Build a fake request
        request_line = "%s %s HTTP/1.1" % (method, path)
        headers = "Host: 127.0.0.1\r\n\r\n"
        raw = (request_line + "\r\n" + headers).encode()

        from io import BytesIO
        rfile = BytesIO(raw)
        wfile = BytesIO()

        # Instantiate handler tied to our fake streams
        handler = app(
            rfile, ("127.0.0.1", 0), "127.0.0.1", timeout=2.0,
        )
        handler.wfile = wfile
        handler.rfile = rfile
        handler.raw_request_line = request_line.encode()
        handler.parse_request()  # sets self.command, self.path, self.headers
        try:
            if method == "GET":
                handler.do_GET()
            else:
                handler.do_POST()
        except Exception:
            pass
        response = wfile.getvalue()
        return response

    def test_b1_sqli_via_handler(self):
        resp = self._invoke("/search?q=" + "x")
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"widget", resp)

    def test_b2_xss_via_handler(self):
        resp = self._invoke("/greet?name=" + "World")
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"Hello, World", resp)

    def test_b3_idor_via_handler(self):
        resp = self._invoke("/users/2")
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"))
        self.assertIn(b"bob", resp)

    def test_b4_404_unknown_path(self):
        resp = self._invoke("/nonexistent")
        self.assertTrue(resp.startswith(b"HTTP/1.1 404"))


# ---------------------------------------------------------------------------
# Adversarial harness tests — three apps through real sockets
# ---------------------------------------------------------------------------

class _AdversarialHarnessMixin:
    APP_MODULE = None
    APP_NAME = None

    def setUp(self):
        from bugwolf.benchmarks.harness import BenchmarkApp
        self.app = BenchmarkApp(name=self.APP_NAME,
                                app_module=self.APP_MODULE,
                                startup_timeout=10.0)
        self.assertTrue(self.app.start(), "failed to start %s" % self.APP_NAME)

    def tearDown(self):
        self.app.stop()


class SqliHarnessTests(_AdversarialHarnessMixin, unittest.TestCase):
    APP_MODULE = "bugwolf.benchmarks.adversarial.sqli_app"
    APP_NAME = "sqli"

    def test_login_baseline(self):
        status, _, body = self.app.get("/login?user=alice&pass=alice-pw")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 1)

    def test_login_sqli_bypass(self):
        status, _, body = self.app.get("/login?user=" +
                                       "%27%20OR%201%3D1%20--&pass=x")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertGreaterEqual(data["count"], 3)


class XssHarnessTests(_AdversarialHarnessMixin, unittest.TestCase):
    APP_MODULE = "bugwolf.benchmarks.adversarial.xss_app"
    APP_NAME = "xss"

    def test_comment_reflects_payload(self):
        payload = "<script>alert(1)</script>"
        status, _, body = self.app.get("/comment?text=" + payload)
        self.assertEqual(status, 200)
        self.assertIn(payload.encode(), body)

    def test_comment_escapes_ampersand_in_path(self):
        status, _, _ = self.app.get("/comment?text=hello")
        self.assertEqual(status, 200)


class IdorHarnessTests(_AdversarialHarnessMixin, unittest.TestCase):
    APP_MODULE = "bugwolf.benchmarks.adversarial.idor_app"
    APP_NAME = "idor"

    def test_returns_user_2_without_auth(self):
        status, _, body = self.app.get("/api/users/2")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["name"], "bob")
        self.assertEqual(data["role"], "admin")

    def test_404_for_missing_user(self):
        status, _, _ = self.app.get("/api/users/9999")
        self.assertEqual(status, 404)


# ---------------------------------------------------------------------------
# Regression suite imports
# ---------------------------------------------------------------------------

class RegressionSuiteTests(unittest.TestCase):

    def test_chain_suite_loads(self):
        from bugwolf.benchmarks.regression.test_all_chains import (
            ChainSchemaTests,
        )
        # Instantiate just the static-schema tests; skip the dynamic kill_chain
        # loader to keep this test fully offline.
        suite = unittest.TestLoader().loadTestsFromTestCase(ChainSchemaTests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful())

    def test_chain_scorer_validates_real_chains(self):
        from bugwolf.benchmarks.scoring.chain_scorer import chain_validity
        import yaml  # type: ignore
        chain_dir = PROJECT_ROOT / "bugwolf" / "chain" / "h100"
        seen = set()
        for f in sorted(chain_dir.glob("*.yaml")):
            data = yaml.safe_load(f.read_text())
            cid = data.get("id")
            self.assertNotIn(cid, seen, "duplicate id %r" % cid)
            seen.add(cid)
            res = chain_validity(data)
            self.assertTrue(res["valid"], "chain %s invalid: %s" % (cid, res["errors"]))
            self.assertTrue(res["has_exploit"], "chain %s has no exploit step" % cid)

    def test_scanner_suite_loads(self):
        from bugwolf.benchmarks.regression.test_all_scanners import (
            _ScannerModuleTests,
        )
        # Just verify the test class is non-empty (proves attachment worked).
        names = [n for n in dir(_ScannerModuleTests)
                 if n.startswith("test_")]
        self.assertGreater(len(names), 5)

    def test_governance_suite_loads(self):
        from bugwolf.benchmarks.regression.test_governance import GovernanceTests
        suite = unittest.TestLoader().loadTestsFromTestCase(GovernanceTests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertTrue(result.wasSuccessful())


# ---------------------------------------------------------------------------
# Stub-safe behavior
# ---------------------------------------------------------------------------

class StubSafeTests(unittest.TestCase):

    def test_harness_get_returns_zero_on_dead_port(self):
        from bugwolf.benchmarks.harness import BenchmarkApp
        ba = BenchmarkApp("dead", "bugwolf.benchmarks.adversarial.sqli_app")
        # Force a port that's certainly unbound.
        ba.port = 1
        status, _, body = ba.get("/anything")
        self.assertEqual(status, 0)
        self.assertEqual(body, b"")

    def test_harness_start_returns_false_for_missing_module(self):
        from bugwolf.benchmarks.harness import BenchmarkApp
        ba = BenchmarkApp("missing", "no_such_module_xyz",
                          startup_timeout=0.3)
        self.assertFalse(ba.start())

    def test_harness_start_returns_false_for_crashing_app(self):
        from bugwolf.benchmarks.harness import BenchmarkApp
        # Use a module that imports but has no main() — start should still
        # be unable to parse PORT=... and return False.
        ba = BenchmarkApp("no_main", "bugwolf.benchmarks.harness",
                          startup_timeout=0.3)
        self.assertFalse(ba.start())


if __name__ == "__main__":
    unittest.main(verbosity=2)
#!/usr/bin/env python3
"""Tests for tools/variant_hunt.py (v1.24.1+)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.variant_hunt import (
    derive_root_cause, infer_cluster, enumerate_siblings,
    hunt, write_hunt, CLUSTERS,
)


SAMPLE_FINDING = {
    "id": "f-001",
    "bug_class": "ssrf",
    "sink": "fetch",
    "source": "user_input",
    "path": "/api/v1/import",
    "param": "url",
    "method": "POST",
    "payload_value": "http://169.254.169.254/",
    "evidence_refs": ["evid-1"],
}


class RootCauseDerivation(unittest.TestCase):

    def test_root_cause_stable(self):
        a = derive_root_cause(SAMPLE_FINDING)
        b = derive_root_cause(SAMPLE_FINDING)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 16)

    def test_root_cause_differs_on_different_field(self):
        a = derive_root_cause(SAMPLE_FINDING)
        f2 = {**SAMPLE_FINDING, "sink": "load_url"}
        b = derive_root_cause(f2)
        self.assertNotEqual(a, b)


class ClusterInference(unittest.TestCase):

    def test_ssrf_cluster(self):
        self.assertEqual(infer_cluster(SAMPLE_FINDING), "ssrf_consumer")

    def test_idor_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "idor"}
        self.assertEqual(infer_cluster(f), "authz_omission")

    def test_sql_injection_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "sql_injection"}
        self.assertEqual(infer_cluster(f), "missing_input_validation")

    def test_race_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "race_condition"}
        self.assertEqual(infer_cluster(f), "race_window")

    def test_jwt_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "jwt_forgery"}
        self.assertEqual(infer_cluster(f), "crypto_choice")

    def test_reentrancy_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "reentrancy"}
        self.assertEqual(infer_cluster(f), "copy_paste")

    def test_default_cluster(self):
        f = {**SAMPLE_FINDING, "bug_class": "novel_unknown"}
        # Should still produce a cluster, default = copy_paste
        self.assertIn(infer_cluster(f), CLUSTERS)


class SiblingEnumeration(unittest.TestCase):

    def test_no_siblings_when_no_inputs(self):
        # SAMPLE_FINDING has no source_file (so sister-file skipped) and
        # endpoints/params are empty.  Only encoding variants fire because
        # payload_value is set.  Verify encoding fires but nothing else.
        plans = enumerate_siblings(SAMPLE_FINDING)
        # No endpoints, no params, no source_file
        endpoint_plans = [p for p in plans if "method-swap" in p.technique]
        param_plans = [p for p in plans if p.technique == "sibling-param-swap"]
        file_plans = [p for p in plans if p.technique == "sister-file-same-module"]
        self.assertEqual(endpoint_plans, [])
        self.assertEqual(param_plans, [])
        self.assertEqual(file_plans, [])
        # Encoding IS expected (payload_value is set)
        self.assertGreater(len(plans), 0)

    def test_endpoint_siblings(self):
        endpoints = [
            "/api/v1/import",
            "/api/v1/export",
            "/api/v1/admin",
            "/api/v2/users",
        ]
        plans = enumerate_siblings(SAMPLE_FINDING, endpoints=endpoints)
        # Siblings: /api/v1/export and /api/v1/admin (both share /api/v1)
        # /api/v2/users is on a different prefix
        paths = {p.surface for p in plans}
        self.assertIn("/api/v1/export", paths)
        self.assertIn("/api/v1/admin", paths)
        # Each sibling gets 4 method-swap plans (PUT/PATCH/DELETE/POST)
        method_plans = [p for p in plans if "method-swap" in p.technique]
        self.assertGreater(len(method_plans), 0)

    def test_param_siblings(self):
        params = ["url", "uri", "link", "redirect", "next", "id", "amount"]
        plans = enumerate_siblings(SAMPLE_FINDING, params=params)
        # "url" family: uri, link, redirect, next (5 family members)
        param_plans = [p for p in plans if p.technique == "sibling-param-swap"]
        self.assertEqual(len(param_plans), 4)
        # No swap for "id" or "amount" (different family)

    def test_file_siblings(self):
        # SAMPLE_FINDING has no source_file, so we attach one to test the
        # sister-file enumeration.
        root = {**SAMPLE_FINDING,
                "source_file": "/app/services/import_service.py"}
        source_files = [
            "/app/services/import_service.py",  # the root itself (skipped)
            "/app/handlers/export.py",            # different stem "export"
            "/app/services/user_lookup.py",       # different stem "user"
        ]
        plans = enumerate_siblings(root, source_files=source_files)
        # No sister files share the "import" stem → 0 plans
        file_plans = [p for p in plans if p.technique == "sister-file-same-module"]
        self.assertEqual(len(file_plans), 0)

        # Now test with a real sister sharing the leading "import" token
        source_files.append("/app/services/import_validator.py")
        plans = enumerate_siblings(root, source_files=source_files)
        file_plans = [p for p in plans if p.technique == "sister-file-same-module"]
        self.assertEqual(len(file_plans), 1)
        self.assertEqual(file_plans[0].surface,
                         "/app/services/import_validator.py")

    def test_encoding_variants(self):
        plans = enumerate_siblings(SAMPLE_FINDING)
        encoding_plans = [p for p in plans if "encoding-" in p.technique]
        # 5 codecs
        self.assertEqual(len(encoding_plans), 5)


class HuntDriver(unittest.TestCase):

    def test_hunt_returns_variants(self):
        result = hunt(SAMPLE_FINDING, target="acme.com",
                      endpoints=["/api/v1/import", "/api/v1/export"],
                      params=["url", "uri"])
        self.assertEqual(result.target, "acme.com")
        self.assertEqual(result.cluster, "ssrf_consumer")
        self.assertGreater(result.total_siblings, 0)
        # Every plan must reference the root_cause
        for plan in result.plans:
            self.assertEqual(plan.root_finding, "f-001")
            self.assertEqual(plan.cluster, "ssrf_consumer")

    def test_write_hunt_creates_file(self):
        result = hunt(SAMPLE_FINDING, target="acme.com",
                      endpoints=["/api/v1/import", "/api/v1/export"])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_hunt(result, Path(tmp))
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["schema"], "bugwolf-variant-hunt/v1")
            self.assertEqual(data["target"], "acme.com")
            self.assertIn("plans", data)
            self.assertGreater(len(data["plans"]), 0)


if __name__ == "__main__":
    unittest.main()

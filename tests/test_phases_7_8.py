#!/usr/bin/env python3
"""Tests for Phases 7 and 8."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.reporting import ReportingGate
from tools.release_ops import (
    REQUIRED_BUNDLE_ENTRIES,
    build_sbom,
    check_bundle,
    smoke_imports,
)


class TestReportingGate(unittest.TestCase):
    def _complete_finding(self):
        return {
            "finding_id": "f-1",
            "title": "BOLA on user profile",
            "severity": "high",
            "reproduction": "GET /api/users/1 with no session returns alice",
            "impact_proof": "control account canary returned",
            "affected_versions": "1.2.x",
            "remediation": "enforce object-level authorization",
        }

    def test_incomplete_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t", tmp)
            finding = self._complete_finding()
            del finding["impact_proof"]
            result = gate.check(finding)
            self.assertFalse(result["reportable"])
            self.assertTrue(any("impact_proof" in r for r in result["refusal_reasons"]))

    def test_review_required_before_reportable(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t", tmp)
            gate.check(self._complete_finding())
            result = gate.review("f-1", "confirmed", reviewer="operator")
            self.assertTrue(result["reportable"])
            self.assertEqual(result["refusal_reasons"], [])

    def test_non_confirmed_review_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t", tmp)
            gate.check(self._complete_finding())
            result = gate.review("f-1", "needs_more_evidence")
            self.assertFalse(result["reportable"])
            self.assertTrue(any("needs_more_evidence" in r for r in result["refusal_reasons"]))

    def test_disclosure_workflow_tracks_patch_and_retest(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t", tmp)
            gate.check(self._complete_finding())
            gate.review("f-1", "confirmed")
            gate.disclose("f-1", vendor_contact="vendor@example.com")
            gate.record_vendor_response("f-1", response="will patch",
                                        patch_version="1.3.0")
            gate.record_retest("f-1", outcome="not reproducible on 1.3.0")
            record = gate.records()[0]
            self.assertEqual(record.disclosure.state, "retested")
            self.assertEqual(record.disclosure.patch_version, "1.3.0")
            self.assertTrue(record.is_reportable())


class TestReleaseOps(unittest.TestCase):
    def test_sbom_enumerates_modules_and_is_stable(self):
        sbom = build_sbom()
        self.assertGreater(sbom["module_count"], 50)
        self.assertTrue(any(m["name"].endswith("runtime_paths.py")
                            for m in sbom["modules"]))
        self.assertEqual(len(sbom["sbom_sha256"]), 64)
        sbom2 = build_sbom()
        self.assertEqual(sbom["sbom_sha256"], sbom2["sbom_sha256"])

    def test_bundle_check_detects_missing_entry_and_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "fake.skill"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("SKILL.md", "# fake")
                archive.writestr("VERSION", "1.0.0")
                archive.writestr("__pycache__/leak.pyc", "x")
            result = check_bundle(str(bundle))
            self.assertFalse(result["valid"])
            self.assertTrue(any("missing required entry" in e for e in result["errors"]))
            self.assertTrue(any("__pycache__" in e for e in result["errors"]))

    def test_bundle_check_rejects_traversal_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "evil.skill"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("../escape.txt", "x")
            result = check_bundle(str(bundle))
            self.assertFalse(result["valid"])
            self.assertTrue(any("path-traversal" in e for e in result["errors"]))

    def test_smoke_imports_all_modules(self):
        result = smoke_imports()
        self.assertTrue(result["valid"], result["failed"][:5])
        self.assertGreater(result["modules_tested"], 50)


if __name__ == "__main__":
    unittest.main()

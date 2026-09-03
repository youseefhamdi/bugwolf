#!/usr/bin/env python3
"""Tests for the offline Phase 0 readiness contract."""

import copy
import unittest

from tools.readiness import load_manifest, validate_manifest


class TestReadinessManifest(unittest.TestCase):
    def test_repository_manifest_is_valid_but_not_production_ready(self):
        manifest = load_manifest()
        report = validate_manifest(manifest)
        self.assertTrue(report["valid"])
        # L2: the harness is clean-checkout reproducible (proven by the
        # functional verifier inside validate_manifest, not asserted).
        self.assertEqual(report["readiness_level"],
                         "L2-reproducible-research-harness")
        self.assertTrue(
            manifest["global_controls"]["clean_checkout_reproducible"])
        self.assertFalse(manifest["claims"]["zero_day_guarantee"])
        # Boundary authorization is now enforced (scope gate) and the claim
        # is FUNCTIONALLY verified inside validate_manifest.
        self.assertTrue(
            manifest["global_controls"]
            ["authorization_enforced_at_execution_boundary"])
        self.assertTrue(
            manifest["global_controls"]["ssrf_protection_complete"])
        self.assertNotIn("authorization is not yet enforced",
                         " ".join(report["warnings"]))
        # Subprocess sandbox is now required AND functionally verified.
        self.assertTrue(
            manifest["global_controls"]["subprocess_sandbox_required"])
        self.assertNotIn("subprocess sandbox is not yet required",
                         " ".join(report["warnings"]))
        self.assertEqual(report["operator_authority"]["organization"], "unknown")
        self.assertEqual(report["operator_authority"]["research_depth"], "full_apt_team")
        self.assertTrue(manifest["claims"]["full_depth_apt_research"])
        self.assertTrue(manifest["global_controls"]["research_depth_never_reduced_by_gates"])
        self.assertEqual(
            report["execution_profiles"]["authorized_live"], "full_apt_team"
        )
        self.assertEqual(
            report["execution_profiles"]["disposable_lab"], "full_apt_team"
        )

    def test_missing_full_research_depth_is_invalid(self):
        manifest = load_manifest()
        manifest["execution_profiles"]["authorized_live"]["research_depth"] = "reduced"
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("full_apt_team" in error for error in report["errors"]))

    def test_depth_guarantee_is_required(self):
        manifest = load_manifest()
        manifest["claims"]["full_depth_apt_research"] = False
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("full_depth_apt_research" in error for error in report["errors"]))

    def test_operator_authority_must_not_be_hardcoded(self):
        manifest = load_manifest()
        manifest["operator_authority"]["organization"] = "Some Hardcoded Org"
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("must not be hardcoded" in error for error in report["errors"]))

    def test_phase_3_4_controls_are_required(self):
        manifest = load_manifest()
        report = validate_manifest(manifest)
        self.assertTrue(report["valid"])
        self.assertEqual(manifest["phase_completion"]["phase_3_research_substrate"], "complete")
        self.assertEqual(manifest["phase_completion"]["phase_4_benchmark_laboratory"], "complete")
        self.assertEqual(manifest["global_controls"]["benchmark_corpus"], "deterministic_synthetic_lab")

    def test_phase_2_5_6_complete_and_controls_required(self):
        manifest = load_manifest()
        report = validate_manifest(manifest)
        self.assertTrue(report["valid"])
        for phase in ("phase_2_evidence_validation", "phase_5_static_analysis",
                      "phase_6_research_intelligence"):
            self.assertEqual(manifest["phase_completion"][phase], "complete")
        for control in ("candidate_evidence_state_machine", "impact_validation_layers",
                        "static_source_fingerprinting", "patch_diff_reasoning",
                        "dependency_provenance", "research_source_provenance"):
            self.assertTrue(manifest["global_controls"][control])

    def test_phase_7_8_complete_and_controls_required(self):
        manifest = load_manifest()
        report = validate_manifest(manifest)
        self.assertTrue(report["valid"])
        for phase in ("phase_7_review_disclosure", "phase_8_release_ops"):
            self.assertEqual(manifest["phase_completion"][phase], "complete")
        for control in ("reporting_gate", "coordinated_disclosure",
                        "retest_workflow", "sbom_generation",
                        "bundle_integrity_check", "clean_install_smoke"):
            self.assertTrue(manifest["global_controls"][control])

    def test_version_drift_is_invalid(self):
        manifest = load_manifest()
        manifest["release_version"] = "0.0.0"
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("does not match VERSION" in error for error in report["errors"]))

    def test_zero_day_guarantee_is_rejected(self):
        manifest = load_manifest()
        manifest["claims"]["zero_day_guarantee"] = True
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("zero_day_guarantee" in error for error in report["errors"]))

    def test_supported_class_requires_entrypoint(self):
        manifest = load_manifest()
        manifest["target_classes"]["web_api"]["entrypoints"] = []
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("web_api" in error for error in report["errors"]))

    def test_missing_control_is_invalid(self):
        manifest = copy.deepcopy(load_manifest())
        del manifest["global_controls"]["canonical_finding_ledger"]
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("canonical_finding_ledger" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()

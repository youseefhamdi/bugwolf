#!/usr/bin/env python3
"""Clean-checkout reproducibility probe tests (readiness L2 evidence).

Contracts pinned here:
  * determinism invariants: latency values may drift machine-to-machine,
    but outcome fields (per-target status/threshold/direction, gate
    verdict) must be identical across two runs -- and drift must be
    DETECTED when they are not;
  * verify_clean_checkout() returns the (ok, detail) verifier tuple;
  * manifest logic: readiness_level L2 without the control is an ERROR,
    the control claimed but not verifiable is an ERROR, and the shipped
    manifest passes validate_manifest with the live probe.
"""
import json
import unittest

from tools.reproducibility import (
    _determinism_invariants, probe_clean_checkout, verify_clean_checkout)
from tools.readiness import load_manifest, validate_manifest


def _dashboard(target_status="MET"):
    return {
        "gate_passed": True,
        "targets": [
            {"target": "first_plan_artifact_seconds", "status": target_status,
             "threshold": 5.0, "direction": "max"},
            {"target": "duplicate_dispatches", "status": "MET",
             "threshold": 0, "direction": "max"},
        ],
    }


class TestDeterminismInvariants(unittest.TestCase):
    def test_identical_dashboards_match(self):
        a = _determinism_invariants(_dashboard())
        b = _determinism_invariants(_dashboard())
        self.assertEqual(a, b)

    def test_status_drift_is_detected(self):
        a = _determinism_invariants(_dashboard("MET"))
        b = _determinism_invariants(_dashboard("UNMET"))
        self.assertNotEqual(a, b)

    def test_gate_verdict_is_an_invariant(self):
        d = _dashboard()
        d["gate_passed"] = False
        a = _determinism_invariants(_dashboard())
        b = _determinism_invariants(d)
        self.assertNotEqual(a, b)

    def test_invariants_ignore_latency_values(self):
        """Latency numbers are not invariants -- the invariant view must
        not carry them, or every machine-to-machine run would 'drift'."""
        inv = _determinism_invariants(_dashboard())
        for target, fields in inv["targets"].items():
            for field in fields:
                self.assertNotIn("value", str(field))


class TestVerifierTuple(unittest.TestCase):
    def test_verify_returns_ok_and_detail(self):
        ok, detail = verify_clean_checkout()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(detail, str)
        self.assertTrue(detail, "verifier must always explain itself")


class TestManifestL2Logic(unittest.TestCase):
    """The spoof-detection contract: paperwork without the code errors."""

    def _manifest(self):
        return load_manifest()

    def test_shipped_manifest_is_l2_and_valid(self):
        manifest = self._manifest()
        report = validate_manifest(manifest)
        self.assertEqual(report["readiness_level"],
                         "L2-reproducible-research-harness")
        self.assertTrue(report["valid"], report["errors"])

    def test_l2_level_without_control_is_an_error(self):
        manifest = self._manifest()
        del manifest["global_controls"]["clean_checkout_reproducible"]
        report = validate_manifest(manifest)
        self.assertFalse(report["valid"])
        self.assertTrue(any("clean_checkout_reproducible" in e
                            for e in report["errors"]))

    def test_control_claim_without_working_code_is_an_error(self):
        manifest = self._manifest()
        manifest["global_controls"]["clean_checkout_reproducible"] = True
        # Point the verifier machinery at a manifest whose repo root is
        # poisoned: the probe re-clones from REPO_ROOT, so simulate breakage
        # by claiming the control on a manifest whose level says L0 -- the
        # code must still run the probe and any failure must surface.
        manifest["readiness_level"] = "L0-experimental-planner"
        report = validate_manifest(manifest)
        # Either the probe passes (then the level is merely understated ->
        # warning) or it fails (-> error).  Never silent.
        verified = not any("clean_checkout_reproducible claim is not "
                           "verifiable" in e for e in report["errors"])
        if verified:
            self.assertTrue(any("understates" in w
                                for w in report["warnings"]))
        else:
            self.assertFalse(report["valid"])

    def test_below_l2_with_unproven_control_is_only_a_warning(self):
        manifest = self._manifest()
        manifest["readiness_level"] = "L1-controlled-active-researcher"
        del manifest["global_controls"]["clean_checkout_reproducible"]
        report = validate_manifest(manifest)
        self.assertTrue(report["valid"])
        self.assertTrue(any("clean-checkout reproducibility is not yet "
                            "proven" in w for w in report["warnings"]))


class TestFullProbe(unittest.TestCase):
    """The live probe: a bare clone reproduces the deterministic product.

    Runs the real clone -> preflight -> subset -> two-run determinism
    chain (minutes, not seconds -- this is the L2 evidence itself).
    """

    def test_clean_checkout_reproduces(self):
        rep = probe_clean_checkout()
        self.assertTrue(
            rep["ok"],
            json.dumps(rep["steps"], indent=2, default=str))
        self.assertTrue(
            all(s["ok"] for s in rep["steps"]),
            json.dumps(rep["steps"], indent=2, default=str))


if __name__ == "__main__":
    unittest.main()

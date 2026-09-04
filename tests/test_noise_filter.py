#!/usr/bin/env python3
"""Noise-filter tests (INTEGRATION_PLAN Phase B, v1.25).

Locked contract:

  * each NOISE_PATTERNS category trips on its marker (title-scoped for
    subjective categories, body+title for sink patterns);
  * demonstrated impact OVERRIDES a category match (impact outranks the
    denylist — the ECC in-scope allowlist semantics);
  * the filter is ADVISORY: check() adds a ``noise`` section and a
    ``noise_held`` flag, never deletes or auto-rejects a finding;
  * the existing evidence/refusal semantics are unchanged.
"""

import tempfile
import unittest

from tools.reporting import ReportingGate, noise_reasons, NOISE_PATTERNS


class TestNoiseReasons(unittest.TestCase):
    def test_every_category_trips(self):
        probes = {
            "self-xss": {"title": "Self-XSS in profile editor"},
            "headers-only": {"title": "Missing security header: X-Frame"},
            "rate-limit-generic": {"title": "No rate limit on /login"},
            "local-only-deserialization": {
                "title": "Unsafe deserialization",
                "reproduction": "pickle.load(user_file)"},
            "cli-only-exec": {
                "title": "Code exec",
                "reproduction": "eval(user_input) in cli tool"},
            "hardcoded-shell": {
                "title": "Shell use",
                "reproduction": "subprocess.run(cmd, shell=True)"},
            "test-only": {
                "title": "SQLi",
                "reproduction": "payload against /tests/demo endpoint"},
        }
        for category, finding in probes.items():
            with self.subTest(category=category):
                reasons = noise_reasons(finding)
                self.assertTrue(reasons, finding)
                self.assertEqual(reasons[0]["category"], category)
                self.assertTrue(reasons[0]["why"])

    def test_impact_overrides_match(self):
        finding = {"title": "Unsafe deserialization",
                   "reproduction": "pickle.load(user_file)",
                   "impact_proof": "reached cloud metadata service, "
                                   "internal network read"}
        self.assertEqual(noise_reasons(finding), [])

    def test_clean_finding_has_no_noise(self):
        finding = {"title": "SQL injection in /api/search",
                   "reproduction": "union select via q param",
                   "impact_proof": "data exfiltration of users table"}
        self.assertEqual(noise_reasons(finding), [])


class TestGateIntegration(unittest.TestCase):
    def test_check_carries_advisory_noise_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t.example", project_root=tmp)
            result = gate.check({
                "finding_id": "f-noise",
                "title": "Self-XSS in profile editor",
                "review_decision": "confirmed",
                "reproduction": "paste payload into own profile",
                "impact_proof": "own session only",
                "affected_versions": "1.0",
                "remediation": "encode output",
            })
            self.assertTrue(result["noise"])
            self.assertEqual(result["noise"][0]["category"], "self-xss")
            # Held = noise present AND not reportable (it already wasn't:
            # the filter never changes reportability, it annotates).
            self.assertIn("noise_held", result)

    def test_noise_never_changes_reportability(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = ReportingGate("t.example", project_root=tmp)
            complete = {
                "finding_id": "f-clean",
                "title": "SQL injection in search",
                "review_decision": "confirmed",
                "reproduction": "union select via q",
                "impact_proof": "data exfiltration",
                "affected_versions": "1.0",
                "remediation": "parameterize queries",
            }
            noisy = dict(complete, finding_id="f-noisy",
                         title="Self-XSS in editor")
            # The noisy finding keeps its own (weak) impact text: a strong
            # impact_proof would correctly override the category match.
            noisy["impact_proof"] = "own session only, no cross-user reach"
            clean = gate.check(complete)
            marked = gate.check(noisy)
            self.assertTrue(clean["reportable"])
            self.assertTrue(marked["reportable"])  # advisory only
            self.assertTrue(marked["noise"])

    def test_pattern_table_matches_upstream(self):
        categories = [c for c, _, _ in NOISE_PATTERNS]
        self.assertEqual(categories, [
            "self-xss", "headers-only", "rate-limit-generic",
            "local-only-deserialization", "cli-only-exec",
            "hardcoded-shell", "test-only",
        ])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.js_token_forge import analyze_text, analyze_paths, build_plans


TIP_BUNDLE = """
var tokenConstant = "IUNvbXBhbnlAMSE=";
function getSDToken(deviceId, userId, strDesc) {
    var dateConstant = Math.floor(new Date().getTime()/21600000);
    var sdTokenTemp = deviceId + "|" + userId + "|" + strDesc + "|" + dateConstant;
    var encoded = CryptoJS.HmacSHA256(sdTokenTemp, tokenConstant);
    return encoded.toString(CryptoJS.enc.Base64);
}
"""


class TestTokenForgeAnalyzer(unittest.TestCase):
    def test_tip_bundle_surfaces_all_ingredients(self):
        findings = analyze_text(TIP_BUNDLE, "bundle.js")
        categories = {f.category for f in findings}
        for expected in ("hardcoded_secret", "client_signature_sink",
                         "token_claim_input", "token_mint_function"):
            self.assertIn(expected, categories)
        self.assertTrue(all(f.status == "static_signal_human_review_required"
                            for f in findings))

    def test_plan_is_high_forgeability_and_does_not_leak_secret(self):
        findings = analyze_text(TIP_BUNDLE, "bundle.js")
        plans = build_plans(findings)
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].forgeability, "high")
        self.assertEqual(plans[0].status, "offline_plan_only")
        self.assertTrue(plans[0].remediation)
        self.assertTrue(plans[0].validation_questions)
        # The raw secret must never be serialized into any output.
        blob = json.dumps([f.to_dict() for f in findings] +
                          [p.to_dict() for p in plans])
        self.assertNotIn("IUNvbXBhbnlAMSE", blob)
        self.assertTrue(all(f.evidence_hash for f in findings))
        self.assertTrue(all("line" not in f.to_dict() for f in findings)
                        or all(f.line_number >= 1 for f in findings))

    def test_secret_without_sink_is_low_forgeability(self):
        findings = analyze_text('const apiSecret = "deadbeefdeadbeef";\n', "cfg.js")
        plans = build_plans(findings)
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].forgeability, "low")

    def test_claim_input_alone_does_not_produce_a_plan(self):
        findings = analyze_text('var x = deviceId + "-suffix";\n', "x.js")
        self.assertTrue(findings)  # claim input is still a signal
        self.assertEqual(build_plans(findings), [])

    def test_analyze_paths_walks_directories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.js").write_text(TIP_BUNDLE)
            sub = root / "nested"
            sub.mkdir()
            (sub / "client.js").write_text("var secret = 'abcdef123456';\n")
            findings, plans = analyze_paths([root])
            self.assertEqual({f.source for f in findings},
                             {str(root / "app.js"), str(sub / "client.js")})
            self.assertEqual(len(plans), 2)


class TestJsCtIntelIntegration(unittest.TestCase):
    def test_analyze_javascript_emits_token_forge_outputs(self):
        from tools.js_ct_intel import analyze_javascript
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            js = root / "js"
            js.mkdir()
            (js / "bundle.js").write_text(TIP_BUNDLE)
            out = root / "out"
            summary = analyze_javascript(
                "example.com", [], js, out, scope=None, run_tools=False)
            self.assertGreater(summary["token_forge_findings"], 0)
            self.assertGreater(summary["token_forge_plans"], 0)
            findings = [json.loads(line) for line in
                        (out / "token-forge-findings.jsonl").read_text().splitlines()]
            plans = [json.loads(line) for line in
                     (out / "token-forge-plans.jsonl").read_text().splitlines()]
            self.assertTrue(findings)
            self.assertTrue(plans)
            self.assertEqual(plans[0]["forgeability"], "high")


if __name__ == "__main__":
    unittest.main()

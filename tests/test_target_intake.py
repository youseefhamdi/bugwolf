import json
import tempfile
import unittest
from pathlib import Path

from tools.target_intake import TargetSpec, export_academic, record_target_spec
from tools.evidence import EvidenceStore


class TestTargetIntake(unittest.TestCase):
    def spec(self):
        return TargetSpec(
            target_identifier="https://owned.example.test",
            domain="web/api",
            authorization_basis="own-asset",
            scope_notes={"in_scope": ["/api/*"], "out_of_scope": ["/admin"], "rate_limit": "1 rps", "testing_window": "24h", "credentials": "operator supplied"},
            roe_flags={"no_destructive": True}, validation_strategy="live",
            operator="operator@example.test", attestation="I attest I am authorized to test this asset.", campaign_id="C-1")

    def test_invalid_spec_is_rejected(self):
        self.assertTrue(TargetSpec("", "bad", "bad", operator="", attestation="").validate())

    def test_records_attestation_in_campaign_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = record_target_spec(self.spec(), project_root=tmp)
            self.assertEqual(result["capability_policy"], "maximum capability inside operator-supplied boundary")
            campaign = Path(tmp) / "state/campaigns/https_owned.example.test/target-spec.json"
            self.assertTrue(campaign.exists())
            evidence = EvidenceStore(self.spec().target_identifier)
            # EvidenceStore uses cwd, so inspect the target-specific campaign audit directly.
            audit = Path(tmp) / "state/campaigns/https_owned.example.test/audit.jsonl"
            self.assertIn("target_spec_attested", audit.read_text())
            self.assertTrue(result["evidence_id"])

    def test_academic_export_is_reproducible_artifact_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            record_target_spec(self.spec(), project_root=tmp)
            result = export_academic(target=self.spec().target_identifier, output_dir="research/academic", project_root=tmp,
                                     attempts=[{"case_id": "c1", "run_id": "r1", "found": True, "secret": "redact-me"}],
                                     methodology="# Methodology\nUse fixed seeds.")
            out = Path(tmp) / "research/academic"
            self.assertEqual(result["schema"], "bugwolf/academic-reproducibility/v1")
            for name in ("reproducibility.json", "aggregate-dataset.json", "baseline-vs-technique.json", "methodology.md", "methodology.tex", "evidence-appendix.md"):
                self.assertTrue((out / name).exists())
            dataset = json.loads((out / "aggregate-dataset.json").read_text())
            self.assertNotIn("redact-me", json.dumps(dataset))


if __name__ == "__main__":
    unittest.main()

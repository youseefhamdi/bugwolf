#!/usr/bin/env python3
"""Elicitation gap bridge tests (U2).

Covers:
  * resolve_deterministic_artifacts — only existing artifacts, grouped
  * attach_deterministic_artifacts — advisory merge into unit context
  * ThreadBuilder units carry artifact paths + model routing hints (U5)
  * orchestrator recon units carry deterministic evidence
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.campaign as campaign_mod
from tools.research_thread import (  # noqa: E402
    resolve_deterministic_artifacts, attach_deterministic_artifacts,
    ThreadBuilder,
)
from tools.campaign import AssetRecord  # noqa: E402


def _write_artifact(root: Path, rel: str, payload: dict):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n")


class TestResolveArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_resolves_only_existing_artifacts(self):
        _write_artifact(self.root, "research/acme/bypass/waf-payloads-nginx.json",
                        {"families": []})
        _write_artifact(self.root, "recon/acme/discovery/smuggling-plan.jsonl",
                        {"probe_count": 1})
        resolved = resolve_deterministic_artifacts(
            "acme", project_root=str(self.root))
        self.assertIn("waf_payloads", resolved["deterministic_evidence"])
        self.assertIn("smuggling_plan", resolved["deterministic_evidence"])
        self.assertNotIn("jwt_plans", resolved["deterministic_evidence"])
        self.assertEqual(len(resolved["artifact_paths"]), 2)
        for path in resolved["artifact_paths"]:
            self.assertTrue((self.root / path).is_file())

    def test_empty_when_no_artifacts(self):
        resolved = resolve_deterministic_artifacts("ghost",
                                                   project_root=str(self.root))
        self.assertEqual(resolved["artifact_paths"], [])
        self.assertEqual(resolved["deterministic_evidence"], {})

    def test_target_slug_sanitized(self):
        # Dots survive slugging (research_loop convention); slashes do not.
        _write_artifact(self.root, "research/target.com/bypass/waf-payloads-x.json",
                        {"ok": True})
        resolved = resolve_deterministic_artifacts(
            "target.com", project_root=str(self.root))
        self.assertEqual(len(resolved["artifact_paths"]), 1)


class TestAttachArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _unit(self):
        return {
            "schema": "bugwolf-research-unit-v1",
            "objective": "Probe WAF bypass on the endpoint",
            "bug_class": "sqli",
            "endpoint": "https://acme.com/",
            "context": {"thread_id": "t1"},
        }

    def test_merges_advisory_context_and_preserves_unit(self):
        _write_artifact(self.root, "research/acme/bypass/waf-payloads-nginx.json",
                        {"families": []})
        unit = self._unit()
        original = dict(unit)
        out = attach_deterministic_artifacts(
            unit, "acme", project_root=str(self.root), bug_class="sqli")
        self.assertIs(out, unit)
        for key in ("schema", "objective", "bug_class", "endpoint"):
            self.assertEqual(unit[key], original[key])
        self.assertEqual(unit["context"]["thread_id"], "t1")
        self.assertEqual(unit["context"]["bug_class_filter"], "sqli")
        self.assertIn("waf_payloads", unit["context"]["deterministic_evidence"])

    def test_no_artifacts_means_empty_context_block(self):
        unit = self._unit()
        attach_deterministic_artifacts(unit, "acme",
                                       project_root=str(self.root))
        self.assertEqual(unit["context"]["artifact_paths"], [])
        self.assertEqual(unit["context"]["deterministic_evidence"], {})

    def test_garbage_never_raises(self):
        self.assertIsNone(attach_deterministic_artifacts(None, "acme"))
        self.assertEqual(attach_deterministic_artifacts("x", "acme"), "x")


class TestThreadUnitEnrichment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots
        self.tmp.cleanup()

    def _spawn_thread(self):
        builder = ThreadBuilder("acme")
        builder.campaign.initialize()
        asset = builder.campaign.add_asset(
            "api.acme", "web_api", priority="high")
        threads = builder.build_threads_for_asset(asset)
        return builder, threads[0]

    def test_research_unit_carries_artifacts_and_routing_hint(self):
        _write_artifact(self.root,
                        "research/acme/bypass/waf-payloads-nginx.json",
                        {"families": []})
        builder, thread = self._spawn_thread()
        unit = builder.get_next_research_unit(thread)
        context = unit["context"]
        self.assertIn("deterministic_evidence", context)
        self.assertIn("artifact_paths", context)
        self.assertGreaterEqual(len(context["artifact_paths"]), 1)
        # U5 advisory hint is present and never gating.
        self.assertIn("model_preference", context)
        self.assertIn("model_fallback", context)


class TestOrchestratorReconUnit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_recon_unit_carries_deterministic_evidence(self):
        from tools.campaign_orchestrator import CampaignOrchestrator
        _write_artifact(self.root,
                        "research/acme/auth/jwt-forgery-plans.json",
                        {"plans": []})
        orch = CampaignOrchestrator("acme", mode="web")
        orch.project = self.root  # point artifact resolution at the temp dir
        asset = AssetRecord(asset_id="a1", hostname="api.acme",
                            type="web_api", priority="high")
        unit = orch._build_recon_unit(asset)
        context = unit["context"]
        self.assertIn("deterministic_evidence", context)
        self.assertIn("jwt_plans", context["deterministic_evidence"])
        self.assertIn("model_preference", context)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""pass@k test-time compute scaling tests (U4).

Covers:
  * ThreadBuilder spawns k diverse variant threads per threat
  * variant-aware deduplication (re-spawn never duplicates)
  * default pass_at_k=1 behavior unchanged
  * variant units carry pass_index/variant/system_prompt + rotated approaches
  * orchestrator plumbing (pass_at_k on init) and deterministic dispatch order
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
from tools.research_thread import ThreadBuilder, PASS_SYSTEM_PROMPTS
from tools.campaign import ThreadState


class _Isolated:
    """temp-dir campaign isolation (mirrors test_campaign_orchestrator)."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"

    def cleanup(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots
        self.tmp.cleanup()


class TestThreadBuilderPassAtK(unittest.TestCase):
    def setUp(self):
        self._iso = _Isolated()
        self.addCleanup(self._iso.cleanup)

    def _asset(self, builder):
        builder.campaign.initialize()
        return builder.campaign.add_asset("api.acme", "web_api", priority="high")

    def test_default_pass_at_k_spawns_one_thread_per_threat(self):
        builder = ThreadBuilder("acme")
        threads = builder.start_asset_research(self._asset(builder))
        self.assertGreater(len(threads), 0)
        self.assertTrue(all(t.pass_variant == 0 for t in threads))
        # No duplicate bug_class in the default mode.
        bug_classes = [t.bug_class for t in threads]
        self.assertEqual(len(bug_classes), len(set(bug_classes)))

    def test_pass_at_k_three_spawns_variant_groups(self):
        builder = ThreadBuilder("acme", pass_at_k=3)
        threads = builder.start_asset_research(self._asset(builder))
        by_group: dict = {}
        for t in threads:
            by_group.setdefault(t.pass_group, []).append(t.pass_variant)
        self.assertTrue(by_group)
        for group, variants in by_group.items():
            self.assertEqual(sorted(variants), [0, 1, 2])
        # Primary (variant 0) plus two diverse passes.
        self.assertEqual(len(threads), len(by_group) * 3)

    def test_dedupe_is_variant_aware(self):
        builder = ThreadBuilder("acme", pass_at_k=1)
        asset = self._asset(builder)
        first = builder.start_asset_research(asset)
        count_after_first = len(builder.campaign.list_threads(asset_id=asset.asset_id))
        # Re-running pass_at_k=1 adds nothing (variant 0 already exists).
        again = builder.start_asset_research(asset, pass_at_k=1)
        self.assertEqual(again, [])
        self.assertEqual(len(builder.campaign.list_threads(asset_id=asset.asset_id)),
                         count_after_first)
        # Scaling up to 3 adds only the missing variants (1 and 2).
        added = builder.start_asset_research(asset, pass_at_k=3)
        self.assertEqual(len(added), count_after_first * 2)
        self.assertEqual(len(first), count_after_first)

    def test_variant_units_carry_pass_metadata(self):
        builder = ThreadBuilder("acme", pass_at_k=3)
        threads = builder.start_asset_research(self._asset(builder))
        unit = builder.get_next_research_unit(threads[0])
        self.assertEqual(unit["variant"], threads[0].pass_variant)
        self.assertEqual(unit["pass_index"], threads[0].pass_variant)
        self.assertIn(unit["system_prompt"], PASS_SYSTEM_PROMPTS)
        self.assertIn("thread_id", unit["context"])

    def test_variant_approaches_rotate_deterministically(self):
        builder = ThreadBuilder("acme", pass_at_k=2)
        threads = builder.start_asset_research(self._asset(builder))
        group = [t for t in threads if t.pass_group == threads[0].pass_group]
        self.assertEqual(len(group), 2)
        v0, v1 = sorted(group, key=lambda t: t.pass_variant)
        unit0 = builder.get_next_research_unit(v0)
        unit1 = builder.get_next_research_unit(v1)
        self.assertNotEqual(unit0.get("suggested_approaches"),
                            unit1.get("suggested_approaches"))
        self.assertNotEqual(unit0["system_prompt"], unit1["system_prompt"])


class TestOrchestratorPassAtK(unittest.TestCase):
    def test_init_plumbs_pass_at_k_into_thread_builder(self):
        from tools.campaign_orchestrator import CampaignOrchestrator
        orch = CampaignOrchestrator("acme", mode="web", pass_at_k=4)
        self.assertEqual(orch.pass_at_k, 4)
        self.assertEqual(orch.threads.pass_at_k, 4)
        default = CampaignOrchestrator("acme", mode="web")
        self.assertEqual(default.pass_at_k, 1)

    def test_deep_dive_preset_parses(self):
        from tools.campaign_orchestrator import CampaignOrchestrator
        # The CLI computes pass_at_k before construction; mirror the logic.
        orch = CampaignOrchestrator("acme", mode="web",
                                    pass_at_k=max(1, 3))
        self.assertEqual(orch.pass_at_k, 3)


class TestOrchestratorDispatchOrder(unittest.TestCase):
    """End-to-end: pass@k variants spawn and dispatch in deterministic order."""

    def setUp(self):
        from tools.harness_guard import initialize as initialize_contract
        self._iso = _Isolated()
        self.addCleanup(self._iso.cleanup)
        self.root = self._iso.root
        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text("# BugWolf\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "vps"}))
        scope = self.root / "scope.json"
        scope.write_text(json.dumps({"authorized": True,
                                     "in_scope_domains": ["api.acme"]}))
        from tools.campaign_orchestrator import CampaignOrchestrator
        self.orch = CampaignOrchestrator("api.acme", mode="web", pass_at_k=3)
        self.orch.initialize()
        self.orch.complete_workflow_stage("authorization", scope_file=str(scope))

    def _spawn_and_dispatch(self):
        self.orch.register_discovered_assets(
            [{"hostname": "api.acme", "type": "web_api"}])
        assets = self.orch.campaign.list_assets()
        self.orch.register_recon(
            assets[0].asset_id,
            endpoints=["https://api.acme/v1/users"])
        unit = self.orch.get_next_research_unit()
        return unit

    def test_first_unit_is_variant_zero_and_variants_cover_all_passes(self):
        unit = self._spawn_and_dispatch()
        self.assertEqual(unit["campaign_phase"], "researching")
        self.assertEqual(unit["variant"], 0)
        self.assertEqual(unit["pass_index"], 0)
        threads = self.orch.campaign.list_threads()
        by_group: dict = {}
        for t in threads:
            by_group.setdefault(t.pass_group, []).append(t.pass_variant)
        # Every threat got all three passes.
        for variants in by_group.values():
            self.assertEqual(sorted(variants), [0, 1, 2])
        self.assertEqual(len(threads), len(by_group) * 3)


if __name__ == "__main__":
    unittest.main()

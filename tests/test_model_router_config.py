#!/usr/bin/env python3
"""Tests for the config-backed tier->model mapping (orchestrator plan lever P1).

Contract under test:
  * configs/models.json maps complexity tiers to advisory preference strings;
  * loading is fail-open -- missing/malformed manifests silently fall back to
    the shipped defaults and routing never raises, never gates;
  * shipped preference strings stay byte-identical to the pre-config router
    (MODEL_NONE / MODEL_SLM / MODEL_FRONTIER);
  * config overrides take effect (first candidate wins, cache keyed on
    path/mtime/size);
  * RoutingDecision carries fallback_preference and config_status() reports
    provenance without ever raising.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.core import model_router as mr
from tools.core.model_router import (
    MODEL_FRONTIER, MODEL_NONE, MODEL_SLM,
    TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER,
    route, route_unit, attach_hint, config_status,
)


class ConfigBackedRouterTestBase(unittest.TestCase):
    """Isolate tests from the real configs/models.json via temp candidates."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self._orig_cache = dict(mr._CONFIG_CACHE)
        mr._CONFIG_CACHE.clear()
        mr._CONFIG_CACHE.update({"key": None})

    def tearDown(self):
        self._td.cleanup()
        mr._CONFIG_CACHE.clear()
        mr._CONFIG_CACHE.update(self._orig_cache)

    def use_config(self, payload):
        """Point the loader at a temp manifest with the given JSON content."""
        path = self.td / "configs" / "models.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if payload is None:
            path.write_text("{ this is not json", encoding="utf-8")
        else:
            path.write_text(json.dumps(payload), encoding="utf-8")
        patcher = mock.patch.object(mr, "_config_candidates",
                                    return_value=[path])
        patcher.start()
        self.addCleanup(patcher.stop)
        return path

    def use_no_config(self):
        patcher = mock.patch.object(mr, "_config_candidates",
                                    return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)


class TestShippedDefaults(ConfigBackedRouterTestBase):

    def test_real_manifest_present_and_valid(self):
        # The repo ships a manifest; it must parse and define all three tiers.
        manifest = json.loads(
            (Path(mr.__file__).resolve().parent.parent.parent
             / "configs" / "models.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("schema"), "bugwolf-models/v1")
        for tier in (TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER):
            self.assertIn(tier, manifest["tiers"])
            self.assertTrue(manifest["tiers"][tier]["model_preference"])

    def test_default_candidates_resolve_to_shipped_manifest(self):
        status = config_status()
        self.assertTrue(status["config_loaded"])
        self.assertFalse(status["defaults_used"])
        self.assertTrue(status["config_sha256"])
        self.assertIn("configs", status["config_path"])

    def test_shipped_preference_strings_unchanged(self):
        # Byte-identical to the pre-config router defaults.
        status = config_status()
        self.assertEqual(status["preferences"], {
            TIER_DETERMINISTIC: MODEL_NONE,
            TIER_LOCAL: MODEL_SLM,
            TIER_FRONTIER: MODEL_FRONTIER,
        })
        self.assertEqual(status["fallback_preferences"], {
            TIER_DETERMINISTIC: MODEL_NONE,
            TIER_LOCAL: MODEL_NONE,
            TIER_FRONTIER: MODEL_SLM,
        })


class TestFailOpenBehavior(ConfigBackedRouterTestBase):

    def test_missing_manifest_falls_open(self):
        self.use_no_config()
        status = config_status()
        self.assertFalse(status["config_loaded"])
        self.assertTrue(status["defaults_used"])
        self.assertIsNone(status["config_path"])
        # Routing still works with shipped defaults.
        decision = route("synthesize an exploit chain",
                         bug_class="account_takeover")
        self.assertEqual(decision.tier, TIER_FRONTIER)
        self.assertEqual(decision.model_preference, MODEL_FRONTIER)

    def test_malformed_json_falls_open(self):
        self.use_config(None)  # invalid JSON
        status = config_status()
        self.assertFalse(status["config_loaded"])
        self.assertTrue(status["defaults_used"])
        self.assertIsNotNone(status["config_path"])  # found but unusable
        self.assertEqual(status["config_sha256"], "")

    def test_non_dict_manifest_falls_open(self):
        self.use_config(["not", "a", "dict"])
        self.assertTrue(config_status()["defaults_used"])

    def test_tiers_not_a_dict_falls_open(self):
        self.use_config({"schema": "bugwolf-models/v1", "tiers": "nope"})
        self.assertTrue(config_status()["defaults_used"])

    def test_partial_manifest_merges_with_defaults(self):
        self.use_config({
            "schema": "bugwolf-models/v1",
            "tiers": {
                "frontier": {"model_preference": "custom-frontier",
                             "fallback_preference": "custom-slm"},
                "bogus_tier": {"model_preference": "ignored"},
                "local_slm": {"fallback_preference": "none"},
            },
        })
        status = config_status()
        self.assertTrue(status["config_loaded"])
        # Overridden tier comes from config...
        self.assertEqual(status["preferences"][TIER_FRONTIER],
                         "custom-frontier")
        self.assertEqual(status["fallback_preferences"][TIER_FRONTIER],
                         "custom-slm")
        # ...untouched tiers keep shipped defaults.
        self.assertEqual(status["preferences"][TIER_DETERMINISTIC], MODEL_NONE)
        self.assertEqual(status["preferences"][TIER_LOCAL], MODEL_SLM)

    def test_routing_never_gates_even_on_garbage(self):
        self.use_config(None)
        for objective, bug_class in (
            ("", ""),
            ("fuzz this", "xss"),
            ("synthesis" * 100, "zero_day"),
        ):
            decision = route(objective, bug_class=bug_class)
            self.assertIn(decision.tier,
                          (TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER))
            self.assertTrue(decision.model_preference)
        self.assertIsNotNone(route_unit(None))
        self.assertIsNotNone(route_unit({"objective": 42, "context": "bad"}))


class TestConfigOverrideAndCache(ConfigBackedRouterTestBase):

    def test_override_changes_routing_decision(self):
        self.use_config({
            "schema": "bugwolf-models/v1",
            "tiers": {"frontier": {"model_preference": "opus-custom",
                                   "fallback_preference": "haiku-custom"}},
        })
        decision = route("synthesize an exploit chain for account takeover",
                         bug_class="account_takeover")
        self.assertEqual(decision.tier, TIER_FRONTIER)
        self.assertEqual(decision.model_preference, "opus-custom")
        self.assertEqual(decision.fallback_preference, "haiku-custom")
        # attach_hint surfaces both strings to the harness.
        unit = {"objective": "refute this zero-day candidate",
                "bug_class": "zero_day", "context": {}}
        attach_hint(unit)
        self.assertEqual(unit["context"]["model_preference"], "opus-custom")
        self.assertEqual(unit["context"]["model_fallback_preference"],
                         "haiku-custom")

    def test_cache_respects_file_changes(self):
        path = self.use_config({
            "schema": "bugwolf-models/v1",
            "tiers": {"frontier": {"model_preference": "v1-model"}},
        })
        self.assertEqual(config_status()["preferences"][TIER_FRONTIER],
                         "v1-model")
        # Rewrite the manifest and force a fresh mtime so the cache key moves.
        path.write_text(json.dumps({
            "schema": "bugwolf-models/v1",
            "tiers": {"frontier": {"model_preference": "v2-model"}},
        }), encoding="utf-8")
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        self.assertEqual(config_status()["preferences"][TIER_FRONTIER],
                         "v2-model")

    def test_config_status_reports_digest_and_never_raises(self):
        path = self.use_config({"schema": "bugwolf-models/v1",
                                "tiers": {"frontier": {
                                    "model_preference": "m"}}})
        status = config_status()
        self.assertEqual(status["config_path"], str(path))
        self.assertEqual(len(status["config_sha256"]), 64)
        # Garbage in -> still a well-formed status dict.
        self.use_config(None)
        status = config_status()
        for key in ("config_loaded", "config_path", "config_sha256",
                    "preferences", "fallback_preferences", "defaults_used"):
            self.assertIn(key, status)


if __name__ == "__main__":
    unittest.main()

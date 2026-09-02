#!/usr/bin/env python3
"""Integration tests: mandatory pre-flight wired into CampaignOrchestrator.

Contract under test (plan v2 section 4.5 + section 4.2 MISSION_CREATED):
  * initialize() runs the pre-flight before returning (order rule) and the
    manifest persists under state/preflight/;
  * ensure_preflight() is lazy and runs once per orchestrator; force=True
    re-runs;
  * get_context() carries the pre-flight digest (PF3 memory) and never
    raises when pre-flight is unavailable (fail-open);
  * every enriched unit carries context["preflight_digest"] so no lane has
    to rediscover machine capabilities;
  * a fresh campaign start publishes MISSION_CREATED exactly once (resume
    does not re-publish).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tools.campaign as campaign_mod
from tools.campaign_orchestrator import CampaignOrchestrator
from tools.harness_guard import initialize as initialize_contract


class OrchestratorPreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"

        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text("# BugWolf\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "vps"}))

        # Fast pre-flight: skip binary version probes (still writes the
        # manifest, checks MCP endpoints against nothing, publishes events).
        self._preflight_calls = []
        real_run = None
        from tools.runtime import preflight as pf_mod
        real_run = pf_mod.run_preflight

        def fast_run(target, *, project_root=None, probe_binaries=True,
                     mission_id=""):
            self._preflight_calls.append(target)
            return real_run(target, project_root=project_root,
                            probe_binaries=False, mission_id=mission_id)

        self._pf_patch = mock.patch("tools.runtime.preflight.run_preflight",
                                    side_effect=fast_run)
        self._pf_patch.start()
        # Keep the orchestrator's lazy import pointing at the patched callable.
        self.addCleanup(self._pf_patch.stop)

        self.orch = CampaignOrchestrator("example.test", mode="web")

    def tearDown(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots
        self.tmp.cleanup()

    # -- initialize order rule ----------------------------------------------

    def test_initialize_runs_preflight_and_persists_manifest(self):
        self.orch.initialize()
        self.assertEqual(len(self._preflight_calls), 1)
        manifest_path = (self.root / "state" / "preflight" / "manifest.json")
        self.assertTrue(manifest_path.is_file())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "bugwolf-preflight/v1")
        self.assertTrue(manifest["sha256"])

    def test_initialize_is_fail_open_when_preflight_breaks(self):
        with mock.patch("tools.runtime.preflight.run_preflight",
                        side_effect=RuntimeError("probe blew up")):
            state = self.orch.initialize()  # must not raise
            self.assertIsNotNone(state)
            self.assertIsNone(self.orch.ensure_preflight())
            self.assertEqual(self.orch.preflight_digest(), "")
        # Recoverable: a working preflight succeeds after the failure.
        manifest = self.orch.ensure_preflight(force=True)
        self.assertIsNotNone(manifest)
        self.assertTrue(self.orch.preflight_digest())

    # -- lazy / once semantics ----------------------------------------------

    def test_ensure_preflight_is_lazy_and_cached(self):
        self.assertEqual(self._preflight_calls, [])  # not yet run
        first = self.orch.ensure_preflight()
        self.assertIsNotNone(first)
        self.orch.ensure_preflight()
        self.orch.ensure_preflight()
        self.assertEqual(len(self._preflight_calls), 1)  # cached
        self.orch.ensure_preflight(force=True)
        self.assertEqual(len(self._preflight_calls), 2)  # forced re-run

    # -- PF3 memory ----------------------------------------------------------

    def test_context_carries_preflight_digest(self):
        self.orch.initialize()
        context = self.orch.get_context()
        self.assertTrue(context.preflight)
        self.assertIn("capabilities:", context.preflight.get("digest", ""))
        self.assertEqual(len(self._preflight_calls), 1)  # context reuses cache

    def test_units_carry_preflight_digest(self):
        self.orch.initialize()
        unit = self.orch.get_discovery_unit()
        self.assertIn("preflight_digest", unit["context"])
        self.assertIn("capabilities:", unit["context"]["preflight_digest"])

    def test_units_carry_digest_even_without_initialize(self):
        # Lazy path: enriching a unit before initialize() still discovers
        # capabilities exactly once (never blocks, never re-runs).
        unit = self.orch.get_discovery_unit()
        self.assertIn("preflight_digest", unit["context"])
        self.assertEqual(len(self._preflight_calls), 1)

    # -- section 4.2 MISSION_CREATED ------------------------------------------

    def test_mission_created_published_once_on_fresh_start(self):
        events = []
        bus = getattr(self.orch, "_signal_bus", None)
        if bus is None:
            self.skipTest("signal bus unavailable in this environment")
        bus.subscribe("MISSION_CREATED",
                      lambda event: events.append(event.payload))
        self.orch.initialize()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get("target"), self.orch.target)
        # Resume (second initialize) must not re-publish.
        self.orch.initialize()
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()

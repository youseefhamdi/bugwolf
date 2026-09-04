#!/usr/bin/env python3
"""Phase 8 tests: release hardening.

Contracts under test (plan v2 section 7 phase 8 + section 10 DoD):
  * The generated capability manifest verifies every documented capability
    against the implementation; any documented-but-missing capability
    fails release (the honesty rule).
  * Every CLI documented in commands/*.md resolves (exit 0, or exit 2 for
    the scheduler's clean not-found).
  * The plugin package is complete: plugin.json, hooks.json, all 8
    commands, MCP bridge.
  * Readiness manifest claims stay truthful (zero_day_guarantee false,
    human review required).
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REPO = Path(__file__).resolve().parents[1]


class CapabilityManifestTest(unittest.TestCase):
    """The generated manifest: documented = implemented, or no release."""

    def test_manifest_generates_and_is_releasable(self):
        from tools.capability_manifest import generate, SCHEMA
        manifest = generate()
        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertTrue(manifest["releasable"],
                        json.dumps(manifest["capabilities"], indent=2))
        self.assertEqual(manifest["honesty"]["zero_day_guarantee"], False)
        self.assertEqual(manifest["honesty"]["unmet_count"], 0)
        # All nine plan phases ship with evidence.
        self.assertEqual(len(manifest["plan_phases"]), 9)
        self.assertTrue(all(p["status"] == "shipped"
                            for p in manifest["plan_phases"].values()))
        # Persisted artifact.
        artifact = json.loads(
            (REPO / "state" / "release" /
             "capability_manifest.json").read_text())
        self.assertEqual(artifact["releasable"], True)

    def test_missing_module_fails_release(self):
        from tools import capability_manifest as cm
        original = dict(cm.ENGINE_MODULES)
        try:
            cm.ENGINE_MODULES["ghost_engine"] = "tools.runtime.does_not_exist"
            manifest = cm.generate()
            self.assertFalse(manifest["releasable"])
            unmet = [c for c in manifest["capabilities"]
                     if c["status"] == "missing"]
            self.assertEqual(len(unmet), 1)
            self.assertEqual(unmet[0]["capability"], "module:ghost_engine")
            self.assertEqual(manifest["honesty"]["unmet_count"], 1)
        finally:
            cm.ENGINE_MODULES.clear()
            cm.ENGINE_MODULES.update(original)
            # Restore the manifest on disk to the truthful state.
            cm.generate()

    def test_documented_clis_resolve(self):
        from tools.capability_manifest import DOCUMENTED_CLIS
        for name, cmd in DOCUMENTED_CLIS.items():
            env = dict(os.environ, BUGWOLF_PROJECT_ROOT=tempfile.mkdtemp())
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  env=env, timeout=60, cwd=str(REPO))
            self.assertIn(proc.returncode, (0, 2),
                          f"{name}: rc={proc.returncode} "
                          f"{(proc.stderr or proc.stdout)[:200]}")

    def test_all_documented_commands_exist(self):
        # commands/*.md frontmatter references map to real files.
        # 8 orchestrator commands + /bugwolf-sandbox (kill switch)
        # + /bugwolf-team (multi-agent waves)
        # + the six Phase 5 commands (leads/scope/research/chain/doctor/
        #   understand — master plan 5.x).
        commands = sorted((REPO / "commands").glob("bugwolf*.md"))
        self.assertEqual(len(commands), 16)
        plugin = json.loads(
            (REPO / ".claude-plugin" / "plugin.json").read_text())
        listed = sorted(Path(p).name for p in plugin["commands"])
        self.assertEqual(listed,
                         sorted(p.name for p in commands))


class ReleaseTruthTest(unittest.TestCase):
    """Readiness claims stay honest at release time."""

    def test_readiness_manifest_claims(self):
        from tools.readiness import load_manifest, validate_manifest
        report = validate_manifest(load_manifest())
        self.assertTrue(report["valid"], report["errors"])
        manifest = load_manifest()
        claims = manifest["claims"]
        self.assertIs(claims["zero_day_guarantee"], False)
        self.assertIs(claims["autonomous_production_exploitation"], False)
        self.assertIs(
            claims["reportable_findings_without_human_review"], False)
        controls = manifest["global_controls"]
        self.assertIs(
            controls["human_review_required_for_reportable_findings"], True)
        self.assertIs(controls["canonical_finding_ledger"], True)

    def test_migration_guide_documents_every_phase(self):
        guide = (REPO / "docs" / "MIGRATION.md").read_text()
        for phase in ("preflight", "scheduler", "lead", "modes", "OAST",
                      "browser validation", "race engine", "dedup",
                      "capability_manifest"):
            self.assertIn(phase, guide, phase)

    def test_docs_do_not_claim_pass_through_execution(self):
        """The v1.3.0 boundary is ENFORCED (scope gate deny-by-default,
        sandbox on every spawn).  Docs claiming pass-through execution
        or 'never blocks' scopes contradict the shipped product -- they
        are release lies and fail this test."""
        stale = ("pass-through execution", "never a block",
                 "never blocks", "never block execution", "never reject a")
        for rel in ("README.md", "SKILL.md", "AUDIT.md", "AUDIT_MAP.md",
                    "docs/OPERATOR_RUNBOOK.md"):
            text = (REPO / rel).read_text(encoding="utf-8").lower()
            for phrase in stale:
                self.assertNotIn(phrase, text,
                                 f"{rel} still claims '{phrase}'")
        # The enforced posture must be present where operators read it.
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertIn("deny-by-default", readme)
        self.assertIn("v1.3.0", readme)


if __name__ == "__main__":
    unittest.main()

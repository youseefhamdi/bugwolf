#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class TestSkillPackage(unittest.TestCase):
    def test_bundle_layout_and_version(self):
        version = (ROOT / "VERSION").read_text().strip()
        output = ROOT / "dist" / f"bugwolf-v{version}.skill"
        output.unlink(missing_ok=True)
        try:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "build_skill.sh")],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            with zipfile.ZipFile(output) as bundle:
                names = set(bundle.namelist())
            self.assertIn("SKILL.md", names)
            self.assertIn("VERSION", names)
            self.assertIn("tools/zero_day.py", names)
            self.assertIn("tools/execution_controller.py", names)
            self.assertIn("tools/environment_profile.py", names)
            self.assertIn("tools/harness_guard.py", names)
            self.assertIn("tools/stage_controller.py", names)
            self.assertIn("tools/recon_exec.py", names)
            self.assertIn("tools/harness_intelligence.py", names)
            self.assertIn("tools/harness_command.py", names)
            self.assertIn("tools/chain_orchestrator.py", names)
            self.assertIn("configs/harness/intelligence.json", names)
            self.assertIn("tools/adaptive_learning.py", names)
            self.assertIn("scripts/install_harness_contract.sh", names)
            self.assertIn("configs/harness/BUGWOLF.md", names)
            self.assertIn("configs/harness/AGENTS.md", names)
            self.assertIn("configs/harness/CLAUDE.md", names)
            self.assertIn("tools/js_ct_intel.py", names)
            self.assertIn("tools/js_token_forge.py", names)
            self.assertIn("tools/methodology_playbook.py", names)
            self.assertIn("tools/asset_intel.py", names)
            self.assertIn("tools/defensive_detection.py", names)
            self.assertIn("tools/identity_cloud.py", names)
            self.assertIn("tools/idor_research.py", names)
            self.assertIn("tools/chain_analyzer.py", names)
            self.assertIn("tools/paper_intel.py", names)
            self.assertIn("tools/post_finding_trigger.py", names)
            self.assertIn("tools/agent_bus.py", names)
            self.assertIn("tests/test_agent_bus_trigger.py", names)
            self.assertIn("tests/fixtures/agent-inventory-security-gaps.json", names)
            self.assertIn("tools/ai_defense.py", names)
            self.assertIn("tools/pii_firewall.py", names)
            self.assertIn("tools/data_governance.py", names)
            self.assertIn("tools/surface_model.py", names)
            self.assertIn("tools/mutator.py", names)
            self.assertIn("tools/discovery_scheduler.py", names)
            self.assertIn("tools/contract_discovery.py", names)
            self.assertIn("tools/schema_extractor.py", names)
            self.assertIn("tools/differential_runner.py", names)
            self.assertIn("tools/header_trust.py", names)
            self.assertIn("references/zero-day-research.md", names)
            self.assertIn("references/privacy-governance.md", names)
            self.assertIn("references/defensive-intelligence.md", names)
            self.assertIn("references/chain-analysis.md", names)
            self.assertIn("references/paper-intelligence.md", names)
            self.assertIn("references/discovery-core.md", names)
            self.assertIn("references/adaptive-learning.md", names)
            self.assertNotIn("bugwolf/SKILL.md", names)
            self.assertFalse(any(name.endswith(".pyc") for name in names))
            self.assertFalse(any("__pycache__/" in name for name in names))
        finally:
            output.unlink(missing_ok=True)

    def _build_bundles(self):
        version = (ROOT / "VERSION").read_text().strip()
        skill = ROOT / "dist" / f"bugwolf-v{version}.skill"
        freebuff = ROOT / "dist" / f"bugwolf-v{version}.freebuff.zip"
        skill.unlink(missing_ok=True)
        freebuff.unlink(missing_ok=True)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / "build_skill.sh")],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return skill, freebuff

    def test_freebuff_bundle_layout_and_version(self):
        """The Freebuff/Codebuff bundle is laid out as .agents/skills/bugwolf/…"""
        version = (ROOT / "VERSION").read_text().strip()
        _, output = self._build_bundles()
        try:
            self.assertTrue(output.is_file())
            with zipfile.ZipFile(output) as bundle:
                names = set(bundle.namelist())
            prefix = ".agents/skills/bugwolf/"
            self.assertIn(prefix + "SKILL.md", names)
            self.assertIn(prefix + "VERSION", names)
            self.assertIn(prefix + "tools/zero_day.py", names)
            self.assertIn(prefix + "tools/execution_controller.py", names)
            self.assertIn(prefix + "tools/harness_guard.py", names)
            self.assertIn(prefix + "tools/stage_controller.py", names)
            self.assertIn(prefix + "tools/recon_exec.py", names)
            self.assertIn(prefix + "tools/harness_intelligence.py", names)
            self.assertIn(prefix + "tools/harness_command.py", names)
            self.assertIn(prefix + "tools/chain_orchestrator.py", names)
            self.assertIn(prefix + "tools/paper_intel.py", names)
            self.assertIn(prefix + "tools/post_finding_trigger.py", names)
            self.assertIn(prefix + "tools/agent_bus.py", names)
            self.assertIn(prefix + "tests/test_agent_bus_trigger.py", names)
            self.assertIn(prefix + "tests/fixtures/agent-inventory-security-gaps.json", names)
            self.assertIn(prefix + "references/paper-intelligence.md", names)
            self.assertIn(prefix + "configs/harness/intelligence.json", names)
            self.assertIn(prefix + "tools/adaptive_learning.py", names)
            self.assertIn(prefix + "scripts/install_harness_contract.sh", names)
            self.assertIn(prefix + "configs/harness/BUGWOLF.md", names)
            self.assertIn(prefix + "configs/harness/AGENTS.md", names)
            self.assertIn(prefix + "configs/harness/CLAUDE.md", names)
            self.assertIn(prefix + "references/zero-day-research.md", names)
            # Not the flat Claude.ai layout: SKILL.md must sit under the skill dir.
            self.assertNotIn("SKILL.md", names)
            self.assertFalse(any(name.endswith(".pyc") for name in names))
            self.assertFalse(any("__pycache__/" in name for name in names))
        finally:
            output.unlink(missing_ok=True)

    def test_freebuff_deepseek_config_ships_in_both_bundles(self):
        """The Freebuff+DeepSeek runtime profile and project template ship
        in both the Claude.ai .skill and the Freebuff bundle."""
        skill, freebuff = self._build_bundles()
        try:
            with zipfile.ZipFile(skill) as bundle:
                skill_names = set(bundle.namelist())
                profile = json.loads(bundle.read("configs/freebuff-deepseek.json"))
            with zipfile.ZipFile(freebuff) as bundle:
                fb_names = set(bundle.namelist())
                fb_profile = json.loads(
                    bundle.read(".agents/skills/bugwolf/configs/freebuff-deepseek.json"))
            self.assertIn("configs/freebuff/AGENTS.md", skill_names)
            self.assertIn(".agents/skills/bugwolf/configs/freebuff/AGENTS.md", fb_names)
            self.assertEqual(profile["platform"], "freebuff")
            self.assertEqual(profile["model"]["provider"], "deepseek")
            self.assertEqual(profile["model"]["default"], "deepseek-v4-flash")
            self.assertEqual(profile, fb_profile)
            self.assertTrue(profile["runtime"]["gates"]["confirm_active"])
            self.assertTrue(profile["runtime"]["gates"]["confirm_destructive"])
            self.assertTrue(profile["runtime"]["gates"]["environment_preflight"])
            self.assertIn("intelligence_contract", profile["runtime"])
            self.assertIn("cross_surface_chain", profile["runtime"]["intelligence_contract"]["creative_angles"])
            self.assertEqual(profile["runtime"]["intelligence_contract"]["command_adapter"], "tools/harness_command.py")
        finally:
            skill.unlink(missing_ok=True)
            freebuff.unlink(missing_ok=True)

    def test_skill_frontmatter_is_discoverable(self):
        """The skill loader (Freebuff/Codebuff `npx skills`, Claude) requires
        `name` + `description` frontmatter on SKILL.md."""
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        frontmatter = text.split("---\n", 2)[1]
        self.assertIn("name: bugwolf", frontmatter)
        self.assertIn("description:", frontmatter)
        self.assertIn("---\n", text.split("---\n", 2)[2])

    def test_installed_bundle_writes_runtime_data_to_project(self):
        """Installed tools must not persist research artifacts inside the skill."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "install_freebuff.sh"), str(project)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            skill = project / ".agents" / "skills" / "bugwolf"
            run = subprocess.run(
                [sys.executable, str(skill / "tools" / "research_loop.py"),
                 "--checkpoint", "post-maps", "--mode", "solidity",
                 "--target", "installed-test", "--execute", "--no-search", "--json"],
                cwd=project, capture_output=True, text=True, check=False,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue((project / "research" / "installed-test" /
                             "post-maps" / "results.json").is_file())
            guard = subprocess.run(
                [sys.executable, str(skill / "tools" / "harness_guard.py"),
                 "--project-root", str(project), "--skill-root", str(skill),
                 "--verify", "--json"],
                cwd=project, capture_output=True, text=True, check=False,
            )
            self.assertEqual(guard.returncode, 0, guard.stderr)
            self.assertTrue(json.loads(guard.stdout)["ready"])
            self.assertFalse((skill / "research").exists())

    def test_generic_harness_contract_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "install_harness_contract.sh"), str(target)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((target / "BUGWOLF.md").is_file())
            self.assertTrue((target / "AGENTS.md").is_file())
            self.assertTrue((target / "CLAUDE.md").is_file())
            self.assertTrue((target / ".bugwolf" / "harness.json").is_file())

    def test_freebuff_install_script_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "install_freebuff.sh"), str(target)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            skill = target / ".agents" / "skills" / "bugwolf"
            self.assertTrue((skill / "SKILL.md").is_file())
            self.assertTrue((skill / "VERSION").is_file())
            self.assertTrue((skill / "tools" / "zero_day.py").is_file())
            self.assertTrue((skill / "tools" / "harness_guard.py").is_file())
            self.assertTrue((skill / "tools" / "stage_controller.py").is_file())
            self.assertTrue((skill / "tools" / "adaptive_learning.py").is_file())
            self.assertTrue((skill / "references" / "zero-day-research.md").is_file())
            self.assertTrue((target / "BUGWOLF.md").is_file())
            self.assertTrue((target / "AGENTS.md").is_file())
            self.assertTrue((target / "CLAUDE.md").is_file())
            self.assertTrue((target / ".bugwolf" / "harness.json").is_file())
            guard = subprocess.run(
                [sys.executable, str(skill / "tools" / "harness_guard.py"),
                 "--project-root", str(target), "--skill-root", str(skill),
                 "--verify", "--json"],
                cwd=target, capture_output=True, text=True, check=False,
            )
            self.assertEqual(guard.returncode, 0, guard.stderr)
            self.assertTrue(json.loads(guard.stdout)["ready"])
            # Installed tree is free of build artifacts.
            self.assertFalse(any(p.suffix == ".pyc" for p in skill.rglob("*")))
            self.assertFalse(any("__pycache__" in str(p) for p in skill.rglob("*")))


if __name__ == "__main__":
    unittest.main()

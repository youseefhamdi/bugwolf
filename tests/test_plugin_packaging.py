#!/usr/bin/env python3
"""Plugin packaging gates (master plan Phase 0.4 + 4.3).

Locks the v1.24.0 packaging contract:

  * version sync across VERSION / plugin.json / marketplace.json / CHANGELOG
  * manifest shape: referenced commands, hooks, skills, agents exist
  * agent front-matter shape: native ``model:`` + Claude Code tool allowlist;
    the silently-ignored ``model-tier:`` key is forbidden
  * generator sync: agents/bugwolf/*.md are byte-identical to the registry
  * native Task dispatch: every generated definition is structurally valid
    for ``Task(subagent_type="bugwolf:<role>")`` — subagent name matches the
    harness convention, lane discipline holds (verify agents are read-only),
    and the deny-by-default scope + sandbox contract is present.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.plugin_manifest import (  # noqa: E402
    check_agent_frontmatter,
    check_manifest_shape,
    check_version_sync,
    run_all,
)

AGENTS_DIR = ROOT / "agents" / "bugwolf"
VALID_MODELS = {"sonnet", "opus", "haiku", "inherit"}
CLAUDE_TOOL_RE = re.compile(
    r"^(Read|Write|Edit|Glob|Grep|Bash|WebFetch|WebSearch|Task|TodoWrite)$")


def _frontmatter(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path.name}: no front-matter"
    return text.split("---\n", 2)[1]


def _front_field(front: str, key: str) -> str:
    match = re.search(rf"^{key}:\s*(.+)$", front, re.MULTILINE)
    return match.group(1).strip() if match else ""


class TestVersionSync(unittest.TestCase):
    def test_all_version_surfaces_agree(self):
        report = check_version_sync(ROOT)
        self.assertTrue(report["ok"], report["failures"])

    def test_plugin_json_matches_version_file(self):
        version = (ROOT / "VERSION").read_text().strip()
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin["version"], version)

    def test_marketplace_matches_version_file(self):
        version = (ROOT / "VERSION").read_text().strip()
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(marketplace["metadata"]["version"], version)
        self.assertEqual(marketplace["plugins"][0]["version"], version)

    def test_changelog_head_is_current_version(self):
        version = (ROOT / "VERSION").read_text().strip()
        heading = re.search(r"^##\s+v(\d+\.\d+\.\d+)\b",
                            (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
                            re.MULTILINE)
        self.assertIsNotNone(heading, "no '## vX.Y.Z' heading in CHANGELOG")
        self.assertEqual(heading.group(1), version)


class TestManifestShape(unittest.TestCase):
    def test_manifest_shape_ok(self):
        report = check_manifest_shape(ROOT)
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["plugin"], "bugwolf")
        self.assertEqual(report["marketplace"], "bugwolf")

    def test_mcp_json_registers_bridge(self):
        mcp = json.loads((ROOT / ".mcp.json").read_text())
        server = mcp["mcpServers"]["bugwolf"]
        self.assertEqual(server["command"], "python3")
        self.assertIn("bridge/bugwolf-mcp.py", server["args"])
        self.assertTrue((ROOT / "bridge" / "bugwolf-mcp.py").is_file())

    def test_marketplace_declares_security_category(self):
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text())
        entry = marketplace["plugins"][0]
        self.assertEqual(entry["category"], "security")
        self.assertTrue(entry["tags"])
        self.assertTrue(entry["repository"].startswith("https://"))


class TestAgentFrontmatter(unittest.TestCase):
    def test_all_agents_pass_frontmatter_gate(self):
        report = check_agent_frontmatter(ROOT)
        self.assertTrue(report["ok"], report["failures"])
        self.assertGreaterEqual(report["checked"], 39)

    def test_no_legacy_model_tier_key_anywhere(self):
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            self.assertFalse(re.search(r"^model-tier:", front, re.MULTILINE),
                             f"{path.name}: legacy 'model-tier:' survived")

    def test_model_field_is_native_value(self):
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            model = _front_field(front, "model")
            self.assertIn(model, VALID_MODELS, f"{path.name}: model {model!r}")

    def test_tools_are_claude_code_tool_names(self):
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            tools = _front_field(front, "tools")
            self.assertTrue(tools, f"{path.name}: empty tools allowlist")
            for tool in [t.strip() for t in tools.split(",")]:
                self.assertRegex(tool, CLAUDE_TOOL_RE,
                                 f"{path.name}: non-Claude tool {tool!r}")

    def test_x_bugwolf_tier_preserves_router_vocabulary(self):
        valid_tiers = {"deterministic", "local_slm", "frontier"}
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            tier = _front_field(front, "x-bugwolf-tier").split(" ")[0]
            self.assertIn(tier, valid_tiers, f"{path.name}: tier {tier!r}")

    def test_bugwolf_modules_preserved_in_body(self):
        """The old tools: content (module names) must survive in the body."""
        for path in sorted(AGENTS_DIR.glob("*.md")):
            body = path.read_text(encoding="utf-8").split("---\n", 2)[2]
            self.assertIn("Tool modules", body,
                          f"{path.name}: module list lost from body")


class TestGeneratorSync(unittest.TestCase):
    def test_generated_agents_match_registry(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_agents.py", "--check"],
            cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TestNativeTaskDispatch(unittest.TestCase):
    """Structural validation for Task(subagent_type="bugwolf:<role>")."""

    def test_every_agent_name_uses_harness_convention(self):
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            name = _front_field(front, "name")
            self.assertRegex(name, r"^bugwolf:[a-z0-9-]+$",
                             f"{path.name}: name {name!r} not dispatchable")

    def test_verify_lane_is_read_only(self):
        front = _frontmatter(AGENTS_DIR / "verify.md")
        tools = [t.strip() for t in _front_field(front, "tools").split(",")]
        self.assertNotIn("Bash", tools,
                         "verify agent must not hold Bash (lane discipline)")
        self.assertIn("Read", tools)

    def test_report_lane_is_read_only(self):
        front = _frontmatter(AGENTS_DIR / "report.md")
        tools = [t.strip() for t in _front_field(front, "tools").split(",")]
        self.assertNotIn("Bash", tools)

    def test_hunt_lane_has_execution_and_dispatch(self):
        front = _frontmatter(AGENTS_DIR / "web-api.md")
        tools = [t.strip() for t in _front_field(front, "tools").split(",")]
        self.assertIn("Bash", tools)
        self.assertIn("Task", tools)

    def test_every_agent_carries_scope_and_sandbox_contract(self):
        for path in sorted(AGENTS_DIR.glob("*.md")):
            front = _frontmatter(path)
            self.assertIn("deny-by-default", _front_field(front, "scope"),
                          f"{path.name}: missing deny-by-default scope")
            self.assertIn("required", _front_field(front, "sandbox"),
                          f"{path.name}: sandbox not required")

    def test_registry_roles_and_files_match(self):
        sys.path.insert(0, str(ROOT))
        from tools.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        expected = {f"{role}.md" for role in registry.all_roles()}
        actual = {p.name for p in AGENTS_DIR.glob("*.md")}
        self.assertEqual(expected, actual)


class TestRunAllGate(unittest.TestCase):
    def test_full_gate_passes(self):
        report = run_all(str(ROOT))
        self.assertTrue(report["ok"], json.dumps(report, indent=2))


if __name__ == "__main__":
    unittest.main()

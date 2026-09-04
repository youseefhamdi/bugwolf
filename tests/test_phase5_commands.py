#!/usr/bin/env python3
"""Phase 5 command-surface tests (master plan 5.x).

The six operator commands (leads / scope / research / chain / doctor /
understand) must be registered in BOTH manifests, carry the front-matter
contract (description + argument-hint), reference only backends that exist
on disk (drift gate), and — for /bugwolf-understand — encode the
Understanding Layer doctrine: U1–U9 in strict order, the coverage gate
(park with reason), the Assumption Ledger as the zero-day hypothesis pool,
and the Hunting Brief as the output.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COMMANDS_DIR = ROOT / "commands"
NEW_COMMANDS = [
    "bugwolf-leads", "bugwolf-scope", "bugwolf-research",
    "bugwolf-chain", "bugwolf-doctor", "bugwolf-understand",
]
ALL_COMMANDS = [
    "bugwolf", "bugwolf-plan", "bugwolf-run", "bugwolf-status",
    "bugwolf-review", "bugwolf-report", "bugwolf-stop",
    "bugwolf-resume", "bugwolf-sandbox", "bugwolf-team",
] + NEW_COMMANDS


def _load(name: str):
    text = (COMMANDS_DIR / f"{name}.md").read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{name}: missing front-matter"
    parts = text.split("---\n", 2)
    return parts[1], parts[2]


def _field(front: str, key: str) -> str:
    match = re.search(rf"^{key}:\s*(.+)$", front, re.MULTILINE)
    return match.group(1).strip() if match else ""


class TestCommandRegistration(unittest.TestCase):
    def test_all_sixteen_commands_exist_on_disk(self):
        for name in ALL_COMMANDS:
            self.assertTrue((COMMANDS_DIR / f"{name}.md").is_file(), name)

    def test_both_manifests_register_every_command(self):
        expected = {f"commands/{name}.md" for name in ALL_COMMANDS}
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(set(plugin["commands"]), expected)
        self.assertEqual(set(marketplace["plugins"][0]["commands"]), expected)


class TestCommandShape(unittest.TestCase):
    def test_front_matter_contract(self):
        for name in NEW_COMMANDS:
            front, body = _load(name)
            self.assertTrue(_field(front, "description"), name)
            self.assertTrue(_field(front, "argument-hint"), name)
            self.assertGreaterEqual(len(body.strip()), 400, name)

    def test_referenced_backends_exist(self):
        """Every python3 backend a new command cites must exist on disk."""
        for name in NEW_COMMANDS:
            _, body = _load(name)
            refs = set(re.findall(
                r"python3 -m ([a-z0-9_.]+)|"
                r"python3 ((?:tools|hooks|bridge|scripts)/[a-z0-9_/]+\.py)",
                body))
            self.assertTrue(refs, f"{name}: no backend commands referenced")
            for mod, rel in refs:
                if mod and mod != "unittest":
                    candidate = ROOT.joinpath(*mod.split("."))
                    self.assertTrue(
                        candidate.with_suffix(".py").is_file()
                        or (candidate / "__init__.py").is_file(),
                        f"{name}: missing backend module {mod}")
                elif rel:
                    self.assertTrue((ROOT / rel).is_file(),
                                    f"{name}: missing backend file {rel}")

    def test_scope_command_shows_live_gate_preview(self):
        _, body = _load("bugwolf-scope")
        self.assertIn("ScopeGate", body)
        self.assertIn("deny_entries", body)
        self.assertIn("scope_contract.json", body)
        self.assertIn("bugwolf_pretool_scope_hook.py", body)

    def test_leads_command_encodes_kill_guard(self):
        _, body = _load("bugwolf-leads")
        self.assertIn("--next-mutation", body)
        self.assertIn("PARK", body)
        self.assertIn("chain pool", body)

    def test_research_command_covers_all_seven_checkpoints(self):
        _, body = _load("bugwolf-research")
        for checkpoint in ("R1", "R2", "R3", "R4", "R5", "R6", "R7"):
            self.assertIn(checkpoint, body)
        self.assertIn("research_loop.py", body)


class TestUnderstandDoctrine(unittest.TestCase):
    """/bugwolf-understand is the Understanding Layer's operator front door."""

    def setUp(self):
        _, self.body = _load("bugwolf-understand")

    def test_u_stages_present_in_strict_order(self):
        positions = [self.body.index(marker) for marker in (
            "**U1 ", "**U2 ", "**U3 ", "**U4 ", "**U5 ",
            "**U6 ", "**U7 ", "**U8 ", "**U9 ")]
        self.assertEqual(positions, sorted(positions),
                         "U-stages must appear in sequential order")

    def test_thesis_is_enforced_by_construction(self):
        self.assertIn("you cannot hunt what you haven't modeled",
                      self.body.lower())
        self.assertIn("fail-closed", self.body.lower())

    def test_coverage_gate_parks_classes_with_reason(self):
        self.assertIn("parked with reason", self.body.lower())
        self.assertIn("coverage", self.body.lower())

    def test_assumption_ledger_is_the_zero_day_seed_list(self):
        self.assertIn("assumptions.jsonl", self.body)
        self.assertIn("dispro", self.body.lower())
        self.assertIn("zero-day", self.body.lower())

    def test_hunting_brief_is_the_output(self):
        self.assertIn("Hunting Brief", self.body)
        self.assertIn("target-model.json", self.body)
        self.assertIn("hunting-brief.md", self.body)


if __name__ == "__main__":
    unittest.main()

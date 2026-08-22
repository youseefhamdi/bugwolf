#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.harness_guard import (
    CONTRACT_MARKER,
    INTELLIGENCE_MARKER,
    INTELLIGENCE_PROFILE,
    INTELLIGENCE_SCHEMA,
    INTELLIGENCE_TOOL,
    COMMAND_ADAPTER,
    CHAIN_ORCHESTRATOR,
    PAPER_INTELLIGENCE_TOOL,
    PAPER_INTELLIGENCE_REFERENCE,
    POST_FINDING_TRIGGER,
    REQUIRED_SEQUENCE,
    initialize,
    record_checkpoint,
    verify,
)


class TestHarnessGuard(unittest.TestCase):
    def test_init_and_verify_are_offline_and_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            initialized = initialize(str(project))
            self.assertTrue(initialized["ready"])
            self.assertEqual(initialized["marker"], CONTRACT_MARKER)
            self.assertEqual(initialized["intelligence_marker"], INTELLIGENCE_MARKER)
            self.assertEqual(initialized["required_sequence"], REQUIRED_SEQUENCE)
            self.assertTrue((project / ".bugwolf" / "harness.json").is_file())

            checked = verify(str(project))
            self.assertTrue(checked["ready"])
            self.assertEqual(checked["errors"], [])
            self.assertEqual(checked["network"], "not performed")

    def test_verify_detects_skill_contract_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            skill = project / "skill"
            for relative in ("SKILL.md", "references/research-loop.md",
                             "references/isolation.md", INTELLIGENCE_PROFILE,
                             INTELLIGENCE_TOOL, COMMAND_ADAPTER,
                             CHAIN_ORCHESTRATOR, PAPER_INTELLIGENCE_TOOL,
                             PAPER_INTELLIGENCE_REFERENCE, POST_FINDING_TRIGGER):
                path = skill / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if relative == INTELLIGENCE_PROFILE:
                    path.write_text(json.dumps({
                        "schema": INTELLIGENCE_SCHEMA,
                        "marker": INTELLIGENCE_MARKER,
                        "creative_angles": ["boundary_flip", "differential_pair", "state_and_time"],
                        "evidence_states": ["hypothesis"],
                        "direct_invocation": {"prefix": "bugwolf"},
                    }))
                else:
                    path.write_text(relative)
            initialize(str(project), str(skill))
            (skill / "SKILL.md").write_text("changed")
            checked = verify(str(project), str(skill))
            self.assertFalse(checked["ready"])
            self.assertTrue(any("contract changed" in error
                                for error in checked["errors"]))

    def test_invalid_intelligence_profile_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            skill = project / "skill"
            source = Path(__file__).resolve().parent.parent
            for relative in ("SKILL.md", "references/research-loop.md",
                             "references/isolation.md", INTELLIGENCE_PROFILE,
                             INTELLIGENCE_TOOL, COMMAND_ADAPTER,
                             CHAIN_ORCHESTRATOR, PAPER_INTELLIGENCE_TOOL,
                             PAPER_INTELLIGENCE_REFERENCE, POST_FINDING_TRIGGER):
                path = skill / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                source_path = source / relative
                path.write_text(source_path.read_text(encoding="utf-8")
                                if source_path.is_file() else "placeholder")
            initialize(str(project), str(skill))
            (skill / INTELLIGENCE_PROFILE).write_text("{}")
            checked = verify(str(project), str(skill))
            self.assertFalse(checked["ready"])
            self.assertTrue(any("intelligence profile" in error
                                for error in checked["errors"]))

    def test_checkpoint_record_requires_verified_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            initialize(str(project))
            result = record_checkpoint("pre-hunt", str(project))
            self.assertEqual(result["recorded"]["checkpoint"], "pre-hunt")
            lines = (project / ".bugwolf" / "checkpoints.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["checkpoint"], "pre-hunt")

    def test_invalid_checkpoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            initialize(str(project))
            with self.assertRaises(ValueError):
                record_checkpoint("not-a-checkpoint", str(project))


if __name__ == "__main__":
    unittest.main()

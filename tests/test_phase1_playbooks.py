#!/usr/bin/env python3
"""Tests for Phase 1.2 typed YAML playbook system.

Covers:
  * every YAML file in bugwolf/playbooks/ validates as a Playbook
  * schema, payload lookup, dedupe, governance union, conflicts
  * mini YAML parser handles comments / quotes / nested lists / ints / bools
  * mini YAML parser rejects anchors / tags / multi-doc
  * shim in tools/methodology_playbook.py returns a valid Playbook

No external dependencies; only Python stdlib + the project's own modules.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make sure both packages are importable when invoked from project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from bugwolf.playbooks import (  # noqa: E402
    SCHEMA,
    ComposedPlaybook,
    Playbook,
    PlaybookComposer,
    PlaybookLoader,
    PlaybookValidationError,
)
from bugwolf.playbooks.base import _mini_yaml_parse  # noqa: E402
from tools.methodology_playbook import load_yaml_playbook  # noqa: E402


PLAYBOOKS_DIR = PROJECT_ROOT / "bugwolf" / "playbooks"
ALL_YAML_NAMES = [
    "recon",
    "webvuln",
    "ssrf",
    "ssti",
    "jwt",
    "graphql",
    "race",
    "takeover",
    "supabase",
    "deserialize",
]


class TestPhase1Playbooks(unittest.TestCase):
    def setUp(self) -> None:
        self.loader = PlaybookLoader()
        self.playbooks = self.loader.load_all(PLAYBOOKS_DIR)
        self.composer = PlaybookComposer(PLAYBOOKS_DIR)

    # ---- Per-YAML validation ----

    def test_every_yaml_validates(self) -> None:
        for name in ALL_YAML_NAMES:
            with self.subTest(name=name):
                self.assertIn(name, self.playbooks, f"missing playbook {name}")
                pb = self.playbooks[name]
                self.assertEqual(pb.schema, SCHEMA)
                # validate() should be idempotent and return self
                self.assertIs(pb.validate(), pb)
                # mandatory precondition keys
                self.assertIn("target_is_reachable", pb.preconditions)
                self.assertIn("scope_allows_active", pb.preconditions)
                # every payload has a requires_scope_verb
                for p in pb.payloads:
                    self.assertIn(
                        p.requires_scope_verb,
                        {"passive", "active", "destructive"},
                    )
                # mandatory budget and governance
                self.assertGreater(pb.budget.max_requests, 0)
                self.assertIn(
                    pb.governance.scope_class, {"passive", "active", "destructive"}
                )
                self.assertIsInstance(pb.governance.destructive_allowed, bool)

    def test_loader_rejects_unknown_schema(self) -> None:
        bad = """
schema: not-a-real-schema
name: bogus
preconditions:
  target_is_reachable: true
  scope_allows_active: true
payload_catalog: []
evidence_collection: []
post_conditions: {}
budget:
  max_requests: 1
  max_wall_clock: 1
  min_interval_ms: 0
governance:
  requires_approval: false
  scope_class: passive
  require_reproducible_evidence: true
  destructive_allowed: false
  notes: ""
"""
        with self.assertRaises(PlaybookValidationError):
            self.loader.loads(bad)

    def test_payload_by_id_for_ssrf(self) -> None:
        ssrf = self.playbooks["ssrf"]
        p = ssrf.payload_by_id("imds_aws")
        self.assertEqual(p.id, "imds_aws")
        self.assertEqual(p.expected_status, 200)
        self.assertIn("cloud_metadata", p.sinks)
        # negative path: missing id raises KeyError
        with self.assertRaises(KeyError):
            ssrf.payload_by_id("does_not_exist")

    def test_compose_dedupes_payloads(self) -> None:
        composed = self.composer.compose(["ssrf", "ssrf"])
        self.assertIsInstance(composed, ComposedPlaybook)
        # Payload id counts must match a single ssrf playbook, not double.
        single = self.playbooks["ssrf"]
        self.assertEqual(
            len(composed.merged_payloads),
            len(single.payloads),
        )
        # Confirm both source names are recorded.
        self.assertEqual(composed.playbooks, ("ssrf", "ssrf"))

    def test_validate_compatibility_flags_scope_class_conflict(self) -> None:
        # recon is scope_class=active, takeover is scope_class=passive.
        # Mixing them should produce a scope_class conflict message.
        conflicts = self.composer.validate_compatibility(["recon", "takeover"])
        self.assertTrue(
            any("scope_class" in c for c in conflicts),
            f"expected scope_class conflict, got {conflicts!r}",
        )

    def test_validate_compatibility_flags_destructive_conflict(self) -> None:
        # ssrf has destructive_allowed=False. Build an ad-hoc second playbook
        # in memory with destructive_allowed=True to provoke a conflict.
        from bugwolf.playbooks.base import BudgetSpec, GovernanceSpec

        permissive = Playbook(
            schema=SCHEMA,
            name="synthetic_destructive",
            preconditions={"target_is_reachable": True, "scope_allows_active": True},
            payloads=(),
            evidence=(),
            post_conditions={},
            budget=BudgetSpec(),
            governance=GovernanceSpec(destructive_allowed=True),
        )
        ssrf = self.playbooks["ssrf"]
        conflicts = PlaybookComposer.validate_compatibility_loaded([ssrf, permissive])
        self.assertTrue(
            any("destructive_allowed" in c for c in conflicts),
            f"expected destructive conflict, got {conflicts!r}",
        )

    def test_governance_union_requires_approval(self) -> None:
        # recon has requires_approval=False, webvuln has requires_approval=True.
        # The composed governance union must require approval.
        recon = self.playbooks["recon"]
        webvuln = self.playbooks["webvuln"]
        self.assertFalse(recon.governance.requires_approval)
        self.assertTrue(webvuln.governance.requires_approval)
        composed = self.composer.compose(["recon", "webvuln"])
        self.assertTrue(composed.governance.requires_approval)

    def test_governance_union_destructive_and(self) -> None:
        # Both source playbooks have destructive_allowed=False, so the
        # AND-union result must also be False.
        composed = self.composer.compose(["ssrf", "webvuln"])
        self.assertFalse(composed.governance.destructive_allowed)

    def test_mini_yaml_parser_basic_features(self) -> None:
        text = """
# this is a comment
name: ssrf
enabled: true
count: 42
items:
  - a
  - b
  - c
nested:
  inner_key: "quoted value"
  flag: false
"""
        result = _mini_yaml_parse(text)
        self.assertEqual(result["name"], "ssrf")
        self.assertIs(result["enabled"], True)
        self.assertEqual(result["count"], 42)
        self.assertEqual(result["items"], ["a", "b", "c"])
        self.assertEqual(result["nested"]["inner_key"], "quoted value")
        self.assertIs(result["nested"]["flag"], False)

    def test_mini_yaml_parser_rejects_anchors_aliases_tags_multidoc(self) -> None:
        with self.subTest("anchor"):
            with self.assertRaises(PlaybookValidationError):
                _mini_yaml_parse("a: &ref 1\nb: *ref\n")
        with self.subTest("tag"):
            with self.assertRaises(PlaybookValidationError):
                _mini_yaml_parse("a: !tag 1\n")
        with self.subTest("multi-doc"):
            with self.assertRaises(PlaybookValidationError):
                _mini_yaml_parse("---\na: 1\n---\nb: 2\n")

    def test_shim_load_yaml_playbook(self) -> None:
        pb = load_yaml_playbook("ssrf")
        self.assertIsInstance(pb, Playbook)
        self.assertEqual(pb.name, "ssrf")
        # ssrf.yaml defines 10 payloads.
        self.assertEqual(len(pb.payloads), 10)


class TestComposerDirect(unittest.TestCase):
    def test_compose_min_budget_and_throttle_max(self) -> None:
        # Build three synthetic playbooks with known budgets and verify
        # the merge picks the strictest min / max.
        from bugwolf.playbooks.base import BudgetSpec

        pbs = [
            Playbook(
                schema=SCHEMA,
                name=f"p{i}",
                preconditions={"target_is_reachable": True, "scope_allows_active": True},
                budget=BudgetSpec(max_requests=100, max_wall_clock=300, min_interval_ms=10 + i * 10),
            )
            for i in range(3)
        ]
        merged_budget = PlaybookComposer._merge_budget(pbs)
        self.assertEqual(merged_budget.max_requests, 100)  # min of identical
        self.assertEqual(merged_budget.max_wall_clock, 300)  # min of identical
        self.assertEqual(merged_budget.min_interval_ms, 30)  # max


if __name__ == "__main__":
    unittest.main()
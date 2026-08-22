#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.graphql_gid import (
    GidCandidate, analyze_introspection, build_candidates,
    build_validation_plans, harvest_gids, sensitivity_for,
)


RELAY_INTROSPECTION = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "node",
                 "args": [{"name": "id", "type": {"kind": "NON_NULL",
                          "ofType": {"kind": "SCALAR", "name": "ID"}}}],
                 "type": {"kind": "INTERFACE", "name": "Node"}},
                {"name": "nodes",
                 "args": [{"name": "ids", "type": {"kind": "LIST", "ofType": {
                     "kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}}],
                 "type": {"kind": "LIST", "ofType": {"kind": "INTERFACE", "name": "Node"}}},
            ]},
            {"kind": "INTERFACE", "name": "Node", "fields": [
                {"name": "id", "type": {"kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            {"kind": "OBJECT", "name": "Report", "interfaces": [{"name": "Node"}],
             "fields": [{"name": "id", "type": {"kind": "NON_NULL",
                        "ofType": {"kind": "SCALAR", "name": "ID"}}},
                        {"name": "title", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"kind": "OBJECT", "name": "PolicyPageAssetGroup",
             "interfaces": [{"name": "Node"}],
             "fields": [{"name": "id", "type": {"kind": "NON_NULL",
                        "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            {"kind": "OBJECT", "name": "User", "interfaces": [],
             "fields": [{"name": "id", "type": {"kind": "NON_NULL",
                        "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            {"kind": "SCALAR", "name": "ID"},
            {"kind": "SCALAR", "name": "String"},
        ],
    }},
}

HACKERONE_GID = ("gid://hackerone/PolicyPageAssetGroupsIndex::"
                 "PolicyPageAssetGroup/3981-41287")
PLAIN_GID = "gid://app/User/abc123XYZ"


class TestIntrospectionAnalysis(unittest.TestCase):
    def test_node_and_nodes_resolvers_detected(self):
        surface = analyze_introspection(RELAY_INTROSPECTION)
        self.assertTrue(surface.has_node_resolver)
        self.assertTrue(surface.has_nodes_resolver)
        self.assertIn("Node", surface.resolver_return_types)

    def test_global_id_types_include_implementors_and_id_carriers(self):
        surface = analyze_introspection(RELAY_INTROSPECTION)
        self.assertIn("Report", surface.global_id_types)        # Node implementor
        self.assertIn("PolicyPageAssetGroup", surface.global_id_types)
        self.assertIn("User", surface.global_id_types)          # id: ID! carrier

    def test_empty_introspection_returns_empty_surface(self):
        surface = analyze_introspection({})
        self.assertFalse(surface.has_node_resolver)
        self.assertEqual(surface.global_id_types, [])


class TestHarvesting(unittest.TestCase):
    def test_harvest_extracts_redacts_and_hashes(self):
        results = harvest_gids(
            f"query {{ node(id: \"{HACKERONE_GID}\") }} {PLAIN_GID}",
            "queries.txt")
        by_class = {r.class_name: r for r in results}
        composite = by_class["PolicyPageAssetGroupsIndex::PolicyPageAssetGroup"]
        self.assertTrue(composite.composite)
        self.assertEqual(composite.type_name, "PolicyPageAssetGroup")
        self.assertEqual(composite.sensitivity, "high")  # policy in HIGH terms
        # Ids are redacted in output; only the hash references the raw value.
        self.assertNotIn("3981-41287", composite.example_redacted)
        self.assertIn("█", composite.example_redacted)
        self.assertTrue(composite.gid_hash)
        self.assertEqual(composite.source, "queries.txt")
        self.assertEqual(by_class["User"].sensitivity, "high")
        self.assertFalse(by_class["User"].composite)

    def test_harvest_deduplicates_repeat_gids(self):
        results = harvest_gids(f"{PLAIN_GID} and again {PLAIN_GID}")
        self.assertEqual(len(results), 1)

    def test_harvest_from_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "queries.txt").write_text(f"node(id: \"{PLAIN_GID}\")")
            sub = root / "js"
            sub.mkdir()
            (sub / "bundle.js").write_text(HACKERONE_GID)
            from tools.graphql_gid import harvest_artifacts
            results = harvest_artifacts([root])
            self.assertGreaterEqual(len(results), 2)


class TestCandidates(unittest.TestCase):
    def test_introspection_candidates_use_node_interface(self):
        candidates = build_candidates(
            "example.com", introspection=RELAY_INTROSPECTION)
        by_type = {c.type_name: c for c in candidates}
        self.assertIn("Report", by_type)
        self.assertEqual(by_type["Report"].interface, "node")
        self.assertTrue(any("node(id:)" in note for note in by_type["Report"].notes))

    def test_artifact_candidates_carry_redacted_examples(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "bundle.js"
            artifact.write_text(HACKERONE_GID)
            candidates = build_candidates("example.com", artifacts=[artifact])
            self.assertTrue(candidates)
            by_type = {c.type_name: c for c in candidates}
            self.assertEqual(by_type["PolicyPageAssetGroup"].interface, "artifact")
            self.assertTrue(by_type["PolicyPageAssetGroup"].composite)
            self.assertNotIn("3981", by_type["PolicyPageAssetGroup"].example_gid_redacted)

    def test_merged_candidates_dedupe_by_type_and_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "bundle.js"
            artifact.write_text(HACKERONE_GID)
            candidates = build_candidates(
                "example.com", introspection=RELAY_INTROSPECTION,
                artifacts=[artifact])
            ids = [c.candidate_id for c in candidates]
            self.assertEqual(len(ids), len(set(ids)))  # no duplicates
            self.assertTrue(all(any("own fixture gid" in note for note in c.notes)
                                for c in candidates))
            # Bounded even with many inputs.
            many = build_candidates("example.com", introspection=RELAY_INTROSPECTION,
                                    max_candidates=1)
            self.assertLessEqual(len(many), 1)


class TestValidationPlans(unittest.TestCase):
    def test_two_account_plans_use_owned_fixtures_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "bundle.js"
            artifact.write_text(HACKERONE_GID)
            candidates = build_candidates("example.com", artifacts=[artifact])
            plans = build_validation_plans(candidates, "example.com")
            self.assertTrue(plans)
            for plan in plans:
                self.assertEqual(plan.reference_type, "graphql_gid")
                self.assertEqual(plan.status, "read_only_test_fixture")
                self.assertEqual(len(plan.accounts), 2)
                joined = " ".join(plan.mutations + plan.baseline).lower()
                self.assertIn("own fixture gid", joined)
                prohibited = " ".join(plan.prohibited_actions).lower()
                self.assertIn("enumeration", prohibited)
                self.assertIn("harvested", prohibited)
                self.assertIn("node(id:)", plan.invariant.lower())

    def test_low_sensitivity_candidates_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "x.txt"
            artifact.write_text("gid://app/Widget/abc")
            candidates = build_candidates("example.com", artifacts=[artifact])
            plans = build_validation_plans(candidates, "example.com")
            self.assertEqual(plans, [])  # Widget is low sensitivity


class TestSensitivity(unittest.TestCase):
    def test_keyword_classification(self):
        self.assertEqual(sensitivity_for("Report"), "high")
        self.assertEqual(sensitivity_for("PolicyPageAssetGroup"), "high")
        self.assertEqual(sensitivity_for("Member"), "medium")
        self.assertEqual(sensitivity_for("Widget"), "low")


if __name__ == "__main__":
    unittest.main()

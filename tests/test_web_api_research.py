#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.web_api_research import WebApiResearchAdapter
from tools.candidate_lifecycle import CandidateStatus


class TestWebApiResearchAdapter(unittest.TestCase):
    def test_builds_surface_and_emits_candidates_from_openapi(self):
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "http://lab.test"}],
            "paths": {
                "/v1/orders/{id}": {
                    "get": {"operationId": "getOrder", "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ]}
                },
                "/v2/orders/{id}": {
                    "get": {"operationId": "getOrderV2", "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ]}
                },
            },
        }
        adapter = WebApiResearchAdapter("lab.test")
        model, candidates = adapter.analyze_openapi(spec)
        self.assertEqual(len(model.operations), 2)
        self.assertEqual(len(model.siblings), 1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, CandidateStatus.DISCOVERED)
        self.assertEqual(candidates[0].domain, "web_api")

    def test_behavioral_oracle_requires_material_delta(self):
        adapter = WebApiResearchAdapter("lab.test")
        observations = [
            {"endpoint": "/orders", "status": 200, "body": '{"ok":true}', "headers": {}},
            {"endpoint": "/orders", "status": 200, "body": '{"ok":true}', "headers": {}},
        ]
        self.assertEqual(adapter.analyze_observations(observations), [])
        observations[1]["body"] = '{"ok":false}'
        candidates = adapter.analyze_observations(observations)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "behavior_differential")

    def test_registers_candidates_in_local_phase_one_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = WebApiResearchAdapter("lab.test", project_root=tmp)
            candidate = adapter.analyze_observations([
                {"endpoint": "/x", "status": 200, "body": "a"},
                {"endpoint": "/x", "status": 500, "body": "stack trace"},
            ])[0]
            self.assertTrue(adapter.register([candidate]))
            self.assertFalse(adapter.register([candidate]))
            self.assertEqual(len(adapter.store.load()), 1)
            self.assertEqual(adapter.store.load()[0].domain, "web_api")


if __name__ == "__main__":
    unittest.main()

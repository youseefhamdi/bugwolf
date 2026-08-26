#!/usr/bin/env python3
"""Tests for Week-2 P0 tools: BFLA matrix, GraphQL batching analyzer, OAuth flow analyzer."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.idor_research import (  # noqa: E402
    build_bfla_matrix, openapi_role_inventory, BflaValidationPlan,
)
from tools.domains.api.graphql_batch_analyzer import (  # noqa: E402
    analyze as gql_analyze, _URL_NAMES,
)
from tools.domains.auth.oauth_flow_analyzer import (  # noqa: E402
    parse_flow, parse_js_surface, analyze as oauth_analyze,
)


class TestBflaMatrix(unittest.TestCase):
    def _endpoints(self):
        return [
            {"url": "https://acme.com/api/v1/admin/users/delete",
             "method": "DELETE", "operation": "function"},
            {"url": "https://acme.com/api/v1/roles/grant",
             "method": "POST", "operation": "function", "required_role": "owner"},
            {"url": "https://acme.com/api/v1/users/{id}",
             "method": "GET", "operation": "read"},
        ]

    def test_privileged_endpoints_become_plans(self):
        plans = build_bfla_matrix("acme", self._endpoints())
        self.assertGreaterEqual(len(plans), 2)
        for plan in plans:
            self.assertIsInstance(plan, BflaValidationPlan)
            self.assertEqual(plan.status, "offline_plan_only")

    def test_required_role_inference(self):
        plans = {p.location: p for p in build_bfla_matrix("acme", self._endpoints())}
        self.assertEqual(plans["https://acme.com/api/v1/admin/users/delete"].required_role,
                         "admin")
        self.assertEqual(plans["https://acme.com/api/v1/roles/grant"].required_role,
                         "owner")

    def test_non_privileged_endpoints_skipped(self):
        plans = build_bfla_matrix("acme", self._endpoints())
        for plan in plans:
            self.assertNotIn("users/{id}", plan.location)

    def test_mutations_require_lower_role_caller(self):
        plans = build_bfla_matrix("acme", self._endpoints(),
                                  role_sets=[["user", "admin"]])
        for plan in plans:
            self.assertIn("user", plan.declared_roles)
            self.assertIn(plan.required_role, plan.declared_roles)
            self.assertTrue(any("lower-privileged" in m or "user" in m
                                for m in plan.mutations))

    def test_deterministic(self):
        a = build_bfla_matrix("acme", self._endpoints())
        b = build_bfla_matrix("acme", self._endpoints())
        self.assertEqual([p.to_dict() for p in a],
                         [p.to_dict() for p in b])


class TestOpenApiRoleInventory(unittest.TestCase):
    SPEC = {
        "openapi": "3.0.0",
        "paths": {
            "/admin/users": {
                "get": {"operationId": "listUsers",
                        "security": [{"bearerAuth": ["admin"]}]}
            },
            "/roles": {
                "post": {"operationId": "grantRole",
                         "x-permission": "owner"}
            },
            "/public": {
                "get": {"operationId": "publicInfo",
                        "security": [{"bearerAuth": []}]}
            },
        },
    }

    def test_extracts_privileged_operations(self):
        inventory = openapi_role_inventory(self.SPEC)
        by_id = {item["operation"]: item for item in inventory}
        self.assertEqual(by_id["listUsers"]["required_role"], "admin")
        self.assertEqual(by_id["grantRole"]["required_role"], "owner")
        self.assertEqual(by_id["publicInfo"]["required_role"], "")

    def test_methods_mapped_upper(self):
        inventory = openapi_role_inventory(self.SPEC)
        methods = {item["method"] for item in inventory}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)


class TestGraphqlBatchAnalyzer(unittest.TestCase):
    INTROSPECTION = {
        "data": {"__schema": {"types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user",
                 "type": {"kind": "OBJECT", "name": "User"},
                 "args": [{"name": "id", "type": {"kind": "NON_NULL", "name": "ID"}}]},
                {"name": "fetchPage",
                 "type": {"kind": "OBJECT", "name": "Page"},
                 "args": [{"name": "url", "type": {"kind": "NON_NULL", "name": "String"}}]},
            ]},
            {"kind": "OBJECT", "name": "User",
             "fields": [{"name": "name",
                         "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
            {"kind": "OBJECT", "name": "Page",
             "fields": [{"name": "title",
                         "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        ]}}
    }

    def test_introspection_yields_all_categories(self):
        result = gql_analyze("acme", introspection=self.INTROSPECTION,
                             endpoint="/graphql")
        categories = {p.category for p in result.plans}
        self.assertIn("batching", categories)
        self.assertIn("field_duplication", categories)
        self.assertIn("fragment_depth", categories)
        self.assertIn("introspection", categories)

    def test_url_arg_detected_as_ssrf_surface(self):
        result = gql_analyze("acme", introspection=self.INTROSPECTION,
                             endpoint="/graphql")
        ssrf = [p for p in result.plans if p.category == "ssrf"]
        self.assertEqual(len(ssrf), 1)
        self.assertEqual(ssrf[0].severity_hint, "high")
        self.assertIn("fetchPage", " ".join(ssrf[0].observations))

    def test_raw_query_batching_detection(self):
        query = "query { a: user(id:1){name} b: user(id:2){name} c: user(id:3){name} }"
        result = gql_analyze("acme", query=query)
        categories = {p.category for p in result.plans}
        self.assertIn("batching", categories)

    def test_raw_query_introspection_detection(self):
        result = gql_analyze("acme", query="query { __schema { types { name } } }")
        self.assertIn("introspection", {p.category for p in result.plans})

    def test_empty_input_no_plans(self):
        result = gql_analyze("acme")
        self.assertEqual(result.plans, [])

    def test_deterministic(self):
        a = gql_analyze("acme", introspection=self.INTROSPECTION)
        b = gql_analyze("acme", introspection=self.INTROSPECTION)
        self.assertEqual([p.to_dict() for p in a.plans],
                         [p.to_dict() for p in b.plans])


class TestBoplaMatrix(unittest.TestCase):
    SPEC = {
        "openapi": "3.0.0",
        "components": {"schemas": {
            "UserUpdate": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "is_admin": {"type": "boolean"},
                    "id": {"type": "string", "readOnly": True},
                },
            },
        }},
        "paths": {
            "/users/{id}": {
                "patch": {
                    "operationId": "updateUser",
                    "requestBody": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/UserUpdate"},
                    }}},
                },
                "post": {
                    "operationId": "createUser",
                    "requestBody": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/UserUpdate"},
                    }}},
                },
            },
        },
    }

    def _matrix(self, bodies=None):
        from tools.domains.api.bopla_matrix import build_matrix
        return build_matrix("acme", self.SPEC, observed_bodies=bodies)

    def test_sensitive_declared_properties_flagged(self):
        matrix = self._matrix()
        over = [f for f in matrix.findings if f.shape == "over_post"
                and f.schema_declared]
        props = {f.property_name for f in over}
        self.assertIn("role", props)
        self.assertIn("is_admin", props)

    def test_read_only_property_flagged(self):
        matrix = self._matrix()
        ro = [f for f in matrix.findings if f.shape == "read_only_declared"]
        self.assertTrue(any(f.property_name == "id" for f in ro))

    def test_shadow_property_from_observed_body(self):
        bodies = [{"url": "/users/{id}", "method": "PATCH",
                   "body": {"name": "x", "balance": 999}}]
        matrix = self._matrix(bodies=bodies)
        shadow = [f for f in matrix.findings if not f.schema_declared
                  and f.shape == "over_post"]
        self.assertTrue(any(f.property_name == "balance" and f.risk == "high"
                            for f in shadow))

    def test_under_post_implicit_trust_surfaced(self):
        matrix = self._matrix()
        under = [f for f in matrix.findings if f.shape == "under_post"]
        self.assertTrue(any(f.property_name == "owner_id" for f in under))
        self.assertTrue(any(f.property_name == "is_verified" for f in under))

    def test_all_findings_have_validation_steps(self):
        matrix = self._matrix()
        self.assertGreater(len(matrix.findings), 0)
        for finding in matrix.findings:
            self.assertTrue(finding.validation_steps)

    def test_deterministic(self):
        a = self._matrix()
        b = self._matrix()
        self.assertEqual([f.to_dict() for f in a.findings],
                         [f.to_dict() for f in b.findings])

    def test_endpoint_bodies_shape_matching(self):
        bodies = [{"url": "/users/{id}", "method": "PATCH",
                   "body": {"name": "x"}}]
        matrix = self._matrix(bodies=bodies)
        # "name" is declared, so no shadow finding for it; "balance" absent.
        shadow = [f for f in matrix.findings if not f.schema_declared
                  and f.shape == "over_post"]
        self.assertFalse(any(f.property_name == "name" for f in shadow))


class TestOAuthFlowAnalyzer(unittest.TestCase):
    FLOW = {
        "authorize_url": ("https://acme.com/oauth/authorize"
                          "?client_id=app1&response_type=code"
                          "&redirect_uri=https://acme.com/cb"),
        "token_url": "https://acme.com/oauth/token",
        "callback_url": "https://acme.com/cb",
    }

    def test_parse_flow_extracts_params(self):
        flow = parse_flow(self.FLOW)
        self.assertEqual(flow.client_id, "app1")
        self.assertEqual(flow.response_type, "code")
        self.assertEqual(flow.callback_url, "https://acme.com/cb")

    def test_all_five_categories_generated(self):
        analysis = oauth_analyze("acme", [parse_flow(self.FLOW)])
        categories = {p.category for p in analysis.plans}
        self.assertEqual(categories,
                         {"redirect_uri", "state_csrf", "pkce",
                          "token_in_url", "coat"})

    def test_state_missing_is_high_severity(self):
        analysis = oauth_analyze("acme", [parse_flow(self.FLOW)])
        state = next(p for p in analysis.plans if p.category == "state_csrf")
        self.assertEqual(state.severity_hint, "high")
        self.assertIn("state", state.description.lower())

    def test_pkce_present_lowers_severity(self):
        flow = parse_flow(self.FLOW)
        flow.params["code_challenge"] = "abc123"
        analysis = oauth_analyze("acme", [flow])
        pkce = next(p for p in analysis.plans if p.category == "pkce")
        self.assertEqual(pkce.severity_hint, "medium")

    def test_js_surface_scanner(self):
        js = (
            "const cfg = { auth: 'https://sso.acme.com/oauth2/authorize"
            "?client_id=web1&redirect_uri=https://app.acme.com/cb',"
            " token: 'https://sso.acme.com/oauth2/token' };"
        )
        found = parse_js_surface(js)
        self.assertTrue(any("authorize" in item["path"] for item in found))
        web1 = next((item for item in found if item["client_id"] == "web1"), None)
        self.assertIsNotNone(web1)
        self.assertEqual(web1["params"].get("redirect_uri"),
                         "https://app.acme.com/cb")

    def test_deterministic(self):
        a = oauth_analyze("acme", [parse_flow(self.FLOW)])
        b = oauth_analyze("acme", [parse_flow(self.FLOW)])
        self.assertEqual([p.to_dict() for p in a.plans],
                         [p.to_dict() for p in b.plans])


if __name__ == "__main__":
    unittest.main()

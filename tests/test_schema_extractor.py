"""Tests for auto-extracting OpenAPI/GraphQL schemas from recon output."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.schema_extractor import (
    SchemaDiscovery, SchemaCandidate, discover, load_cached_schemas,
    build_surface, fetch_schemas,
)
from tools.execution_controller import ExecutionDenied


def _make_recon(tmp: str) -> Path:
    recon = Path(tmp) / "recon" / "example.com"
    recon.mkdir(parents=True)
    (recon / "urls.txt").write_text(
        "https://api.example.com/v1/users\n"
        "https://api.example.com/openapi.json\n"
        "https://api.example.com/graphql\n"
        "https://api.example.com/v2/users\n")
    (recon / "live-hosts.txt").write_text(
        "https://api.example.com [200] Example\n")
    jsdir = recon / "js"
    jsdir.mkdir()
    (jsdir / "app.js").write_text(
        "const s = '/api/v1/openapi.json';\n"
        "fetch(s).then(r => r.json());\n")
    return recon


OPENAPI = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/v1/users/{id}": {
            "get": {"operationId": "getUser",
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "integer"}}]},
        },
        "/v2/users/{id}": {
            "get": {"operationId": "getUserV2",
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "integer"}}]},
        },
    },
}

INTROSPECTION = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "me", "args": []},
            ]},
        ],
    }},
}


class TestDiscovery(unittest.TestCase):
    def test_discovers_openapi_and_graphql(self):
        with tempfile.TemporaryDirectory() as tmp:
            recon = _make_recon(tmp)
            disc = discover(recon, "example.com")
            openapi_urls = {c.url for c in disc.openapi}
            self.assertIn("https://api.example.com/openapi.json", openapi_urls)
            self.assertIn("https://api.example.com/api/v1/openapi.json",
                          openapi_urls)  # from JS
            self.assertIn("https://api.example.com/graphql",
                          {c.url for c in disc.graphql})
            # Confidence: explicit schema file is high, JS reference medium.
            by_url = {c.url: c for c in disc.openapi}
            self.assertEqual(by_url["https://api.example.com/openapi.json"].confidence,
                             "high")
            self.assertEqual(
                by_url["https://api.example.com/api/v1/openapi.json"].confidence,
                "medium")

    def test_dedupes_and_keeps_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            recon = _make_recon(tmp)
            # Add a duplicate via live-hosts/swagger to prove dedup.
            (recon / "swagger.txt").write_text(
                "https://api.example.com/openapi.json\n")
            disc = discover(recon, "example.com")
            count = sum(1 for c in disc.openapi
                        if c.url == "https://api.example.com/openapi.json")
            self.assertEqual(count, 1)

    def test_load_cached_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            schemas = Path(tmp) / "schemas"
            schemas.mkdir()
            (schemas / "openapi-a.json").write_text(json.dumps(OPENAPI))
            (schemas / "graphql-a.json").write_text(json.dumps(INTROSPECTION))
            (schemas / "junk.json").write_text('{"foo": 1}')
            cached = load_cached_schemas(schemas)
            kinds = {c["kind"] for c in cached}
            self.assertEqual(kinds, {"openapi", "graphql"})


class TestBuildSurface(unittest.TestCase):
    def test_builds_from_cached_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            recon = _make_recon(tmp)
            schemas = recon / "schemas"
            schemas.mkdir()
            (schemas / "openapi-a.json").write_text(json.dumps(OPENAPI))
            (schemas / "graphql-a.json").write_text(json.dumps(INTROSPECTION))

            model = build_surface("example.com", recon)
            ops = {o.operation_id: o for o in model.operations}
            self.assertIn("getUser", ops)          # openapi v1
            self.assertIn("getUserV2", ops)        # openapi v2
            self.assertIn("Query.me", ops)         # graphql
            self.assertTrue(any(o.path == "/v1/users" for o in model.operations
                                if o.source == "urls"))
            # v1/v2 version siblings were auto-paired.
            self.assertTrue(any({"getUser", "getUserV2"} <= set(g.operation_ids)
                                for g in model.siblings))

    def test_build_requires_recon_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            with self.assertRaises(ValueError):
                build_surface("example.com", empty)


class TestFetchGating(unittest.TestCase):
    def test_fetch_requires_scope_and_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            recon = _make_recon(tmp)
            with self.assertRaises(ExecutionDenied):
                fetch_schemas("example.com", recon, scope_file="",
                              confirm_active=True)
            with self.assertRaises(ExecutionDenied):
                fetch_schemas("example.com", recon, scope_file="scope.json",
                              confirm_active=False)


if __name__ == "__main__":
    unittest.main()

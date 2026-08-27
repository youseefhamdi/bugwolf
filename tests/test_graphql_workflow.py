#!/usr/bin/env python3
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tools.graphql_workflow import GraphQLCase, GraphQLWorkflow


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        query = payload.get("query", "")
        body = {"data": {"user": {"id": "1", "email": "alice@lab.local"}}}
        if "__schema" in query:
            body = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestGraphQLWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_graphql_cases_are_recorded_and_flagged(self):
        cases = [
            GraphQLCase("node lookup", "query { node(id: \"1\") { id email } }"),
            GraphQLCase("introspection", "query { __schema { queryType { name } } }"),
        ]
        report = GraphQLWorkflow(
            f"http://127.0.0.1:{self.server.server_port}").run(cases)
        self.assertEqual(report["schema"], "bugwolf/graphql-workflow/v1")
        self.assertEqual(len(report["observations"]), 2)
        self.assertTrue(report["potential_authorization_variants"])
        self.assertTrue(report["introspection_enabled"])


if __name__ == "__main__":
    unittest.main()

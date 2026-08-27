#!/usr/bin/env python3
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from tools.multitenant_workflow import MultiTenantWorkflow, WorkflowStep


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path.startswith("/api/users/"):
            user_id = self.path.rsplit("/", 1)[-1]
            body = {"id": user_id, "username": "alice" if user_id == "1" else "bob"}
            self._send(200, body)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/login":
            self._send(200, {"token": f"token-{body.get('username', 'unknown')}"})
        else:
            self._send(404, {"error": "not found"})

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestMultiTenantWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_two_accounts_are_replayed_and_shared_data_is_flagged(self):
        workflow = MultiTenantWorkflow(f"http://127.0.0.1:{self.server.server_port}")
        result = workflow.run(
            [WorkflowStep("read tenant data", "GET", "/tenant/data", expected_status=200)],
            {"alice": {}, "bob": {}},
        )
        self.assertTrue(result["comparison"]["isolation_violation"])
        self.assertEqual(len(result["accounts"]), 2)

    def test_login_token_is_propagated_to_later_steps(self):
        workflow = MultiTenantWorkflow(f"http://127.0.0.1:{self.server.server_port}")
        result = workflow.run(
            [
                WorkflowStep("login", "POST", "/login", {"username": "alice"}, login=True),
                WorkflowStep("read user", "GET", "/api/users/1", expected_status=200),
            ],
            {"alice": {}, "bob": {}},
        )
        self.assertTrue(result["accounts"][0]["observations"][0]["session_established"])
        self.assertEqual(result["accounts"][0]["observations"][1]["status"], 200)

    def test_requires_two_accounts(self):
        workflow = MultiTenantWorkflow("http://127.0.0.1:1")
        with self.assertRaises(ValueError):
            workflow.run([], {"alice": {}})


if __name__ == "__main__":
    unittest.main()

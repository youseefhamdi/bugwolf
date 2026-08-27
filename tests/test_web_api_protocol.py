#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.web_api_protocol import ProtocolTrace, WebApiProtocolExporter


class TestWebApiProtocolExporter(unittest.TestCase):
    def test_normalizes_http_observations_and_preserves_delta(self):
        trace = ProtocolTrace.from_observations("lab.test", [
            {"url": "/api/v1", "method": "GET", "status": 200,
             "request_headers": {"Accept": "application/json"},
             "response_headers": {"Content-Type": "application/json"},
             "body": "{\"ok\":true}", "elapsed_ms": 10},
            {"url": "/api/v1", "method": "GET", "status": 500,
             "request_headers": {"Accept": "application/json"},
             "response_headers": {"Content-Type": "text/plain"},
             "body": "error", "elapsed_ms": 20},
        ])
        self.assertEqual(trace.protocol, "http")
        self.assertEqual(trace.entries[1]["response"]["status"], 500)
        self.assertTrue(trace.delta["status_changed"])

    def test_exports_har_and_json_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = ProtocolTrace.from_observations("lab.test", [{
                "url": "https://lab.test/api", "method": "POST",
                "status": 201, "body": "created",
            }])
            paths = WebApiProtocolExporter().export(trace, Path(tmp))
            har = json.loads(paths["har"].read_text())
            self.assertEqual(har["log"]["version"], "1.2")
            self.assertEqual(len(har["log"]["entries"]), 1)
            self.assertEqual(har["log"]["entries"][0]["response"]["status"], 201)
            self.assertTrue(paths["json"].is_file())


if __name__ == "__main__":
    unittest.main()

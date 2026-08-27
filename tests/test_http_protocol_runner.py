#!/usr/bin/env python3
import unittest

from tools.http_protocol_runner import HTTPProtocolRunner, parse_curl_headers


class TestHTTPProtocolRunner(unittest.TestCase):
    def test_plans_protocol_probes_in_order(self):
        runner = HTTPProtocolRunner("lab")
        plan = runner.plan_protocols("https://lab.test/api")
        self.assertEqual(plan[0]["protocol"], "h1")
        self.assertIn("h2", [p["protocol"] for p in plan])

    def test_parses_curl_header_block(self):
        headers = parse_curl_headers(
            "HTTP/2 200\ncontent-type: application/json\nx-test: 1\n\nbody")
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["x-test"], "1")

    def test_missing_curl_reported_gracefully(self):
        runner = HTTPProtocolRunner("lab")
        result = runner.run_probe("https://lab.test/api", "h3",
                                  curl_path="definitely-not-curl-bugwolf")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
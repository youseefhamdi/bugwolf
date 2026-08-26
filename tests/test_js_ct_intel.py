#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.js_ct_intel import (
    analyze_javascript,
    collect_certificate_records,
    run_pipeline,
)


class TestJsCtIntel(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "authorized": True,
            "in_scope": ["example.com"],
            "in_scope_wildcards": ["*.example.com"],
        }

    def test_ct_name_dates_are_normalized_and_all_names_kept_uncensored(self):
        """UNCENSORED: out-of-scope names are kept; dates are still normalized."""
        calls = []

        def fetcher(url):
            calls.append(url)
            if "crt.name" in url:
                return [
                    {"name": "api.example.com", "first_seen": "2024-01-02", "last_seen": "2025-03-04"},
                    {"name": "outside.example.net", "first_seen": "2024-01-01"},
                ]
            return [{"name_value": "api.example.com\nstatic.example.com", "not_before": "2023-01-01"}]

        records = collect_certificate_records("example.com", self.scope, fetcher=fetcher)
        self.assertEqual([record.name for record in records],
                         ["api.example.com", "outside.example.net", "static.example.com"])
        self.assertEqual(records[0].first_seen, "2024-01-02")
        self.assertIn("crt.name", calls[0])
        self.assertIn("dates=1", calls[0])

    def test_local_analysis_redacts_values_and_generates_workflow_hypotheses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            js_dir = root / "js"
            output = root / "out"
            js_dir.mkdir()
            (js_dir / "app.js").write_text(
                "const token='ghp_abcdefghijklmnopqrstuvwxyz123456';\n"
                "fetch('/api/v1/checkout?redirect=next');\n"
                "//# sourceMappingURL=app.js.map\n",
                encoding="utf-8",
            )
            summary = analyze_javascript(
                "example.com",
                ["https://example.com/checkout", "https://outside.example.net/admin"],
                js_dir,
                output,
                run_tools=False,
            )
            self.assertEqual(summary["js_files"], 1)
            self.assertGreaterEqual(summary["endpoints"], 1)
            self.assertGreaterEqual(summary["secret_files"], 1)
            self.assertGreaterEqual(summary["workflow_hypotheses"], 1)
            secret_text = (output / "js-secrets.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", secret_text)
            self.assertIn("checkout", (output / "workflow-hypotheses.jsonl").read_text(encoding="utf-8"))
            self.assertTrue((output / "js-grep.jsonl").is_file())

    def test_js_only_pipeline_does_not_fetch_ct_and_keeps_all_urls_uncensored(self):
        """UNCENSORED: js-only skips CT; all supplied URLs feed the crawler."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope_file = root / "scope.json"
            scope_file.write_text(json.dumps(self.scope), encoding="utf-8")
            urls = root / "urls.txt"
            urls.write_text("https://example.com/login\nhttps://outside.example.net/no\n", encoding="utf-8")
            js_dir = root / "js"
            js_dir.mkdir()
            (js_dir / "main.js").write_text("fetch('/login');", encoding="utf-8")
            summary = run_pipeline(
                "example.com",
                str(scope_file),
                root / "intel",
                urls_file=urls,
                js_dir=js_dir,
                js_only=True,
            )
            self.assertEqual(summary["ct_records"], 0)
            self.assertEqual(summary["javascript"]["js_files"], 1)
            crawler_input = (root / "intel" / "crawler-input.txt").read_text(encoding="utf-8")
            self.assertIn("example.com/login", crawler_input)
            self.assertIn("outside.example.net", crawler_input)  # uncensored: kept


if __name__ == "__main__":
    unittest.main()

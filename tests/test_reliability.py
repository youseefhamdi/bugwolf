#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.execution_semantics import (  # noqa: E402
    target_in_scope, validate_http_url, validate_public_https_url,
)
from tools.reliability import (  # noqa: E402
    CorruptRecordError, ResourceLimitError, append_jsonl, atomic_write_json,
    operation_record, read_jsonl, run_bounded_subprocess,
)


class TestUncensoredInputSemantics(unittest.TestCase):
    def test_scope_remains_unrestricted(self):
        self.assertTrue(target_in_scope("https://outside.test", {}))

    def test_url_shape_rejects_non_http_schemes_without_scope_gate(self):
        self.assertEqual(validate_http_url("https://example.test/path"),
                         "https://example.test/path")
        with self.assertRaises(ValueError):
            validate_http_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            validate_http_url("javascript:alert(1)")

    def test_https_shape_rejects_http(self):
        with self.assertRaises(ValueError):
            validate_public_https_url("http://example.test")


class TestPersistence(unittest.TestCase):
    def test_atomic_json_write_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "state.json"
            atomic_write_json(path, {"state": "completed"})
            self.assertEqual(json.loads(path.read_text())["state"], "completed")
            self.assertFalse(list(path.parent.glob("*.tmp")))

    def test_jsonl_reader_recovers_bad_lines_and_reports_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"ok": true}\nnot-json\n{"ok": false}\n')
            records, errors = read_jsonl(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(len(errors), 1)
            with self.assertRaises(CorruptRecordError):
                read_jsonl(path, strict=True)

    def test_append_jsonl_enforces_artifact_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            with self.assertRaises(ResourceLimitError):
                append_jsonl(path, {"data": "x" * 100}, max_bytes=10)

    def test_operation_records_have_uuid_and_lifecycle_state(self):
        record = operation_record(action="live_probe", target="lab.test",
                                  status="planned", tool="live_executor")
        self.assertRegex(record["operation_id"],
                         r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        self.assertEqual(record["state"], "planned")


class TestSubprocessBounds(unittest.TestCase):
    def test_timeout_terminates_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(subprocess.TimeoutExpired):
                run_bounded_subprocess(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    cwd=tmp, timeout=0.05)

    def test_output_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ResourceLimitError):
                run_bounded_subprocess(
                    [sys.executable, "-c", "print('x' * 1000)"],
                    cwd=tmp, timeout=2, max_output_bytes=100)


if __name__ == "__main__":
    unittest.main()

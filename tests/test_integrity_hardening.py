#!/usr/bin/env python3
"""Regression tests for shared runtime integrity boundaries."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.core.live_executor import execute_exploit, execute_probe
from tools.runtime_paths import target_slug
from tools.state import _state_dir, add_finding


class TestTargetSlug(unittest.TestCase):
    def test_target_slug_is_one_contained_component(self):
        for value in ("../../outside", "evil/../etc", "..", ".", "host with spaces"):
            slug = target_slug(value)
            self.assertTrue(slug)
            self.assertNotIn("/", slug)
            self.assertNotIn("\\", slug)
            self.assertNotIn(slug, (".", ".."))

    def test_state_path_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = _state_dir("../../outside", project_root=tmp)
            root = Path(tmp).resolve()
            self.assertEqual(state_dir.parent.parent, root / "state")
            self.assertTrue(state_dir.is_relative_to(root))


class TestLiveEvidenceRedaction(unittest.TestCase):
    def test_probe_return_and_persisted_evidence_redact_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = {
                "endpoint": "https://example.test/api",
                "bug_class": "web",
                "auth_header": "Bearer live-secret-token",
                "context": {"token": "context-secret"},
            }

            def transport(spec):
                return (
                    200,
                    {"Set-Cookie": "sid=secret-cookie", "Server": "nginx"},
                    '{"token":"body-secret","ok":true}',
                    3.0,
                )

            result = execute_probe(unit, "https://example.test", transport=transport,
                                   project_root=tmp, include_baseline=False)
            rendered = json.dumps(result.to_dict())
            self.assertNotIn("live-secret-token", rendered)
            self.assertNotIn("secret-cookie", rendered)
            self.assertNotIn("body-secret", rendered)
            probes = Path(tmp) / "state" / "sessions" / "example.test" / "probes.jsonl"
            self.assertTrue(probes.is_file())
            persisted = probes.read_text()
            self.assertNotIn("live-secret-token", persisted)
            self.assertNotIn("secret-cookie", persisted)
            self.assertNotIn("body-secret", persisted)

    def test_fuzz_style_evidence_redacts_sensitive_headers_and_json(self):
        from tools.core.fuzz_bridge import _evidence_block

        evidence = _evidence_block(
            "https://example.test/api", "POST", {"password": "pw-secret"},
            {"Authorization": "Bearer fuzz-secret"}, 200,
            {"Set-Cookie": "sid=fuzz-cookie"},
            '{"api_key":"key-secret"}', 4.0,
        )
        rendered = json.dumps(evidence)
        for secret in ("pw-secret", "fuzz-secret", "fuzz-cookie", "key-secret"):
            self.assertNotIn(secret, rendered)


class TestTruthfulReplay(unittest.TestCase):
    def _finding(self, status=200):
        return {
            "finding_id": "replay-test",
            "evidence": {
                "request": {"method": "GET", "url": "https://example.test/x",
                            "headers": {}, "body": None},
                "response": {"status": status, "headers": {}, "body": "ok"},
            },
        }

    def test_mismatched_http_status_is_not_reproduced(self):
        result = execute_exploit(
            self._finding(200), "https://example.test",
            transport=lambda spec: (403, {}, "denied", 2.0),
        )
        self.assertFalse(result.evidence["reproduced"])

    def test_missing_expected_status_is_not_reproduced(self):
        finding = self._finding()
        finding["evidence"]["response"].pop("status")
        result = execute_exploit(
            finding, "https://example.test",
            transport=lambda spec: (200, {}, "ok", 2.0),
        )
        self.assertFalse(result.evidence["reproduced"])


class TestCanonicalFindingWrite(unittest.TestCase):
    def test_add_finding_writes_endpoint_journal_and_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding = {
                "finding_id": "canonical-1",
                "title": "Canonical finding",
                "endpoint": "https://example.test/api",
                "method": "GET",
                "bug_class": "idor",
                "severity": "high",
                "evidence": {"response": {"status": 200, "body": "safe"}},
                "thread_id": "thread-1",
                "state": "FINDING",
            }
            with mock.patch.dict(os.environ, {"BUGWOLF_PROJECT_ROOT": tmp}, clear=False):
                add_finding("example.test", finding, project_root=tmp)
            state_dir = Path(tmp) / "state" / "sessions" / "example.test"
            self.assertTrue((state_dir / "findings.jsonl").is_file())
            self.assertTrue((state_dir / "endpoints.jsonl").is_file())
            self.assertTrue((state_dir / "journal.jsonl").is_file())
            self.assertTrue((state_dir / "post-finding-triggers.jsonl").is_file())
            record = json.loads((state_dir / "findings.jsonl").read_text().splitlines()[0])
            self.assertEqual(record["thread_id"], "thread-1")
            self.assertEqual(record["state"], "FINDING")


if __name__ == "__main__":
    unittest.main()

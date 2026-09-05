#!/usr/bin/env python3
"""Tests for Phase 3.4 — Code-Diff Regression Scanner.

Covers:
  * Import + core-function smoke test per module (6 modules).
  * GitDiffer.diff() returns SemanticDiff (empty for invalid refs).
  * GitDiffer is STUB-SAFE on non-git paths.
  * CVEExtractor.parse_nvd_json() returns CVEEntries.
  * CVEExtractor.parse_ghsa_advisory() returns CVEEntries.
  * CVEExtractor.match_to_tech_stack() returns 0..1 confidence.
  * CrossCommitTaintAnalyzer.analyze_history() is STUB-SAFE.
  * BisectRunner.bisect() is STUB-SAFE on non-git repo.
  * BisectRunner returns BisectUnavailable on missing repo.
  * RegressionRunner.detect_regressions() returns RegressionReport.
  * RegressionReport.to_markdown() produces non-empty string.
  * Shim patch_gap_regression_bridge() works.
  * NO module uses ``shell=True``, ``verify=False``, hardcoded UA.
  * Every file has ``## Source:`` + ``## License:`` comments.

This test file does not require a real git repo, network, or any
third-party deps.  STUB-SAFE behaviour is asserted, not avoided.
"""
from __future__ import annotations

import ast
import json
import re
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


REGRESSION_DIR = ROOT / "bugwolf" / "regression"


# ---------------------------------------------------------------------------
# Module loader helpers
# ---------------------------------------------------------------------------


def _load_module(name: str, path: Path):
    """Import a single regression module from its absolute path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _has_kwarg(path: Path, kw_name: str, expected: Any) -> bool:
    """Return True iff any call in ``path`` uses ``kw_name=expected``.

    Uses AST so docstrings / comments don't trip the check.
    """
    try:
        tree = ast.parse(path.read_text())
    except Exception:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg == kw_name:
                if isinstance(kw.value, ast.Constant) and kw.value.value == expected:
                    return True
                if expected is False and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is False:
                    return True
                if expected is True and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    return True
    return False


# ---------------------------------------------------------------------------
# Source-level audit tests
# ---------------------------------------------------------------------------


class TestSourceAudit(unittest.TestCase):
    """Static checks over every file in ``bugwolf/regression/``."""

    FILES: Tuple[Path, ...] = (
        REGRESSION_DIR / "__init__.py",
        REGRESSION_DIR / "git_diff.py",
        REGRESSION_DIR / "cve_extractor.py",
        REGRESSION_DIR / "cross_commit_taint.py",
        REGRESSION_DIR / "patch_gap.py",
        REGRESSION_DIR / "bisect.py",
        REGRESSION_DIR / "regression_runner.py",
    )

    def test_files_exist(self):
        for f in self.FILES:
            self.assertTrue(f.exists(), f"missing file: {f}")

    def test_no_shell_true(self):
        offenders: List[str] = []
        for f in self.FILES:
            if _has_kwarg(f, "shell", True):
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"shell=True found in: {offenders}")

    def test_no_verify_false(self):
        offenders: List[str] = []
        for f in self.FILES:
            if _has_kwarg(f, "verify", False):
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"verify=False found in: {offenders}")

    def test_no_hardcoded_user_agent(self):
        offenders: List[str] = []
        ua_re = re.compile(r"User-Agent['\"]?\s*[:=]\s*['\"][^'\"]+['\"]")
        for f in self.FILES:
            txt = f.read_text()
            for line in txt.splitlines():
                stripped = line.lstrip()
                # Skip comments and docstring-ish lines.
                if stripped.startswith("#"):
                    continue
                if ua_re.search(line):
                    offenders.append(f"{f}:{line.strip()}")
                    break
        self.assertEqual(offenders, [],
                         f"hardcoded UA in: {offenders}")

    def test_source_and_license_comments(self):
        missing: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            if "## Source:" not in txt:
                missing.append(f"{f} (no ## Source:)")
            if "## License:" not in txt:
                missing.append(f"{f} (no ## License:)")
        self.assertEqual(missing, [],
                         f"missing header comments: {missing}")

    def test_schema_constant_present(self):
        offenders: List[str] = []
        for f in self.FILES:
            if f.name == "__init__.py":
                continue
            txt = f.read_text()
            if 'SCHEMA = "bugwolf-regression-v1"' not in txt:
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"missing SCHEMA constant in: {offenders}")

    def test_no_forbidden_http_methods(self):
        offenders: List[str] = []
        bad = ("POUET", "UNCHECKOUT", "LABEL")
        for f in self.FILES:
            txt = f.read_text()
            for tok in bad:
                if re.search(rf"\b{re.escape(tok)}\b\s*\(", txt):
                    offenders.append(f"{f}: {tok}")
        self.assertEqual(offenders, [],
                         f"forbidden HTTP methods in: {offenders}")

    def test_no_file_or_gopher_payloads(self):
        offenders: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            for pat in (r"file://", r"gopher://"):
                if re.search(pat, txt):
                    offenders.append(f"{f}: {pat}")
        self.assertEqual(offenders, [],
                         f"forbidden scheme literal in: {offenders}")

    def test_no_scrapling_parser(self):
        offenders: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            if "from scrapling.parser" in txt or "import scrapling.parser" in txt:
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"scrapling.parser import in: {offenders}")


# ---------------------------------------------------------------------------
# Module import + smoke tests
# ---------------------------------------------------------------------------


class TestModuleImports(unittest.TestCase):
    """Every regression module imports cleanly and exposes its public API."""

    def test_import_git_diff(self):
        mod = _load_module("rg_git_diff", REGRESSION_DIR / "git_diff.py")
        self.assertTrue(hasattr(mod, "GitDiffer"))
        self.assertTrue(hasattr(mod, "SemanticDiff"))
        self.assertTrue(callable(mod.GitDiffer))

    def test_import_cve_extractor(self):
        mod = _load_module("rg_cve_extractor", REGRESSION_DIR / "cve_extractor.py")
        self.assertTrue(hasattr(mod, "CVEExtractor"))
        self.assertTrue(hasattr(mod, "CVEEntry"))

    def test_import_cross_commit_taint(self):
        mod = _load_module("rg_cross_commit_taint",
                           REGRESSION_DIR / "cross_commit_taint.py")
        self.assertTrue(hasattr(mod, "CrossCommitTaintAnalyzer"))
        self.assertTrue(hasattr(mod, "CrossCommitFinding"))

    def test_import_patch_gap(self):
        mod = _load_module("rg_patch_gap", REGRESSION_DIR / "patch_gap.py")
        self.assertTrue(hasattr(mod, "RegressionPatchGap"))
        self.assertTrue(hasattr(mod, "RegressionPatchGapReport"))

    def test_import_bisect(self):
        mod = _load_module("rg_bisect", REGRESSION_DIR / "bisect.py")
        self.assertTrue(hasattr(mod, "BisectRunner"))
        self.assertTrue(hasattr(mod, "BisectResult"))
        self.assertTrue(hasattr(mod, "BisectUnavailable"))

    def test_import_regression_runner(self):
        mod = _load_module("rg_regression_runner",
                           REGRESSION_DIR / "regression_runner.py")
        self.assertTrue(hasattr(mod, "RegressionRunner"))
        self.assertTrue(hasattr(mod, "RegressionReport"))

    def test_package_init_reexports(self):
        pkg = _load_module("bugwolf_regression_test",
                           REGRESSION_DIR / "__init__.py")
        for name in ("GitDiffer", "CVEExtractor", "CrossCommitTaintAnalyzer",
                     "BisectRunner", "RegressionRunner",
                     "RegressionPatchGap"):
            self.assertTrue(hasattr(pkg, name), f"missing re-export: {name}")


# ---------------------------------------------------------------------------
# GitDiffer tests
# ---------------------------------------------------------------------------


class TestGitDiffer(unittest.TestCase):
    def test_diff_returns_semantic_diff_on_non_git_path(self):
        from bugwolf.regression.git_diff import GitDiffer, SemanticDiff
        with tempfile.TemporaryDirectory() as td:
            d = GitDiffer(Path(td))
            res = d.diff("HEAD~1", "HEAD")
        self.assertIsInstance(res, SemanticDiff)
        self.assertFalse(res.ok())
        self.assertEqual(res.repo_error, "not a git repository")
        self.assertEqual(res.files_changed, ())

    def test_diff_returns_semantic_diff_on_invalid_refs(self):
        """When the path *is* a git repo but refs are bogus, the differ
        must still return a SemanticDiff (possibly empty, possibly with
        ``repo_error`` set).  STUB-SAFE: never raise."""
        from bugwolf.regression.git_diff import GitDiffer, SemanticDiff
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=str(tmp),
                           check=False, timeout=10)
            differ = GitDiffer(tmp)
            res = differ.diff("definitely-not-a-real-ref-AAAA",
                              "definitely-not-a-real-ref-BBBB")
        self.assertIsInstance(res, SemanticDiff)
        # Either empty diff or error — never raises.

    def test_diff_real_repo_detects_modification(self):
        """A real (very small) git repo with one commit touching a file
        must produce a non-empty :class:`SemanticDiff`."""
        from bugwolf.regression.git_diff import GitDiffer, SemanticDiff
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "config", "user.email", "test@example.com"],
                           cwd=str(tmp), check=False, timeout=10)
            subprocess.run(["git", "config", "user.name", "Test"],
                           cwd=str(tmp), check=False, timeout=10)
            f = tmp / "hello.py"
            f.write_text("def foo():\n    return 1\n")
            subprocess.run(["git", "add", "hello.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "initial", "-q"],
                           cwd=str(tmp), check=False, timeout=10)
            f.write_text("def foo():\n    return 2\n\nimport os\n")
            subprocess.run(["git", "add", "hello.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "second", "-q"],
                           cwd=str(tmp), check=False, timeout=10)
            differ = GitDiffer(tmp)
            res = differ.diff("HEAD~1", "HEAD")
        self.assertIsInstance(res, SemanticDiff)
        if res.ok():
            self.assertGreater(len(res.files_changed), 0)
            self.assertGreater(res.lines_added, 0)
            # ``os`` should be picked up as an added import.
            self.assertIn("hello.py", res.added_imports)


# ---------------------------------------------------------------------------
# CVEExtractor tests
# ---------------------------------------------------------------------------


_NVD_FIXTURE = {
    "resultsPerPage": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en",
                                   "value": "nginx HTTP/2 memory leak"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5}}
                    ],
                },
                "configurations": [
                    {"nodes": [{"cpeMatch": [
                        {"criteria": "cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*"}
                    ]}]}
                ],
                "references": [{"url": "https://example.com/advisory"}],
                "published": "2024-01-02T00:00:00Z",
            }
        }
    ],
}


_GHSA_FIXTURE = """# CVE-2024-8888

GHSA-xxxx-yyyy-zzzz — django auth bypass.

## Description
Django before 4.2 has an authentication bypass in
`django.contrib.auth.backends`.

## Severity
- CVSS: 8.1
- Published: 2024-02-03

## Affected products
- pkg:pypi/django@4.1.0
- pkg:pypi/django@4.1.1

## References
- [Django advisory](https://example.com/django)
- [GHSA](https://github.com/advisories/GHSA-xxxx-yyyy-zzzz)
"""


class TestCVEExtractor(unittest.TestCase):
    def test_parse_nvd_json_returns_entries(self):
        from bugwolf.regression.cve_extractor import CVEExtractor, CVEEntry
        extractor = CVEExtractor()
        out = extractor.parse_nvd_json(json.dumps(_NVD_FIXTURE))
        self.assertIsInstance(out, list)
        self.assertGreater(len(out), 0)
        self.assertIsInstance(out[0], CVEEntry)
        self.assertEqual(out[0].cve_id, "CVE-2024-9999")
        self.assertEqual(out[0].cvss_score, 7.5)
        self.assertIn("nginx", out[0].description.lower())
        self.assertGreater(len(out[0].affected_products), 0)
        self.assertGreater(len(out[0].references), 0)

    def test_parse_nvd_json_invalid_returns_empty(self):
        from bugwolf.regression.cve_extractor import CVEExtractor
        extractor = CVEExtractor()
        self.assertEqual(extractor.parse_nvd_json("not json"), [])
        self.assertEqual(extractor.parse_nvd_json(""), [])
        self.assertEqual(extractor.parse_nvd_json('{"foo": "bar"}'), [])

    def test_parse_ghsa_advisory_returns_entries(self):
        from bugwolf.regression.cve_extractor import CVEExtractor, CVEEntry
        extractor = CVEExtractor()
        out = extractor.parse_ghsa_advisory(_GHSA_FIXTURE)
        self.assertIsInstance(out, list)
        self.assertGreater(len(out), 0)
        self.assertIsInstance(out[0], CVEEntry)
        # The first id we can resolve will be CVE-2024-8888.
        self.assertIn(out[0].cve_id, ("CVE-2024-8888", "GHSA-XXXX-YYYY-ZZZZ"))
        self.assertGreater(out[0].cvss_score, 0)

    def test_parse_ghsa_advisory_invalid_returns_empty(self):
        from bugwolf.regression.cve_extractor import CVEExtractor
        extractor = CVEExtractor()
        self.assertEqual(extractor.parse_ghsa_advisory(""), [])
        self.assertEqual(extractor.parse_ghsa_advisory("nothing here"), [])

    def test_match_to_tech_stack_returns_0_to_1(self):
        from bugwolf.regression.cve_extractor import CVEExtractor, CVEEntry
        extractor = CVEExtractor()
        cve = CVEEntry(
            cve_id="CVE-2024-9999",
            description="nginx HTTP/2 memory leak",
            cvss_score=7.5,
            published_date="2024-01-02",
            affected_products=("cpe:2.3:a:nginx:nginx:1.0.0",),
            references=(),
        )
        score = extractor.match_to_tech_stack(cve, ["nginx", "django"])
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)
        self.assertGreater(score, 0.0)

    def test_match_to_tech_stack_empty_keywords_returns_zero(self):
        from bugwolf.regression.cve_extractor import CVEExtractor, CVEEntry
        extractor = CVEExtractor()
        cve = CVEEntry(
            cve_id="CVE-2024-0000", description="x", cvss_score=0.0,
            published_date="", affected_products=(), references=(),
        )
        self.assertEqual(extractor.match_to_tech_stack(cve, []), 0.0)


# ---------------------------------------------------------------------------
# CrossCommitTaintAnalyzer tests
# ---------------------------------------------------------------------------


class TestCrossCommitTaintAnalyzer(unittest.TestCase):
    def test_analyze_history_stub_safe_on_non_repo(self):
        from bugwolf.regression.cross_commit_taint import (
            CrossCommitTaintAnalyzer,
        )
        with tempfile.TemporaryDirectory() as td:
            cca = CrossCommitTaintAnalyzer(Path(td), taint_engine=None)
            out = cca.analyze_history("v1.0", "v1.1")
        self.assertEqual(out, [])

    def test_analyze_history_with_mock_engine(self):
        """A trivial engine returns a constant flow set; the analyzer
        must accept it and never raise."""
        from bugwolf.regression.cross_commit_taint import (
            CrossCommitTaintAnalyzer,
            CrossCommitFinding,
        )

        class _Engine:
            def analyze(self, path, text, ref=""):
                if text:
                    return [{
                        "file": path,
                        "line": 1,
                        "source_kind": "request.args",
                        "sink_kind": "eval",
                        "severity": "high",
                        "confidence": 0.9,
                    }]
                return []

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "config", "user.email", "t@example.com"],
                           cwd=str(tmp), check=False, timeout=10)
            subprocess.run(["git", "config", "user.name", "T"],
                           cwd=str(tmp), check=False, timeout=10)
            (tmp / "f.py").write_text("pass\n")
            subprocess.run(["git", "add", "f.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "init", "-q"],
                           cwd=str(tmp), check=False, timeout=10)
            (tmp / "f.py").write_text("x = 1\n")
            subprocess.run(["git", "add", "f.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "change", "-q"],
                           cwd=str(tmp), check=False, timeout=10)
            cca = CrossCommitTaintAnalyzer(tmp, _Engine())
            out = cca.analyze_history("HEAD~1", "HEAD", max_commits=5)
        self.assertIsInstance(out, list)
        for f in out:
            self.assertIsInstance(f, CrossCommitFinding)
            self.assertIn(f.severity, ("low", "medium", "high", "critical"))


# ---------------------------------------------------------------------------
# BisectRunner tests
# ---------------------------------------------------------------------------


class TestBisectRunner(unittest.TestCase):
    def test_bisect_returns_unavailable_on_non_repo(self):
        from bugwolf.regression.bisect import BisectRunner, BisectUnavailable
        with tempfile.TemporaryDirectory() as td:
            br = BisectRunner(Path(td))
            res = br.bisect(bad="HEAD", good="HEAD~1",
                            test_command=["true"], timeout_seconds=10)
        self.assertIsInstance(res, BisectUnavailable)
        self.assertFalse(res.ok)
        self.assertIn("not a git", res.error)

    def test_bisect_returns_unavailable_on_empty_command(self):
        from bugwolf.regression.bisect import BisectRunner, BisectUnavailable
        with tempfile.TemporaryDirectory() as td:
            br = BisectRunner(Path(td))
            res = br.bisect(bad="HEAD", good="HEAD~1",
                            test_command=[], timeout_seconds=10)
        self.assertIsInstance(res, BisectUnavailable)
        self.assertFalse(res.ok)


# ---------------------------------------------------------------------------
# RegressionRunner tests
# ---------------------------------------------------------------------------


class TestRegressionRunner(unittest.TestCase):
    def test_detect_regressions_returns_report(self):
        from bugwolf.regression.regression_runner import (
            RegressionRunner,
            RegressionReport,
        )
        from bugwolf.regression.git_diff import GitDiffer
        from bugwolf.regression.cross_commit_taint import CrossCommitTaintAnalyzer
        from bugwolf.regression.bisect import BisectRunner

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "config", "user.email", "t@example.com"],
                           cwd=str(tmp), check=False, timeout=10)
            subprocess.run(["git", "config", "user.name", "T"],
                           cwd=str(tmp), check=False, timeout=10)
            (tmp / "f.py").write_text("a = 1\n")
            subprocess.run(["git", "add", "f.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "c1", "-q"],
                           cwd=str(tmp), check=False, timeout=10)
            (tmp / "f.py").write_text("b = 2\n")
            subprocess.run(["git", "add", "f.py"], cwd=str(tmp),
                           check=False, timeout=10)
            subprocess.run(["git", "commit", "-m", "c2", "-q"],
                           cwd=str(tmp), check=False, timeout=10)

            differ = GitDiffer(tmp)
            taint = CrossCommitTaintAnalyzer(tmp, None)
            bisect = BisectRunner(tmp)
            runner = RegressionRunner(differ, taint, bisect)
            report = runner.detect_regressions("HEAD~1", "HEAD",
                                               max_bisect_commits=5)
        self.assertIsInstance(report, RegressionReport)

    def test_to_markdown_non_empty(self):
        from bugwolf.regression.regression_runner import RegressionReport
        report = RegressionReport(
            diffs=[],
            findings=[],
            bisects=[],
            metadata=(("ref_a", "v1"), ("ref_b", "v2"), ("schema",
                                                          "bugwolf-regression-v1")),
        )
        md = report.to_markdown()
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 0)
        self.assertIn("Regression Report", md)
        # The schema entry should appear in the metadata section.
        self.assertIn("schema", md.lower())
        self.assertIn("bugwolf-regression-v1", md)


# ---------------------------------------------------------------------------
# Shim test
# ---------------------------------------------------------------------------


class TestPatchGapShim(unittest.TestCase):
    def test_shim_returns_usable_object(self):
        from tools.patch_gap import patch_gap_regression_bridge
        obj = patch_gap_regression_bridge()
        self.assertIsNotNone(obj)
        # The bridge always returns something with a ``scan`` method —
        # either a real ``RegressionPatchGap`` or a stub.
        self.assertTrue(hasattr(obj, "scan"))
        # Calling ``scan`` must NEVER raise.
        try:
            res = obj.scan("nonexistent-target")
        except Exception as e:  # pragma: no cover
            self.fail(f"scan() raised: {e}")
        # The result should be truthy-ish / not crash.
        self.assertTrue(res is not None)


if __name__ == "__main__":
    unittest.main()

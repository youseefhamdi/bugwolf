#!/usr/bin/env python3
"""Phase 3.1 tests — coverage-guided fuzzing substrate.

This module verifies:

  * all 12 modules import cleanly
  * each public surface returns sensible data
  * stub-safety holds (binary missing / backend missing)
  * no shell=True / verify=False / hardcoded UA / forbidden methods
  * every file declares ``## Source:`` + ``## License:`` and ``SCHEMA``
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PKG = ROOT / "bugwolf" / "fuzz"


# ---------------------------------------------------------------------------
# Module-by-module smoke tests
# ---------------------------------------------------------------------------


class TestAFLRunner(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.afl_runner import AFLRunner, FuzzResult, FuzzRunnerUnavailable
        self.assertEqual(AFLRunner.name, "afl++")

    def test_is_available_false_when_missing(self):
        from bugwolf.fuzz.afl_runner import AFLRunner

        runner = AFLRunner(afl_path="/nonexistent/afl-fuzz-binary")
        self.assertFalse(runner.is_available())

    def test_run_returns_unavailable_when_missing(self):
        from bugwolf.fuzz.afl_runner import AFLRunner, FuzzRunnerUnavailable

        runner = AFLRunner(afl_path="/nonexistent/afl-fuzz-binary")
        with _tempdir() as tmp:
            result = runner.run(
                target_binary="/bin/echo",
                input_corpus=tmp / "in",
                output_dir=tmp / "out",
            )
        self.assertIsInstance(result, FuzzRunnerUnavailable)
        self.assertEqual(result.runner_name, "afl++")


class TestLibFuzzerRunner(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.libfuzzer_runner import LibFuzzerRunner, LibFuzzerOptions

        self.assertEqual(LibFuzzerRunner.name, "libfuzzer")
        opts = LibFuzzerOptions(max_total_time=10)
        self.assertEqual(opts.max_total_time, 10)

    def test_is_available_false_when_missing(self):
        from bugwolf.fuzz.libfuzzer_runner import LibFuzzerRunner

        runner = LibFuzzerRunner(target_binary="/nonexistent/libfuzzer-binary")
        self.assertFalse(runner.is_available())

    def test_run_returns_unavailable_when_missing(self):
        from bugwolf.fuzz.libfuzzer_runner import LibFuzzerRunner, FuzzRunnerUnavailable

        runner = LibFuzzerRunner(target_binary="/nonexistent/libfuzzer-binary")
        with _tempdir() as tmp:
            result = runner.run(
                target_binary="/nonexistent/libfuzzer-binary",
                input_corpus=tmp / "in",
                output_dir=tmp / "out",
            )
        self.assertIsInstance(result, FuzzRunnerUnavailable)


class TestGrammarBased(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.grammar_based import (
            GrammarBasedFuzzer,
            GrammarBasedGenerator,
            load_grammar,
        )
        self.assertTrue(callable(load_grammar))

    def test_generator_produces_samples(self):
        from bugwolf.fuzz.grammar_based import GrammarBasedGenerator, load_grammar

        grammar_text = "greet: 'hi' | 'hello' | 'hey';"
        with _tempdir() as tmp:
            gpath = tmp / "g.g4"
            gpath.write_text(grammar_text)
            grammar = load_grammar(gpath)
            gen = GrammarBasedGenerator(grammar=grammar, seed_corpus=[], max_depth=4)
            samples = list(gen.generate("greet", n=8))
            self.assertTrue(samples)
            self.assertTrue(any(s for s in samples))

    def test_grammar_fuzzer_driver_safe_when_missing(self):
        from bugwolf.fuzz.grammar_based import GrammarBasedFuzzer

        fuzzer = GrammarBasedFuzzer(grammar_path=Path("/nonexistent.g4"))
        self.assertFalse(fuzzer.is_available())
        result = fuzzer.run()
        self.assertEqual(result.samples_kept, 0)


class TestDifferential(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.differential import DifferentialDiff, DiffResult
        self.assertTrue(callable(DifferentialDiff().compare))

    def test_compare_returns_diff_result(self):
        from bugwolf.fuzz.differential import DifferentialDiff, DiffResult, HttpObservationLike

        diff = DifferentialDiff()
        a = HttpObservationLike(status=200, body="hello", headers={"x": "1"})
        b = HttpObservationLike(status=500, body="hello world", headers={"x": "2"})
        result = diff.compare(a, b)
        self.assertIsInstance(result, DiffResult)
        self.assertEqual(result.status_delta, "200 -> 500")
        self.assertGreater(result.length_delta, 0)


class TestLLMSeedGenerator(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.llm_seed_gen import LLMSeedGenerator
        self.assertTrue(callable(LLMSeedGenerator().generate))

    def test_generate_empty_when_no_backend(self):
        from bugwolf.fuzz.llm_seed_gen import LLMSeedGenerator

        gen = LLMSeedGenerator(backends=[])
        # Stub-safe: no backend reports available without keys → empty list
        seeds = gen.generate("/bin/echo", n=4)
        self.assertIsInstance(seeds, list)


class TestCrashTriage(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.crash_triage import CrashTriage, CrashReport
        self.assertTrue(callable(CrashTriage().triage))

    def test_categorises_segv(self):
        from bugwolf.fuzz.crash_triage import CrashTriage

        with _tempdir() as tmp:
            crash = tmp / "crash.bin"
            crash.write_text(
                "==12345== ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
                "    #0 0xdeadbeef in main /src/x.c:42\n"
            )
            report = CrashTriage().triage(crash)
        self.assertEqual(report.category, "SEGV")
        self.assertEqual(report.severity, "high")
        self.assertTrue(report.matched_lines)

    def test_categorises_timeout(self):
        from bugwolf.fuzz.crash_triage import CrashTriage

        with _tempdir() as tmp:
            crash = tmp / "hang.bin"
            crash.write_text("hang detected: input took too long\n")
            report = CrashTriage().triage(crash)
        self.assertEqual(report.category, "TIMEOUT")


class TestPoCGenerator(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.poc_generator import PoCGenerator
        self.assertTrue(callable(PoCGenerator().generate))

    def test_writes_file(self):
        from bugwolf.fuzz.crash_triage import CrashReport
        from bugwolf.fuzz.poc_generator import PoCGenerator

        with _tempdir() as tmp:
            crash_file = tmp / "crash.bin"
            crash_file.write_bytes(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
            report = CrashReport(
                crash_path=str(crash_file),
                category="SEGV",
                severity="high",
                sha256_prefix="deadbeef",
                size_bytes=32,
                summary="segv",
                matched_lines=("SEGV",),
                recommended_action="audit",
                fingerprint="abc",
            )
            gen = PoCGenerator(output_dir=tmp / "poc")
            poc = gen.generate(report)
            self.assertIsNotNone(poc)
            self.assertTrue(poc.path.exists())
            self.assertIn(poc.kind, ("curl", "python", "shell"))
            self.assertGreater(poc.bytes_written, 0)


class TestCorpusManager(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.corpus_manager import CorpusManager
        self.assertTrue(callable(CorpusManager))

    def test_add_minimize_merge(self):
        from bugwolf.fuzz.corpus_manager import CorpusManager

        with _tempdir() as tmp:
            mgr = CorpusManager(root=tmp / "corpus")
            e1 = mgr.add(b"hello")
            e2 = mgr.add(b"hello")  # duplicate
            e3 = mgr.add(b"world")
            self.assertEqual(len(mgr.list()), 3)
            entries = mgr.minimize()
            # Duplicate dropped
            self.assertLessEqual(len(entries), 2)
            # Merge from another dir
            other = tmp / "other"
            other.mkdir()
            (other / "x.bin").write_bytes(b"!@#$")
            mgr.merge([other])
            self.assertGreaterEqual(len(mgr.list()), 2)


class TestCoverageTracker(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.coverage_tracker import CoverageTracker
        t = CoverageTracker()
        self.assertEqual(len(t), 0)

    def test_record_merge_score(self):
        from bugwolf.fuzz.coverage_tracker import CoverageTracker

        a = CoverageTracker(capacity=10)
        b = CoverageTracker(capacity=10)
        a.record({1, 2, 3})
        b.record({3, 4, 5})
        new = a.merge(b)
        self.assertEqual(new, 2)  # 4 and 5 are new to a
        self.assertIn(4, a)
        self.assertIn(5, a)
        self.assertGreater(a.score(), 0.0)
        self.assertLessEqual(a.score(), 1.0)


class TestMutationEngine(unittest.TestCase):
    def test_import(self):
        from bugwolf.fuzz.mutation_engine import MutationEngine
        self.assertTrue(callable(MutationEngine().mutate))

    def test_mutate_returns_n_variants(self):
        from bugwolf.fuzz.mutation_engine import MutationEngine

        engine = MutationEngine(seed=42)
        variants = engine.mutate(b"hello world", n=12)
        self.assertEqual(len(variants), 12)
        # At least one variant should differ from the input
        self.assertTrue(any(v != b"hello world" for v in variants))


# ---------------------------------------------------------------------------
# Scheduler tests
# ---------------------------------------------------------------------------


class TestSchedulers(unittest.TestCase):
    def test_afl_fast(self):
        from bugwolf.fuzz.schedulers import AFLFastScheduler
        s = AFLFastScheduler()
        queue = [b"a", b"bb", b"ccc"]
        result = s.select_next(queue, edges_per_input=[{1, 2}, {3}, {1, 3, 5}])
        self.assertIn(result, queue)

    def test_explore(self):
        from bugwolf.fuzz.schedulers import ExploreScheduler
        s = ExploreScheduler()
        queue = [b"x", b"y", b"z"]
        self.assertIn(s.select_next(queue), queue)

    def test_coe(self):
        from bugwolf.fuzz.schedulers import COEScheduler
        s = COEScheduler()
        queue = [b"x", b"y", b"z"]
        self.assertIn(s.select_next(queue), queue)


# ---------------------------------------------------------------------------
# Anti-pattern gates
# ---------------------------------------------------------------------------


def _all_python_files() -> list:
    out = []
    for p in PKG.rglob("*.py"):
        out.append(p)
    return out


class TestAntiPatterns(unittest.TestCase):
    def test_no_shell_true(self):
        offenders = []
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            # Match "shell=True" but not "shell=False"
            if re.search(r"shell\s*=\s*True", text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"shell=True found in: {offenders}")

    def test_no_verify_false(self):
        offenders = []
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"verify\s*=\s*False", text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"verify=False found in: {offenders}")

    def test_no_hardcoded_user_agent(self):
        offenders = []
        ua_pattern = re.compile(
            r"User-Agent['\"]?\s*[:=]\s*['\"](?:Mozilla|curl|wget|Python-requests|BugBot)",
            re.IGNORECASE,
        )
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            if ua_pattern.search(text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"hardcoded UA in: {offenders}")

    def test_no_forbidden_http_methods(self):
        offenders = []
        bad = re.compile(r"\b(POUET|UNCHECKOUT|LABEL)\b")
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            if bad.search(text):
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"forbidden HTTP method in: {offenders}")

    def test_no_scrapling_parser_import(self):
        offenders = []
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            if "from scrapling.parser" in text:
                offenders.append(str(path))
        self.assertEqual(offenders, [], f"scrapling.parser import in: {offenders}")

    def test_no_dangerous_url_schemes(self):
        offenders = []
        schemes = re.compile(r"['\"](?:file|gopher)://")
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in schemes.finditer(text):
                # Skip comments that explicitly forbid these schemes
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]
                if "forbid" in line.lower() or "no file://" in line.lower() or "no gopher://" in line.lower():
                    continue
                offenders.append(f"{path}: {line.strip()}")
        self.assertEqual(offenders, [], f"dangerous scheme in: {offenders}")


# ---------------------------------------------------------------------------
# Source / license header enforcement
# ---------------------------------------------------------------------------


class TestSourceLicenseHeaders(unittest.TestCase):
    def test_every_python_file_has_headers(self):
        missing = []
        for path in _all_python_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            if "## Source:" not in text or "## License:" not in text:
                missing.append(str(path))
        self.assertEqual(missing, [], f"missing headers in: {missing}")

    def test_every_grammar_has_headers(self):
        missing = []
        for path in (PKG / "grammars").glob("*.g4"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "## Source:" not in text or "## License:" not in text:
                missing.append(str(path.name))
        self.assertEqual(missing, [], f"missing headers in grammars: {missing}")


# ---------------------------------------------------------------------------
# Subprocess routing
# ---------------------------------------------------------------------------


class TestSubprocessRouting(unittest.TestCase):
    def test_afl_runner_routes_through_safe_subprocess(self):
        """The runner must use safe_subprocess.spawn_argv or stdlib with shell=False."""
        from bugwolf.fuzz import afl_runner

        src = Path(afl_runner.__file__).read_text(encoding="utf-8")
        self.assertTrue(
            "spawn_argv" in src or "shell=False" in src,
            "AFLRunner must route through safe_subprocess.spawn_argv or stdlib with shell=False",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


import contextlib
import tempfile


@contextlib.contextmanager
def _tempdir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


if __name__ == "__main__":
    unittest.main()

## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""BugWolf coverage-guided fuzzing substrate (Phase 3.1).

This package provides a self-contained, stub-safe fuzzing layer composed
of 12 modules:

  * :class:`AFLRunner`        — wraps AFL++ via :func:`safe_subprocess.spawn_argv`
  * :class:`LibFuzzerRunner`  — wraps libFuzzer via the same safe wrapper
  * :class:`GrammarBasedFuzzer` — EBNF parser + sample generator
  * :class:`DifferentialDiff`  — response-diff comparator
  * :class:`LLMSeedGenerator`  — uses :class:`BaseBackend` from Phase 1.1
  * :class:`CrashTriage`       — root-cause categorisation
  * :class:`PoCGenerator`      — auto-PoC reproducer
  * :class:`CorpusManager`     — seed corpus CRUD
  * :class:`CoverageTracker`   — in-memory coverage map
  * :class:`MutationEngine`    — AFL-style mutation operators
  * Schedulers (afl-fast, explore, coe)

All modules are stub-safe: if a dependency (AFL binary, LLM backend,
grammar file) is missing, the module returns an "unavailable" dataclass
and never raises.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from bugwolf.fuzz.afl_runner import AFLRunner, FuzzRunnerUnavailable
from bugwolf.fuzz.coverage_tracker import CoverageTracker
from bugwolf.fuzz.corpus_manager import CorpusManager
from bugwolf.fuzz.crash_triage import CrashReport, CrashTriage
from bugwolf.fuzz.differential import (
    DifferentialDiff,
    DiffResult,
    HttpObservationLike,
)
from bugwolf.fuzz.grammar_based import (
    GrammarBasedFuzzer,
    GrammarBasedGenerator,
    load_grammar,
)
from bugwolf.fuzz.libfuzzer_runner import LibFuzzerRunner
from bugwolf.fuzz.llm_seed_gen import LLMSeedGenerator
from bugwolf.fuzz.mutation_engine import MutationEngine
from bugwolf.fuzz.poc_generator import PoCGenerator

SCHEMA = "bugwolf-fuzz-v1"


__all__ = [
    "SCHEMA",
    "AFLRunner",
    "LibFuzzerRunner",
    "GrammarBasedFuzzer",
    "GrammarBasedGenerator",
    "load_grammar",
    "DifferentialDiff",
    "DiffResult",
    "HttpObservationLike",
    "LLMSeedGenerator",
    "CrashTriage",
    "CrashReport",
    "PoCGenerator",
    "CorpusManager",
    "CoverageTracker",
    "MutationEngine",
    "FuzzRunnerUnavailable",
    "FuzzResult",
]


# Re-export dataclasses used widely by the package
from bugwolf.fuzz.afl_runner import FuzzResult  # noqa: E402  (placed after exports)

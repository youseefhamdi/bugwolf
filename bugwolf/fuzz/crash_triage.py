## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL+ libFuzzer crash categorisation conventions (README sections)
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Crash triage for the BugWolf fuzzing substrate.

:class:`CrashTriage` inspects a crash artefact, runs regex-driven
categorisation against the stack-trace text (when available) and
emits a structured :class:`CrashReport`.  All heuristics are
deterministic and the module never raises.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "bugwolf-fuzz-triage-v1"


# Crash category taxonomy ---------------------------------------------------

CATEGORIES: Tuple[str, ...] = (
    "SEGV",
    "ASSERT",
    "ASSERT_FAIL",
    "ABORT",
    "TIMEOUT",
    "OOM",
    "STACK_OVERFLOW",
    "USE_AFTER_FREE",
    "HEAP_OVERFLOW",
    "INTEGER_OVERFLOW",
    "NULL_DEREF",
    "UNKNOWN",
)


# Heuristics ----------------------------------------------------------------
# Each entry: (category, compiled regex, weight).  Triage picks the
# category with the highest total weight across matched lines.

_HEURISTICS: Tuple[Tuple[str, re.Pattern, int], ...] = (
    ("SEGV",            re.compile(r"\bSIGSEGV\b|\bSEGV\b|segmentation fault", re.IGNORECASE),  3),
    ("ABORT",           re.compile(r"\bSIGABRT\b|\bAbort\b|abort\(\) called", re.IGNORECASE), 3),
    ("ASSERT",          re.compile(r"\bassert(?:ion)?\b.*failed", re.IGNORECASE),     2),
    ("ASSERT_FAIL",     re.compile(r"ASSERT_FAIL|assertion failed:", re.IGNORECASE),   3),
    ("TIMEOUT",         re.compile(r"timeout|timed out|hang detected", re.IGNORECASE), 2),
    ("OOM",             re.compile(r"out of memory|OutOfMemory|\bOOM\b", re.IGNORECASE), 3),
    ("STACK_OVERFLOW",  re.compile(r"stack overflow|StackOverflow", re.IGNORECASE),    3),
    ("USE_AFTER_FREE",  re.compile(r"use[-_ ]after[-_ ]free|\bUAF\b", re.IGNORECASE),  3),
    ("HEAP_OVERFLOW",   re.compile(r"heap[-_ ]buffer[-_ ]overflow|heap overflow", re.IGNORECASE), 3),
    ("INTEGER_OVERFLOW", re.compile(r"integer overflow|wraparound", re.IGNORECASE),   2),
    ("NULL_DEREF",      re.compile(r"null pointer|null[-_ ]deref|nullptr", re.IGNORECASE), 2),
)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrashReport:
    """Structured triage output for one crash artefact."""

    crash_path: str
    category: str
    severity: str
    sha256_prefix: str
    size_bytes: int
    summary: str
    matched_lines: Tuple[str, ...]
    recommended_action: str
    fingerprint: str
    extras: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "crash_path": self.crash_path,
            "category": self.category,
            "severity": self.severity,
            "sha256_prefix": self.sha256_prefix,
            "size_bytes": self.size_bytes,
            "summary": self.summary,
            "matched_lines": list(self.matched_lines),
            "recommended_action": self.recommended_action,
            "fingerprint": self.fingerprint,
            "extras": dict(self.extras),
        }


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


_SEVERITY_BY_CATEGORY: Dict[str, str] = {
    "SEGV":             "high",
    "ABORT":            "high",
    "ASSERT_FAIL":      "high",
    "ASSERT":           "medium",
    "TIMEOUT":          "medium",
    "OOM":              "high",
    "STACK_OVERFLOW":   "high",
    "USE_AFTER_FREE":   "critical",
    "HEAP_OVERFLOW":    "critical",
    "INTEGER_OVERFLOW": "medium",
    "NULL_DEREF":       "high",
    "UNKNOWN":          "low",
}


_RECOMMENDED_ACTION: Dict[str, str] = {
    "SEGV":             "Inspect crash; bisect to offending offset.",
    "ABORT":            "Reproduce locally; capture core dump if possible.",
    "ASSERT_FAIL":      "Read the assertion text; identify the violated invariant.",
    "ASSERT":           "Capture stack trace; map assertion to source line.",
    "TIMEOUT":          "Reduce input size; check for infinite loops.",
    "OOM":              "Look for unbounded allocations or memory leaks.",
    "STACK_OVERFLOW":   "Audit recursion depth and large stack allocations.",
    "USE_AFTER_FREE":   "Investigate ownership/lifetime of freed memory.",
    "HEAP_OVERFLOW":    "Audit bounds of the affected buffer.",
    "INTEGER_OVERFLOW": "Audit arithmetic; consider safe integer library.",
    "NULL_DEREF":       "Trace the offending pointer; add a null guard.",
    "UNKNOWN":          "Run again with sanitizers to obtain a stack trace.",
}


class CrashTriage:
    """Root-cause categorisation for crash artefacts."""

    def __init__(self) -> None:
        self.categories: Tuple[str, ...] = CATEGORIES
        self._heuristics = _HEURISTICS

    # ----------------------------------------------------------------- API

    def triage(self, crash_file: Path) -> CrashReport:
        """Return a :class:`CrashReport` for ``crash_file``.

        Reads up to 64 KiB from the file, computes a sha256 prefix,
        runs the heuristics, and packages the result.  Never raises.
        """
        path = Path(crash_file)
        try:
            data = self._read_limited(path)
        except Exception as exc:
            return CrashReport(
                crash_path=str(path),
                category="UNKNOWN",
                severity="low",
                sha256_prefix="",
                size_bytes=0,
                summary=f"unable to read crash: {exc!r}",
                matched_lines=(),
                recommended_action=_RECOMMENDED_ACTION["UNKNOWN"],
                fingerprint="",
            )

        sha_prefix = hashlib.sha256(data).hexdigest()[:16]
        text = self._to_text(data)
        category, matched = self._categorise(text)
        severity = _SEVERITY_BY_CATEGORY.get(category, "low")
        action = _RECOMMENDED_ACTION.get(category, _RECOMMENDED_ACTION["UNKNOWN"])
        summary = self._summarise(category, matched, data)
        fingerprint = self._fingerprint(category, matched, sha_prefix)
        return CrashReport(
            crash_path=str(path),
            category=category,
            severity=severity,
            sha256_prefix=sha_prefix,
            size_bytes=len(data),
            summary=summary,
            matched_lines=tuple(matched[:8]),
            recommended_action=action,
            fingerprint=fingerprint,
        )

    def triage_many(self, crash_files: List[Path]) -> List[CrashReport]:
        """Triage a list of crash artefacts."""
        return [self.triage(Path(p)) for p in crash_files]

    # ------------------------------------------------------------ internals

    def _read_limited(self, path: Path, limit: int = 65536) -> bytes:
        if not path.exists():
            return b""
        with path.open("rb") as fh:
            return fh.read(limit)

    def _to_text(self, data: bytes) -> str:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _categorise(self, text: str) -> Tuple[str, List[str]]:
        scores: Dict[str, int] = {}
        matched: List[str] = []
        for line in text.splitlines():
            for cat, pattern, weight in self._heuristics:
                if pattern.search(line):
                    scores[cat] = scores.get(cat, 0) + weight
                    matched.append(line.strip())
        if not scores:
            return "UNKNOWN", matched
        best = max(scores.items(), key=lambda kv: (kv[1], kv[0]))[0]
        return best, matched

    def _summarise(self, category: str, matched: List[str], data: bytes) -> str:
        if not matched:
            return (
                f"{category} crash, {len(data)} bytes, no stack trace recognised"
            )
        head = matched[0][:120]
        return f"{category} crash, first match: {head!r}"

    def _fingerprint(self, category: str, matched: List[str], sha_prefix: str) -> str:
        head = matched[0][:32] if matched else ""
        return f"{category}:{sha_prefix}:{hashlib.md5(head.encode()).hexdigest()[:8]}"


__all__ = [
    "CrashTriage",
    "CrashReport",
    "CATEGORIES",
]

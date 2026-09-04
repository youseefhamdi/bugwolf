#!/usr/bin/env python3
"""Observation of send results — FACTS, never verdicts (Phase 1.5).

The replay engine hands back what happened; the F0.5 evidence gate (and
only the F0.5 gate) decides what it means.  This module provides the
fact-extraction primitives the compare/sweep modes and the verify lane
consume:

  * reflection  -- does the response body contain the probe marker?
  * error_signatures -- known DB/template/runtime error fingerprints
  * diff        -- deterministic A-vs-B delta (status, body size, timing,
                   set-header changes, marker presence change)

Deterministic tier: no model calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from tools.runtime.replay.backend_socket import SendResult

SCHEMA = "bugwolf-replay-observe/v1"

# Common error fingerprints (substring, class label). Deliberately short —
# these are FACTS (the target emitted this text), not findings.
ERROR_SIGNATURES = (
    ("you have an error in your sql syntax", "sql_error_mysql"),
    ("unclosed quotation mark after the character", "sql_error_mssql"),
    ("pg_query()", "sql_error_postgres"),
    ("ora-", "sql_error_oracle"),
    ("sqlite3.", "sql_error_sqlite"),
    ("fatal error:", "php_fatal"),
    ("warning: ", "php_warning"),
    ("traceback (most recent call last)", "python_traceback"),
    ("exception in thread", "java_exception"),
    ("jinja2.exceptions", "ssti_jinja"),
    ("twig_error_runtime", "ssti_twig"),
    ("<error>", "xml_error"),
)


@dataclass
class Observation:
    """Facts extracted from one SendResult."""

    status: Optional[int]
    elapsed_ms: float
    body_bytes: int
    reflections: List[str] = field(default_factory=list)
    error_classes: List[str] = field(default_factory=list)
    truncated: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "body_bytes": self.body_bytes,
            "reflections": self.reflections,
            "error_classes": self.error_classes,
            "truncated": self.truncated,
            "transport_error": self.error,
        }


def observe(result: SendResult, *, markers: Optional[List[str]] = None) -> Observation:
    """Extract facts from one send result.

    ``markers`` are probe canaries (e.g. the bwexec-XXXX signature); each
    marker found in the body is recorded verbatim — presence is a fact,
    exploitation is a verdict the verify lane makes.
    """
    body_text = result.body.decode("latin-1", "replace")
    lowered = body_text.lower()
    reflections = [m for m in (markers or []) if m and m in body_text]
    error_classes = [label for needle, label in ERROR_SIGNATURES
                     if needle in lowered]
    return Observation(
        status=result.status,
        elapsed_ms=result.elapsed_ms,
        body_bytes=len(result.body),
        reflections=reflections,
        error_classes=error_classes,
        truncated=result.truncated,
        error=result.error,
    )


@dataclass
class Delta:
    """Deterministic A-vs-B delta between two sends (compare mode's output)."""

    status_delta: Optional[int] = None          # B.status - A.status
    body_size_delta: int = 0                    # B.body_bytes - A.body_bytes
    timing_delta_ms: float = 0.0
    new_markers_in_b: List[str] = field(default_factory=list)
    dropped_markers_in_b: List[str] = field(default_factory=list)
    new_error_classes_in_b: List[str] = field(default_factory=list)
    a: Dict = field(default_factory=dict)
    b: Dict = field(default_factory=dict)

    @property
    def differs(self) -> bool:
        """Any measurable difference — a FACT.  Whether it means 'vuln'
        belongs to the F0.5 gate, never here."""
        return bool(
            self.status_delta or self.body_size_delta
            or self.new_markers_in_b or self.dropped_markers_in_b
            or self.new_error_classes_in_b
        )

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "differs": self.differs,
            "status_delta": self.status_delta,
            "body_size_delta": self.body_size_delta,
            "timing_delta_ms": round(self.timing_delta_ms, 2),
            "new_markers_in_b": self.new_markers_in_b,
            "dropped_markers_in_b": self.dropped_markers_in_b,
            "new_error_classes_in_b": self.new_error_classes_in_b,
            "a": self.a,
            "b": self.b,
        }


def diff(a: SendResult, b: SendResult, *, markers: Optional[List[str]] = None) -> Delta:
    """Compare two send results of the SAME request shape (baseline vs
    mutation).  Deterministic; no thresholds — raw deltas only."""
    obs_a = observe(a, markers=markers)
    obs_b = observe(b, markers=markers)
    set_a, set_b = set(obs_a.reflections), set(obs_b.reflections)
    return Delta(
        status_delta=(obs_b.status - obs_a.status)
        if (obs_a.status is not None and obs_b.status is not None) else None,
        body_size_delta=obs_b.body_bytes - obs_a.body_bytes,
        timing_delta_ms=obs_b.elapsed_ms - obs_a.elapsed_ms,
        new_markers_in_b=sorted(set_b - set_a),
        dropped_markers_in_b=sorted(set_a - set_b),
        new_error_classes_in_b=sorted(set(obs_b.error_classes)
                                      - set(obs_a.error_classes)),
        a=obs_a.to_dict(),
        b=obs_b.to_dict(),
    )

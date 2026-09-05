## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: tools/differential.py — sibling-drift comparison concept
## Source: tools/observation.py — HttpObservation dataclass shape
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Differential response-diff comparator for the BugWolf fuzzing substrate.

:class:`DifferentialDiff` compares two responses (e.g. the same input
sent to two candidate endpoints) and produces a :class:`DiffResult`
suitable for crash triage and lead scoring.  Comparison is fully
in-process and stdlib-only; no network is involved.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


SCHEMA = "bugwolf-fuzz-differential-v1"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpObservationLike:
    """Minimal duck-typed view of an HTTP observation.

    The BugWolf codebase has several HTTP observation dataclasses
    (e.g. ``tools.observation.HttpObservation``); this minimal record
    matches them on the field names the differential comparator cares
    about — status, body, headers, timing.
    """

    status: int = 0
    body: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    timing_seconds: float = 0.0
    size_bytes: int = 0
    error: str = ""

    @classmethod
    def from_any(cls, obj: Any) -> "HttpObservationLike":
        """Adapt any object with the right attributes into our shape."""
        try:
            return cls(
                status=int(getattr(obj, "status", 0) or 0),
                body=str(getattr(obj, "body", "") or ""),
                headers=dict(getattr(obj, "headers", {}) or {}),
                timing_seconds=float(getattr(obj, "timing_seconds", 0.0) or 0.0),
                size_bytes=int(
                    getattr(obj, "size_bytes", None)
                    or len(str(getattr(obj, "body", "") or ""))
                ),
                error=str(getattr(obj, "error", "") or ""),
            )
        except Exception:
            return cls()


@dataclass(frozen=True)
class DiffResult:
    """Structured diff between two HTTP observations.

    All fields are safe defaults (``""``, ``0.0``, ``True``) so callers
    can pattern-match on a result without worrying about empty
    observations.
    """

    status_delta: str = ""
    body_diff_ratio: float = 1.0
    length_delta: int = 0
    signature_match: bool = True
    timing_delta: float = 0.0
    header_additions: List[str] = field(default_factory=list)
    header_removals: List[str] = field(default_factory=list)
    severity: str = "none"  # none | low | medium | high
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status_delta": self.status_delta,
            "body_diff_ratio": round(self.body_diff_ratio, 3),
            "length_delta": self.length_delta,
            "signature_match": self.signature_match,
            "timing_delta": round(self.timing_delta, 4),
            "header_additions": list(self.header_additions),
            "header_removals": list(self.header_removals),
            "severity": self.severity,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Comparator
# ---------------------------------------------------------------------------


@dataclass
class DifferentialDiff:
    """Compare two responses and emit a :class:`DiffResult`.

    The comparator uses :mod:`difflib` for body similarity and a
    simple symmetric header diff for header deltas.  Severity is
    derived from the magnitude of the diff so callers can sort
    findings without bespoke scoring.
    """

    min_body_diff_threshold: float = 0.20
    timing_anomaly_ratio: float = 2.0

    def compare(
        self,
        response_a: Any,
        response_b: Any,
    ) -> DiffResult:
        """Return a :class:`DiffResult` for ``response_a`` vs ``response_b``.

        The function NEVER raises; on any failure it returns a
        ``DiffResult`` with ``severity="none"``.
        """
        try:
            a = HttpObservationLike.from_any(response_a)
            b = HttpObservationLike.from_any(response_b)
            return self._compare(a, b)
        except Exception as exc:
            return DiffResult(detail=f"compare failed: {exc!r}")

    # ------------------------------------------------------------ internals

    def _compare(
        self,
        a: HttpObservationLike,
        b: HttpObservationLike,
    ) -> DiffResult:
        status_delta = f"{a.status} -> {b.status}" if a.status != b.status else ""
        body_ratio = self._body_similarity(a.body, b.body)
        length_delta = b.size_bytes - a.size_bytes
        timing_delta = b.timing_seconds - a.timing_seconds
        header_add, header_rem = self._header_delta(a.headers, b.headers)
        signature_match = (
            a.status == b.status
            and body_ratio >= (1.0 - self.min_body_diff_threshold)
            and not header_add
            and not header_rem
        )
        severity = self._severity(
            status_delta=bool(status_delta),
            body_diff=1.0 - body_ratio,
            header_changes=bool(header_add or header_rem),
            timing_anomaly=self._is_timing_anomaly(a.timing_seconds, b.timing_seconds),
        )
        detail_parts: List[str] = []
        if status_delta:
            detail_parts.append(f"status delta {status_delta}")
        if 1.0 - body_ratio >= self.min_body_diff_threshold:
            detail_parts.append(f"body diff {1.0 - body_ratio:.2f}")
        if header_add or header_rem:
            detail_parts.append(
                f"headers +{len(header_add)} -{len(header_rem)}"
            )
        if self._is_timing_anomaly(a.timing_seconds, b.timing_seconds):
            detail_parts.append("timing anomaly")
        return DiffResult(
            status_delta=status_delta,
            body_diff_ratio=body_ratio,
            length_delta=length_delta,
            signature_match=signature_match,
            timing_delta=timing_delta,
            header_additions=header_add,
            header_removals=header_rem,
            severity=severity,
            detail="; ".join(detail_parts),
        )

    def _body_similarity(self, a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        return difflib.SequenceMatcher(a=a, b=b, autojunk=False).ratio()

    def _header_delta(
        self,
        a: Mapping[str, str],
        b: Mapping[str, str],
    ) -> tuple:
        a_keys = {k.lower() for k in a.keys()}
        b_keys = {k.lower() for k in b.keys()}
        add = sorted(b_keys - a_keys)
        rem = sorted(a_keys - b_keys)
        return add, rem

    def _is_timing_anomaly(self, a_t: float, b_t: float) -> bool:
        if a_t <= 0 or b_t <= 0:
            return False
        ratio = max(a_t, b_t) / min(a_t, b_t)
        return ratio >= self.timing_anomaly_ratio

    def _severity(
        self,
        *,
        status_delta: bool,
        body_diff: float,
        header_changes: bool,
        timing_anomaly: bool,
    ) -> str:
        score = 0
        if status_delta:
            score += 2
        if body_diff >= 0.5:
            score += 2
        elif body_diff >= self.min_body_diff_threshold:
            score += 1
        if header_changes:
            score += 1
        if timing_anomaly:
            score += 1
        if score >= 4:
            return "high"
        if score >= 2:
            return "medium"
        if score >= 1:
            return "low"
        return "none"


__all__ = [
    "DifferentialDiff",
    "DiffResult",
    "HttpObservationLike",
]

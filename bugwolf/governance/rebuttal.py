"""Rebuttal lifecycle (Phase 1.4 — Governance Core).

State machine for tracking the rebuttal of a single finding::

    ACTIVE -> ACCEPTED            (terminal)
    ACTIVE -> STALLED             (operator marked; reversible to ACTIVE)
    ACTIVE -> EXHAUSTED           (terminal: rebuttal attempts exhausted)

The :class:`Rebuttal` object exposes the canonical rebut/accept/mark_*
verbs.  Each transition appends a hash-chained JSONL entry to the
per-finding log at ``state/governance/rebuttals/<finding_id>.jsonl``.

No external deps; stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ._canonical import SCHEMA as _SCHEMA, canonical_bytes

SCHEMA = "bugwolf-governance-v1"


class RebuttalState(str, Enum):
    ACTIVE = "ACTIVE"
    ACCEPTED = "ACCEPTED"
    STALLED = "STALLED"
    EXHAUSTED = "EXHAUSTED"


class RebuttalError(Exception):
    """Raised when a rebuttal transition is illegal."""


_TERMINAL = {RebuttalState.ACCEPTED, RebuttalState.EXHAUSTED}


@dataclass
class RebuttalEntry:
    schema: str
    finding_id: str
    state: str
    previous_state: Optional[str]
    ts: str
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    entry_sha256: str = ""
    prev_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Rebuttal:
    """Hash-chained rebuttal lifecycle for a single finding."""

    schema = _SCHEMA

    def __init__(
        self,
        finding_id: str,
        *,
        root: Optional[Path] = None,
    ) -> None:
        if not finding_id:
            raise ValueError("Rebuttal requires finding_id")
        self._finding_id = str(finding_id)
        self._state = RebuttalState.ACTIVE
        self._path = self._path_for(root)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    @property
    def finding_id(self) -> str:
        return self._finding_id

    @property
    def state(self) -> RebuttalState:
        return self._state

    @property
    def confidence(self) -> float:
        """Maximum confidence recorded across the rebuttal history.

        Plan Gate 1 invariant: confidence=1.0 may ONLY be recorded when
        a non-null ``replay_key`` is supplied.  Any attempt to set
        confidence=1.0 without a replay_key is silently capped at 0.99
        so downstream consumers can distinguish "high confidence with
        evidence" from "unbacked maximum".
        """
        max_conf = 0.0
        for entry in self.history():
            value = entry.detail.get("confidence")
            if isinstance(value, (int, float)):
                max_conf = max(max_conf, float(value))
        return max_conf

    @property
    def path(self) -> Path:
        return self._path

    def rebut(self, finding: Optional[Mapping[str, Any]] = None,
              *, reason: str = "") -> RebuttalEntry:
        """Record an active rebuttal attempt — no state transition.

        The finding's reasoning, if present, is hashed into the chain
        entry's detail so the audit trail proves the rebuttal was made.

        Implements the Plan Gate 1 invariant: ``confidence`` may only
        be recorded as 1.0 if a non-null ``replay_key`` is supplied.
        Values that violate the invariant are clamped to 0.99.
        """
        detail: Dict[str, Any] = {}
        if finding is not None:
            if isinstance(finding, Mapping):
                detail = {k: v for k, v in finding.items() if _is_hashable(v)}
                confidence = detail.get("confidence")
                replay_key = detail.get("replay_key")
                if isinstance(confidence, (int, float)):
                    conf_val = float(confidence)
                    if conf_val >= 1.0 and not replay_key:
                        detail["confidence"] = 0.99
                        detail["confidence_clamped"] = True
        return self._append(RebuttalState.ACTIVE, reason=reason, detail=detail)

    def accept(self, *, reason: str = "") -> RebuttalEntry:
        """Mark the finding as ACCEPTED (terminal)."""
        return self._transition(RebuttalState.ACCEPTED, reason=reason)

    def mark_stalled(self, *, reason: str = "") -> RebuttalEntry:
        """Mark the rebuttal STALLED (reversible by another ``rebut`` call)."""
        return self._transition(RebuttalState.STALLED, reason=reason)

    def mark_exhausted(self, *, reason: str = "") -> RebuttalEntry:
        """Mark the rebuttal EXHAUSTED (terminal)."""
        return self._transition(RebuttalState.EXHAUSTED, reason=reason)

    def history(self) -> List[RebuttalEntry]:
        """Return all rebuttal entries (oldest first)."""
        if not self._path.is_file():
            return []
        entries: List[RebuttalEntry] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            entries.append(RebuttalEntry(
                schema=payload.get("schema", self.schema),
                finding_id=payload.get("finding_id", self._finding_id),
                state=payload.get("state", RebuttalState.ACTIVE.value),
                previous_state=payload.get("previous_state"),
                ts=payload.get("ts", ""),
                reason=payload.get("reason", ""),
                detail=dict(payload.get("detail") or {}),
                entry_sha256=payload.get("entry_sha256", ""),
                prev_sha256=payload.get("prev_sha256", ""),
            ))
        return entries

    def verify_chain(self) -> Dict[str, Any]:
        result = {
            "schema": self.schema,
            "is_valid": True,
            "verified": 0,
            "errors": [],
        }
        prev_sha = ""
        for index, entry in enumerate(self.history()):
            declared_prev = entry.prev_sha256
            if declared_prev != prev_sha:
                result["is_valid"] = False
                result["errors"].append(
                    f"entry {index}: prev_sha256 mismatch "
                    f"(expected {prev_sha!r}, got {declared_prev!r})")
            unsigned = {
                "schema": entry.schema,
                "finding_id": entry.finding_id,
                "state": entry.state,
                "previous_state": entry.previous_state,
                "ts": entry.ts,
                "reason": entry.reason,
                "detail": entry.detail,
                "prev_sha256": entry.prev_sha256,
            }
            expected = _sha256(canonical_bytes(unsigned))
            if expected != entry.entry_sha256:
                result["is_valid"] = False
                result["errors"].append(
                    f"entry {index}: entry_sha256 mismatch "
                    f"(expected {expected}, got {entry.entry_sha256})")
            prev_sha = entry.entry_sha256
            result["verified"] += 1
        return result

    # -- internals ----------------------------------------------------------

    def _path_for(self, root: Optional[Path]) -> Path:
        base = Path(root) if root else Path(
            os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
        return base / "state" / "governance" / "rebuttals" / (
            f"{self._finding_id}.jsonl")

    def _transition(self, target: RebuttalState, *, reason: str) -> RebuttalEntry:
        if not isinstance(target, RebuttalState):
            raise RebuttalError(f"target must be a RebuttalState, got {target!r}")
        if self._state in _TERMINAL:
            raise RebuttalError(
                f"rebuttal is terminal ({self._state.value}); "
                f"cannot transition to {target.value}")
        # STALLED -> ACTIVE is allowed (a later rebuttal re-engages).
        if target == RebuttalState.STALLED and self._state == RebuttalState.STALLED:
            return self._append(RebuttalState.STALLED, reason=reason, detail={})
        if target == RebuttalState.ACTIVE and self._state != RebuttalState.STALLED:
            raise RebuttalError(
                f"cannot re-activate from {self._state.value} (only STALLED)")
        return self._append(target, reason=reason, detail={})

    def _append(self, target: RebuttalState, *, reason: str,
                detail: Dict[str, Any]) -> RebuttalEntry:
        with self._lock:
            prev_sha = self._tip_sha256_locked()
            previous = self._state
            self._state = target
            entry = RebuttalEntry(
                schema=self.schema,
                finding_id=self._finding_id,
                state=target.value,
                previous_state=previous.value,
                ts=_utc_iso(),
                reason=str(reason or ""),
                detail=dict(detail or {}),
                prev_sha256=prev_sha,
            )
            unsigned = {
                "schema": entry.schema,
                "finding_id": entry.finding_id,
                "state": entry.state,
                "previous_state": entry.previous_state,
                "ts": entry.ts,
                "reason": entry.reason,
                "detail": entry.detail,
                "prev_sha256": entry.prev_sha256,
            }
            entry.entry_sha256 = _sha256(canonical_bytes(unsigned))
            line = json.dumps(entry.to_dict(), sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False)
            with self._path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            return entry

    def _tip_sha256_locked(self) -> str:
        if not self._path.is_file():
            return ""
        try:
            with self._path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                if size == 0:
                    return ""
                offset = size - 1
                buf = b""
                while offset > 0 and b"\n" not in buf:
                    chunk = min(4096, offset)
                    offset -= chunk
                    stream.seek(offset)
                    buf = stream.read(chunk) + buf
                lines = buf.splitlines()
                if not lines:
                    return ""
                last = lines[-1]
                if not last:
                    return ""
                payload = json.loads(last)
                if isinstance(payload, dict):
                    return str(payload.get("entry_sha256") or "")
        except (OSError, json.JSONDecodeError):
            return ""
        return ""


def _is_hashable(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_hashable(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _is_hashable(v)
                   for k, v in value.items())
    return False


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "SCHEMA",
    "RebuttalState",
    "RebuttalError",
    "RebuttalEntry",
    "Rebuttal",
]
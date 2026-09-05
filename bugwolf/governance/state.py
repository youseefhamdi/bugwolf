"""Mission state machine (Phase 1.4 — Governance Core).

Linear mission lifecycle with one terminal state and one emergency state:

    INIT -> SCOPED -> COLLECTING -> ANALYZING -> REPORTING -> DONE
                                                                 \\
                                                                  -> HALTED

``HALTED`` is reachable from any state via the kill-switch (operator
override) and is terminal.  All other transitions go forward through
the linear pipeline.  Re-entry into a previous state is not allowed
(e.g. SCOPED -> INIT, REPORTING -> ANALYZING).  This is the simplest
state machine that satisfies the audit "replay" requirement: every
event in the audit trail can be paired with a deterministic state
transition.

States are stored in the mission's JSONL state file under
``state/governance/missions/<mission_id>.jsonl`` (one entry per
transition).  The state file is append-only; replays re-derive the
state by walking the entries.

No external deps; stdlib only.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"


class MissionState(str, Enum):
    INIT = "INIT"
    SCOPED = "SCOPED"
    COLLECTING = "COLLECTING"
    ANALYZING = "ANALYZING"
    REPORTING = "REPORTING"
    DONE = "DONE"
    HALTED = "HALTED"


class MissionStateError(Exception):
    """Raised when a transition is illegal for the current state."""


_LINEAR_ORDER = [
    MissionState.INIT,
    MissionState.SCOPED,
    MissionState.COLLECTING,
    MissionState.ANALYZING,
    MissionState.REPORTING,
    MissionState.DONE,
]


@dataclass
class MissionRecord:
    """An append-only mission state entry."""

    schema: str
    mission_id: str
    target: str
    state: str
    previous_state: Optional[str]
    ts: str
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MissionStateMachine:
    """Linear mission state machine with kill-switch (HALTED)."""

    schema = _SCHEMA

    def __init__(
        self,
        target: str,
        mission_id: str,
        *,
        root: Optional[Path] = None,
    ) -> None:
        if not target:
            raise ValueError("MissionStateMachine requires target")
        if not mission_id:
            raise ValueError("MissionStateMachine requires mission_id")
        self._target = str(target)
        self._mission_id = str(mission_id)
        self._state = MissionState.INIT
        self._lock = threading.Lock()
        self._path = self._state_path(root)
        # ensure target directory exists for the first transition
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # -- public API ---------------------------------------------------------

    @property
    def target(self) -> str:
        return self._target

    @property
    def mission_id(self) -> str:
        return self._mission_id

    @property
    def state(self) -> MissionState:
        return self._state

    def can_transition(self, target: MissionState) -> bool:
        """True if ``target`` is reachable from the current state."""
        return _is_legal(self._state, target)

    def transition(self, target: MissionState, *, reason: str = "",
                   detail: Optional[Dict[str, Any]] = None) -> MissionRecord:
        """Move to ``target``; raise :class:`MissionStateError` on bad edge."""
        if not isinstance(target, MissionState):
            raise MissionStateError(f"target must be a MissionState, got {target!r}")
        with self._lock:
            if not _is_legal(self._state, target):
                raise MissionStateError(
                    f"illegal transition {self._state.value} -> {target.value}")
            previous = self._state
            self._state = target
            record = MissionRecord(
                schema=self.schema,
                mission_id=self._mission_id,
                target=self._target,
                state=target.value,
                previous_state=previous.value if previous is not None else None,
                ts=_utc_iso(),
                reason=str(reason or ""),
                detail=dict(detail or {}),
            )
            self._append(record)
            return record

    def halt(self, *, reason: str = "kill-switch",
             detail: Optional[Dict[str, Any]] = None) -> MissionRecord:
        """Emergency HALT — reachable from any non-terminal state."""
        return self.transition(MissionState.HALTED, reason=reason, detail=detail)

    def history(self) -> List[MissionRecord]:
        """Return all transition records (linear, oldest-first)."""
        if not self._path.is_file():
            return []
        records: List[MissionRecord] = []
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
            records.append(MissionRecord(
                schema=payload.get("schema", self.schema),
                mission_id=payload.get("mission_id", self._mission_id),
                target=payload.get("target", self._target),
                state=payload.get("state", MissionState.INIT.value),
                previous_state=payload.get("previous_state"),
                ts=payload.get("ts", ""),
                reason=payload.get("reason", ""),
                detail=dict(payload.get("detail") or {}),
            ))
        return records

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "mission_id": self._mission_id,
            "target": self._target,
            "state": self._state.value,
        }

    # -- internals ----------------------------------------------------------

    def _state_path(self, root: Optional[Path]) -> Path:
        base = Path(root) if root else Path(
            os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
        return base / "state" / "governance" / "missions" / (
            f"{self._mission_id}.jsonl")

    def _append(self, record: MissionRecord) -> None:
        line = json.dumps(record.to_dict(), separators=(",", ":"),
                          sort_keys=True, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def _is_legal(current: MissionState, target: MissionState) -> bool:
    if current == MissionState.HALTED:
        return False  # terminal
    if current == MissionState.DONE:
        return False  # terminal
    if target == MissionState.HALTED:
        return True   # emergency path is always reachable
    if current == MissionState.INIT:
        return target == MissionState.SCOPED
    if current not in _LINEAR_ORDER:
        return False
    cur_idx = _LINEAR_ORDER.index(current)
    tgt_idx = _LINEAR_ORDER.index(target)
    return tgt_idx == cur_idx + 1


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "SCHEMA",
    "MissionState",
    "MissionStateError",
    "MissionRecord",
    "MissionStateMachine",
]
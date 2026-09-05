"""State machine derived from journal entries."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-machine-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, Optional, Set

from bugwolf.unified_state.state import State
from bugwolf.unified_state.types import Entry, EntryKind

SCHEMA = "bugwolf-unifiedstate-machine-v1"

_LOG = logging.getLogger("bugwolf.unified_state.machine")


class Phase(Enum):
    """High-level mission phases."""

    INITIALIZED = "initialized"
    SCOPED = "scoped"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


VALID_TRANSITIONS: Dict[Phase, Set[Phase]] = {
    Phase.INITIALIZED: {Phase.SCOPED, Phase.FAILED},
    Phase.SCOPED: {Phase.COLLECTING, Phase.FAILED},
    Phase.COLLECTING: {Phase.ANALYZING, Phase.FAILED},
    Phase.ANALYZING: {Phase.REPORTING, Phase.COLLECTING, Phase.FAILED},
    Phase.REPORTING: {Phase.COMPLETED, Phase.ANALYZING, Phase.FAILED},
    Phase.COMPLETED: set(),
    Phase.FAILED: set(),
}


class InvalidTransition(Exception):
    """Raised when a transition is not permitted by the state machine."""


class StateMachine:
    """Drives phases by appending AUDIT entries to a State journal."""

    def __init__(self, state: State, mission_id: str) -> None:
        self.state = state
        self.mission_id = str(mission_id)

    def current(self) -> Phase:
        """Derive the current phase from the journal.

        Strategy: walk the AUDIT entries for ``mission_id`` from newest to
        oldest; the most recent ``payload.to`` wins. If no audit entries,
        return ``INITIALIZED``.
        """

        entries = self.state.entries_by_mission(self.mission_id)
        audit_entries = [e for e in entries if e.kind == EntryKind.AUDIT]
        for e in reversed(audit_entries):
            to_raw = e.payload.get("to")
            if to_raw is None:
                continue
            try:
                phase = Phase(to_raw)
                return phase
            except (ValueError, TypeError):
                continue
        return Phase.INITIALIZED

    def can_transition(self, new_phase: Phase) -> bool:
        cur = self.current()
        if cur in (Phase.COMPLETED, Phase.FAILED):
            return False
        return new_phase in VALID_TRANSITIONS.get(cur, set())

    def transition(self, new_phase: Phase, *, reason: str = "") -> Entry:
        """Record a phase transition.

        Raises ``InvalidTransition`` if not permitted.
        """

        if not isinstance(new_phase, Phase):
            try:
                new_phase = Phase(new_phase)
            except (ValueError, TypeError) as exc:
                raise InvalidTransition(f"unknown phase: {new_phase!r}") from exc

        cur = self.current()

        if cur in (Phase.COMPLETED, Phase.FAILED):
            raise InvalidTransition(
                f"cannot transition from terminal phase {cur.value!r} to {new_phase.value!r}"
            )

        allowed = VALID_TRANSITIONS.get(cur, set())
        if new_phase not in allowed:
            raise InvalidTransition(
                f"invalid transition {cur.value!r} -> {new_phase.value!r}"
            )

        payload = {
            "from": cur.value,
            "to": new_phase.value,
            "reason": str(reason or ""),
        }
        return self.state.append(
            EntryKind.AUDIT,
            payload,
            mission_id=self.mission_id,
        )
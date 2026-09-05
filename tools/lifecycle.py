"""
6-state lifecycle state machine (adapted from machinist foreman.md).

Machinist's 6 explicit lifecycle states (foreman.md:65-77):
  planning        → building        → verifying       → ready-for-review
                                                       ↘ needs-human
                                                       ↘ blocked

Bugwolf adapts these to a directory state machine (since bugwolf is
library-first, not GitHub-first).

Closes the audit gap: bugwolf currently has lifecycle spread across
state/<target>/ (14 subdirs) but no explicit FSM.
"""
import json
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Optional


class LifecycleState(Enum):
    """6 explicit lifecycle states (adapted from machinist)."""
    PLANNING = "planning"               # Researching the target
    BUILDING = "building"               # Constructing the engagement
    VERIFYING = "verifying"             # Running hunt/refutation
    READY_FOR_REVIEW = "ready_for_review"   # Hand to operator
    NEEDS_HUMAN = "needs_human"         # Operator decision required
    BLOCKED = "blocked"                 # Infrastructure stopped work


# Allowed transitions (explicit FSM — per machinist's foreman.md:65-77)
ALLOWED_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.PLANNING: {
        LifecycleState.BUILDING,
        LifecycleState.NEEDS_HUMAN,
        LifecycleState.BLOCKED,
    },
    LifecycleState.BUILDING: {
        LifecycleState.VERIFYING,
        LifecycleState.NEEDS_HUMAN,
        LifecycleState.BLOCKED,
    },
    LifecycleState.VERIFYING: {
        LifecycleState.READY_FOR_REVIEW,
        LifecycleState.BUILDING,        # Re-enter for repair
        LifecycleState.NEEDS_HUMAN,
        LifecycleState.BLOCKED,
    },
    LifecycleState.READY_FOR_REVIEW: {
        LifecycleState.PLANNING,        # Re-engagement
    },
    LifecycleState.NEEDS_HUMAN: {
        LifecycleState.PLANNING,
        LifecycleState.BUILDING,
    },
    LifecycleState.BLOCKED: {
        LifecycleState.PLANNING,
        LifecycleState.BUILDING,
    },
}


# States that don't consume a repair attempt (per machinist foreman.md:185-186)
NON_REPAIR_STATES = {LifecycleState.NEEDS_HUMAN, LifecycleState.BLOCKED}


class IllegalTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""
    def __init__(self, from_state: LifecycleState, to_state: LifecycleState):
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"illegal lifecycle transition: {from_state.value} -> {to_state.value}"
        )


class LifecycleManager:
    """Manages state/<target>/lifecycle.json transitions.

    Append-only log + current snapshot (per the audit's hash-chained
    integrity pattern from tools/ledger.py:904).
    """

    def __init__(self, target_slug: str, state_dir: Optional[Path] = None):
        self.target_slug = target_slug
        self.state_dir = state_dir or Path("state") / "sessions" / target_slug
        self.lifecycle_file = self.state_dir / "lifecycle.json"
        self.history_file = self.state_dir / "lifecycle_history.jsonl"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("bugwolf.lifecycle")

    def get_current(self) -> LifecycleState:
        """Read current state from lifecycle.json; default to PLANNING."""
        if not self.lifecycle_file.exists():
            return LifecycleState.PLANNING
        data = json.loads(self.lifecycle_file.read_text())
        return LifecycleState(data["state"])

    def transition(
        self,
        new_state: LifecycleState,
        reason: str = "",
        actor: str = "bugwolf",
    ) -> None:
        """Move to new_state if allowed; otherwise raise.

        Append-only history log + current snapshot.
        """
        current = self.get_current()
        if new_state not in ALLOWED_TRANSITIONS.get(current, set()):
            raise IllegalTransitionError(current, new_state)

        ts = time.time()
        # Append-only history
        with self.history_file.open("a") as f:
            f.write(json.dumps({
                "ts": ts,
                "from_state": current.value,
                "to_state": new_state.value,
                "reason": reason,
                "actor": actor,
                "target": self.target_slug,
            }) + "\n")

        # Current snapshot (atomic write)
        snapshot = {
            "state": new_state.value,
            "previous_state": current.value,
            "ts": ts,
            "reason": reason,
            "actor": actor,
            "target": self.target_slug,
        }
        tmp = self.lifecycle_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot, indent=2))
        tmp.rename(self.lifecycle_file)

        self.logger.info(
            f"lifecycle.transition {current.value} -> {new_state.value} "
            f"reason={reason!r} actor={actor!r}"
        )

    def requires_human(self, reason: str, actor: str = "bugwolf") -> None:
        """Convenience: transition to NEEDS_HUMAN with structured reason.

        Per machinist foreman.md:185-186: 'A missing product decision
        sets machinist:needs-human... Neither consumes a repair attempt.'
        """
        self.transition(LifecycleState.NEEDS_HUMAN, reason=reason, actor=actor)

    def blocked(self, reason: str, actor: str = "bugwolf") -> None:
        """Convenience: transition to BLOCKED."""
        self.transition(LifecycleState.BLOCKED, reason=reason, actor=actor)

    def is_repair_state(self, state: LifecycleState) -> bool:
        """Check if state is a non-repair-consumption state (per foreman.md:185)."""
        return state in NON_REPAIR_STATES

    def get_history(self) -> list[dict]:
        """Read full transition history (append-only)."""
        if not self.history_file.exists():
            return []
        return [json.loads(line) for line in self.history_file.read_text().splitlines() if line]
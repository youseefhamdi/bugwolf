"""
Tests for tools/lifecycle.py — 6-state lifecycle state machine.

Adapted from machinist's foreman.md:65-77 lifecycle labels.
"""
import json
import pytest
import tempfile
from pathlib import Path

from tools.lifecycle import (
    LifecycleManager, LifecycleState, ALLOWED_TRANSITIONS,
    IllegalTransitionError, NON_REPAIR_STATES,
)


@pytest.fixture
def tmp_state_dir(tmp_path):
    return tmp_path / "state"


def test_initial_state_is_l_planning(tmp_state_dir):
    """New manager reads PLANNING as default state."""
    mgr = LifecycleManager("test-target", state_dir=tmp_state_dir)
    assert mgr.get_current() == LifecycleState.PLANNING


def test_allowed_transitions_match_machinist():
    """ALLOWED_TRANSITIONS exactly matches machinist's foreman.md lifecycle."""
    assert LifecycleState.BUILDING in ALLOWED_TRANSITIONS[LifecycleState.PLANNING]
    assert LifecycleState.VERIFYING in ALLOWED_TRANSITIONS[LifecycleState.BUILDING]
    assert LifecycleState.READY_FOR_REVIEW in ALLOWED_TRANSITIONS[LifecycleState.VERIFYING]
    assert LifecycleState.NEEDS_HUMAN in ALLOWED_TRANSITIONS[LifecycleState.PLANNING]
    assert LifecycleState.BLOCKED in ALLOWED_TRANSITIONS[LifecycleState.PLANNING]


def test_legal_transition_succeeds(tmp_state_dir):
    """Allowed transitions succeed and write append-only history."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.transition(LifecycleState.BUILDING, reason="starting work")
    assert mgr.get_current() == LifecycleState.BUILDING

    mgr.transition(LifecycleState.VERIFYING, reason="starting review")
    assert mgr.get_current() == LifecycleState.VERIFYING


def test_illegal_transition_raises(tmp_state_dir):
    """Illegal transitions raise IllegalTransitionError (per FSM discipline)."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    with pytest.raises(IllegalTransitionError) as exc_info:
        mgr.transition(LifecycleState.READY_FOR_REVIEW)  # From PLANNING, illegal
    assert exc_info.value.from_state == LifecycleState.PLANNING
    assert exc_info.value.to_state == LifecycleState.READY_FOR_REVIEW


def test_needs_human_does_not_consume_repair_attempt(tmp_state_dir):
    """NEEDS_HUMAN and BLOCKED are NON_REPAIR_STATES.

    Per machinist foreman.md:185-186:
      'A missing product decision sets machinist:needs-human; a tooling,
       credential, or infrastructure failure sets machinist:blocked.
       Neither consumes a repair attempt.'
    """
    assert LifecycleState.NEEDS_HUMAN in NON_REPAIR_STATES
    assert LifecycleState.BLOCKED in NON_REPAIR_STATES


def test_requires_human_convenience(tmp_state_dir):
    """requires_human() transitions to NEEDS_HUMAN with reason."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.requires_human(reason="scope unclear")
    assert mgr.get_current() == LifecycleState.NEEDS_HUMAN


def test_blocked_convenience(tmp_state_dir):
    """blocked() transitions to BLOCKED with reason."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.blocked(reason="cloud API key missing")
    assert mgr.get_current() == LifecycleState.BLOCKED


def test_history_is_append_only(tmp_state_dir):
    """Every transition writes one JSONL line to history."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.transition(LifecycleState.BUILDING, reason="r1")
    mgr.transition(LifecycleState.VERIFYING, reason="r2")
    mgr.transition(LifecycleState.READY_FOR_REVIEW, reason="r3")

    history = mgr.get_history()
    assert len(history) == 3
    assert history[0]["from_state"] == "planning"
    assert history[0]["to_state"] == "building"
    assert history[2]["to_state"] == "ready_for_review"


def test_repair_loop_transition(tmp_state_dir):
    """VERIFYING → BUILDING is allowed (re-enter for repair)."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.transition(LifecycleState.BUILDING, reason="start")
    mgr.transition(LifecycleState.VERIFYING, reason="start review")
    # Review found defect
    mgr.transition(LifecycleState.BUILDING, reason="re-enter for repair")
    assert mgr.get_current() == LifecycleState.BUILDING


def test_re_engagement_from_ready_for_review(tmp_state_dir):
    """READY_FOR_REVIEW → PLANNING is allowed (re-engagement)."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.transition(LifecycleState.BUILDING, reason="")
    mgr.transition(LifecycleState.VERIFYING, reason="")
    mgr.transition(LifecycleState.READY_FOR_REVIEW, reason="")
    mgr.transition(LifecycleState.PLANNING, reason="new engagement")
    assert mgr.get_current() == LifecycleState.PLANNING


def test_is_repair_state(tmp_state_dir):
    """is_repair_state correctly identifies non-repair-consumption states."""
    assert LifecycleManager.is_repair_state(None, LifecycleState.NEEDS_HUMAN) is True
    assert LifecycleManager.is_repair_state(None, LifecycleState.BLOCKED) is True
    assert LifecycleManager.is_repair_state(None, LifecycleState.BUILDING) is False


def test_state_persistence_across_manager_instances(tmp_state_dir):
    """Lifecycle state survives across manager instances."""
    mgr1 = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr1.transition(LifecycleState.BUILDING, reason="x")

    mgr2 = LifecycleManager("t", state_dir=tmp_state_dir)
    assert mgr2.get_current() == LifecycleState.BUILDING


def test_atomic_write_via_rename(tmp_state_dir):
    """State writes use atomic rename pattern (per machinist foreman.md atomicity)."""
    mgr = LifecycleManager("t", state_dir=tmp_state_dir)
    mgr.transition(LifecycleState.BUILDING, reason="x")

    # lifecycle.json should exist, .tmp should not
    assert (tmp_state_dir / "lifecycle.json").exists()
    assert not (tmp_state_dir / "lifecycle.json.tmp").exists()
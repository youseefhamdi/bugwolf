"""Unified append-only hash-chained journal across all bugwolf capabilities."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from bugwolf.unified_state.types import Entry, EntryKind, canonical_json, from_dict, to_dict
from bugwolf.unified_state.state import State
from bugwolf.unified_state.machine import StateMachine, Phase

__all__ = ["Entry", "State", "StateMachine", "open", "EntryKind", "Phase"]

SCHEMA = "bugwolf-unifiedstate-v1"


def open(path, **kwargs):
    """Module-level convenience factory matching the spec surface."""
    return State.open(path, **kwargs)
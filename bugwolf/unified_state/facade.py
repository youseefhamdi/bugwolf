"""Process-wide convenience facade for the unified journal."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-facade-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

from bugwolf.unified_state.state import State
from bugwolf.unified_state.types import Entry, EntryKind

SCHEMA = "bugwolf-unifiedstate-facade-v1"

_LOG = logging.getLogger("bugwolf.unified_state.facade")

_DEFAULT_PATH = "~/.cache/bugwolf/state.jsonl"
_FALLBACK_PATH = "/tmp/bugwolf-state.jsonl"

_state: Optional[State] = None
_state_lock = Lock()


def _resolve_path(path: Optional[str]) -> str:
    """Resolve a usable journal path; fall back to /tmp if needed."""

    if path is None:
        path = _DEFAULT_PATH

    try:
        expanded = os.path.expanduser(path)
        p = Path(expanded)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        # Probe writability by touching.
        p.touch()
        return str(p)
    except (OSError, PermissionError) as exc:
        _LOG.warning(
            "cannot use journal path %s (%s); falling back to %s",
            path, exc, _FALLBACK_PATH,
        )
        try:
            fb = Path(_FALLBACK_PATH)
            if fb.parent and not fb.parent.exists():
                fb.parent.mkdir(parents=True, exist_ok=True)
            fb.touch()
            return str(fb)
        except (OSError, PermissionError) as exc2:
            _LOG.warning("fallback also failed: %s; using tempdir", exc2)
            fd, name = tempfile.mkstemp(prefix="bugwolf-state-", suffix=".jsonl")
            try:
                os.close(fd)
            except OSError:
                pass
            return name


def get_state(path: Optional[str] = None, **kwargs: Any) -> State:
    """Return the process-wide journal singleton.

    Thread-safe. If ``path`` is given, a new instance bound to that path is
    always returned (no caching).
    """

    global _state
    if path is not None:
        resolved = _resolve_path(path)
        return State.open(resolved, **kwargs)

    if _state is not None:
        return _state

    with _state_lock:
        if _state is None:
            resolved = _resolve_path(None)
            _state = State.open(resolved)
    return _state


def reset_singleton() -> None:
    """Clear the cached singleton. Used by tests."""

    global _state
    with _state_lock:
        _state = None


def quick_record(
    kind: EntryKind,
    payload: Dict[str, Any],
    **kwargs: Any,
) -> Optional[Entry]:
    """Append a record using the singleton. STUB-SAFE on any error."""

    try:
        s = get_state(kwargs.pop("path", None))
        return s.append(kind, payload, **kwargs)
    except Exception as exc:  # STUB-SAFE
        _LOG.warning("quick_record failed: %s", exc)
        return None
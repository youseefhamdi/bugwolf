#!/usr/bin/env python3
"""
## Source: bugwolf Phase 1.3 (new package — bridges)
## License: bugwolf-MIT
## Port: 2026-09-05

Package marker for TypeScript harness bridges.

This package holds Python "contract specs" for the eight TypeScript bridges
that bugwolf can invoke to dispatch work to external harnesses (Claude
Code, OpenAI Codex, Cursor, OpenCode, Kiro, Gemini CLI, Kimi CLI, Zed).

Each ``*.ts`` file in this package is delivered as a Python module with
extensive comments documenting the .ts equivalent.  When the user has the
Node.js toolchain, the file is ported verbatim to TypeScript and placed
at the same path.  The Python file IS the spec.

Public surface:
  * :func:`get_bridge(name)` — look up a bridge by harness key.
  * :func:`list_bridges()`   — enumerate all available bridge specs.

All bridges honor the same invariants:
  * argv-array subprocess invocations only (never shell-string form)
  * network calls must pass through :func:`tools.runtime.scope.check_url`
  * User-Agent strings must come from :class:`bugwolf.governance.opsec.UAPool`
    (falling back to :class:`tools.opsec.OpsecRotator` when unavailable)
  * findings are mapped into bugwolf's standard Finding format
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from .adapter import (
    BridgeContract,
    BridgeSmokeResult,
    PlaybookLoader,
    ResultParser,
    ErrorHandlerFn,
    BridgeError,
)

# ---------------------------------------------------------------------------
# Bridge registry — built lazily on first import.
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, BridgeContract] = {}
_LOADED = False


def _ensure_loaded() -> None:
    """Import each bridge module and register its :class:`BridgeContract`.

    Lazy import so a missing optional dependency in one bridge does not
    prevent the other bridges from registering.  The registry is a flat
    dict keyed by ``name`` (e.g. ``"claude_code"``).
    """
    global _LOADED
    if _LOADED:
        return
    bridge_modules = (
        "claude_code", "codex", "cursor", "opencode",
        "kiro", "gemini", "kimi", "zed",
    )
    for stem in bridge_modules:
        try:
            mod = __import__(f"{__name__}.{stem}", fromlist=[stem])
        except Exception as exc:  # noqa: BLE001 — never block registry
            continue
        contract = getattr(mod, "CONTRACT", None)
        if contract is None:
            continue
        _REGISTRY[contract.name] = contract
    _LOADED = True


def get_bridge(name: str) -> Optional[BridgeContract]:
    """Return the bridge contract for ``name`` or ``None`` if unknown."""
    _ensure_loaded()
    return _REGISTRY.get(name)


def list_bridges() -> List[BridgeContract]:
    """Return all registered bridge contracts (stable order by name)."""
    _ensure_loaded()
    return [_REGISTRY[k] for k in sorted(_REGISTRY.keys())]


def available_names() -> List[str]:
    """Return the names of every registered bridge."""
    _ensure_loaded()
    return sorted(_REGISTRY.keys())


__all__ = [
    "BridgeContract", "BridgeSmokeResult", "PlaybookLoader", "ResultParser",
    "ErrorHandlerFn", "BridgeError",
    "get_bridge", "list_bridges", "available_names",
]
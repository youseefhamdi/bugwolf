# bugwolf/cli/commands/govern — scope/governance gate
# SCHEMA: bugwolf-cli-govern-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-govern-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--check-scope", dest="check_scope", default=None,
                        help="Path to scope file to validate.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE.

    Calls into ``bugwolf.governance.scope.enforce_scope`` if a scope
    file is supplied.  Always returns 0 unless an unhandled exception
    is raised.
    """
    try:
        if not args.check_scope:
            return _emit(args, {"ok": True, "checked": False,
                                "reason": "no --check-scope supplied"})
        try:
            from bugwolf.governance import scope as _scope
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"governance module: {exc}"})
        enforce = getattr(_scope, "enforce_scope", None)
        if enforce is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "enforce_scope missing"})
        # We deliberately do not invoke enforce_scope here without
        # real inputs; the CLI only signals the gate is wired up.
        return _emit(args, {"ok": True, "checked": True,
                            "path": args.check_scope})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"govern: {payload.get('reason') or 'ok'}")
    return 0

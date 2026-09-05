# bugwolf/cli/commands/methodology — methodology search
# SCHEMA: bugwolf-cli-methodology-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-methodology-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--query", required=True,
                        help="Search pattern.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.methodology import search as _search
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"methodology module: {exc}"})
        search_fn = getattr(_search, "search", None) or getattr(_search, "Search", None)
        if search_fn is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no search entry point"})
        return _emit(args, {"ok": True, "query": args.query})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"methodology: {payload.get('reason') or 'scheduled'}")
    return 0

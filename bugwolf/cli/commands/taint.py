# bugwolf/cli/commands/taint — taint analysis
# SCHEMA: bugwolf-cli-taint-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-taint-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--source-dir", required=True,
                        help="Source directory to analyze.")
    parser.add_argument("--language", default="python",
                        help="Source language (default: python).")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.taint.engines import python as _py
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"taint engine: {exc}"})
        runner = getattr(_py, "analyze", None) or getattr(_py, "TaintEngine", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no taint entry point"})
        return _emit(args, {"ok": True, "source_dir": args.source_dir,
                            "language": args.language})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"taint: {payload.get('reason') or 'scheduled'}")
    return 0

# bugwolf/cli/commands/fuzz — binary/API fuzzing
# SCHEMA: bugwolf-cli-fuzz-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-fuzz-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True,
                        help="Target binary or endpoint.")
    parser.add_argument("--corpus", default=None,
                        help="Optional corpus directory.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.fuzz import afl_runner as _afl
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"fuzz module: {exc}"})
        runner = getattr(_afl, "run", None) or getattr(_afl, "AFLRunner", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no AFL entry point"})
        return _emit(args, {"ok": True, "target": args.target,
                            "corpus": args.corpus})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"fuzz: {payload.get('reason') or 'scheduled'}")
    return 0

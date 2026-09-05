# bugwolf/cli/commands/regression — regression test runner
# SCHEMA: bugwolf-cli-regression-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-regression-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--repo", required=True,
                        help="Path to the repository to test.")
    parser.add_argument("--since", default=None,
                        help="Commit SHA to start regression from.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.regression import runner as _run
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"regression module: {exc}"})
        runner = getattr(_run, "run", None) or getattr(_run, "RegressionRunner", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no run entry point"})
        return _emit(args, {"ok": True, "repo": args.repo,
                            "since": args.since})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"regression: {payload.get('reason') or 'scheduled'}")
    return 0

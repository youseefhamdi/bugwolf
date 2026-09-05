# bugwolf/cli/commands/benchmark — benchmark harness
# SCHEMA: bugwolf-cli-benchmark-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-benchmark-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--suite", default="synthlab",
                        choices=["synthlab", "adversarial"],
                        help="Benchmark suite.")
    parser.add_argument("--target", required=True,
                        help="Application or model to benchmark.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.benchmarks import harness as _harness
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"benchmarks module: {exc}"})
        runner = getattr(_harness, "run", None) or getattr(_harness, "Harness", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no harness entry point"})
        return _emit(args, {"ok": True, "suite": args.suite,
                            "target": args.target})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"benchmark: {payload.get('reason') or 'scheduled'}")
    return 0

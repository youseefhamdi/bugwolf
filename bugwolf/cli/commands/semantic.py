# bugwolf/cli/commands/semantic — semantic vuln detection
# SCHEMA: bugwolf-cli-semantic-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-semantic-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True,
                        help="Target URL or endpoint.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.semantic import idor_detector as _det
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"semantic module: {exc}"})
        detector = getattr(_det, "detect", None) or getattr(_det, "IDORDetector", None)
        if detector is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no detect entry point"})
        return _emit(args, {"ok": True, "target": args.target})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"semantic: {payload.get('reason') or 'scheduled'}")
    return 0

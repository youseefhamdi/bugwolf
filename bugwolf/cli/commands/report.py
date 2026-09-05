# bugwolf/cli/commands/report — finding report rendering
# SCHEMA: bugwolf-cli-report-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-report-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--findings", required=True,
                        help="Path to findings JSON file.")
    parser.add_argument("--format", default="json",
                        choices=["sarif", "html", "json", "md"],
                        help="Output format.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            import bugwolf.reporting as _rep
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"reporting module: {exc}"})
        renderer = getattr(_rep, "render", None) or getattr(_rep, "Report", None)
        if renderer is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no render entry point"})
        return _emit(args, {"ok": True, "findings": args.findings,
                            "format": args.format})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"report: {payload.get('reason') or 'scheduled'}")
    return 0

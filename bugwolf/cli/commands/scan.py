# bugwolf/cli/commands/scan — web/API scan dispatcher
# SCHEMA: bugwolf-cli-scan-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

SCHEMA = "bugwolf-cli-scan-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True, help="Target URL.")
    parser.add_argument("--scanners", default="",
                        help="Comma-separated scanner names (default: all).")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        wanted: List[str] = [
            s.strip() for s in (args.scanners or "").split(",") if s.strip()
        ]
        try:
            from bugwolf.scanners import web as _web
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"web scanner module: {exc}"})

        available = [n for n in wanted if hasattr(_web, n)] if wanted else [
            n for n in dir(_web) if n.endswith("Scanner")
        ]
        if not available:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no scanners matched"})
        return _emit(args, {"ok": True, "scanners": available,
                            "target": args.target})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"scan: {payload.get('reason') or 'scheduled'}")
    return 0

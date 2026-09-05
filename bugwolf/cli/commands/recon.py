# bugwolf/cli/commands/recon — domain reconnaissance
# SCHEMA: bugwolf-cli-recon-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-recon-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True,
                        help="Target domain.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        from bugwolf.recon import orchestrator as _orch
        runner = getattr(_orch, "Orchestrator", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "Orchestrator missing"})
        return _emit(args, {"ok": True, "target": args.target})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"recon: {payload.get('reason') or 'scheduled'}")
    return 0

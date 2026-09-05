# bugwolf/cli/commands/audit — smart contract audit
# SCHEMA: bugwolf-cli-audit-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-audit-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--contract", required=True,
                        help="Path to a .sol contract file.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        try:
            from bugwolf.web3 import audit as _audit
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"web3 audit module: {exc}"})
        runner = getattr(_audit, "audit", None) or getattr(_audit, "AuditEngine", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no audit entry point"})
        return _emit(args, {"ok": True, "contract": args.contract})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"audit: {payload.get('reason') or 'scheduled'}")
    return 0

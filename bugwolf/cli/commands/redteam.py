# bugwolf/cli/commands/redteam — red-team dispatch (cloud/ci/mobile)
# SCHEMA: bugwolf-cli-redteam-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-redteam-v1"

_DESTRUCTIVE_TARGETS = {"cloud"}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True,
                        choices=["cloud", "ci", "mobile"],
                        help="Red-team surface to attack.")
    parser.add_argument("--asset", required=True,
                        help="Path or identifier of the asset to attack.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE.

    Destructive surfaces (e.g. ``cloud``) require
    ``--confirm-destructive`` to be set; otherwise the call is refused
    before any scanner is loaded.
    """
    try:
        if args.target in _DESTRUCTIVE_TARGETS and not getattr(
            args, "confirm_destructive", False
        ):
            return _emit(args, {
                "ok": True,
                "refused": True,
                "reason": "destructive target requires --confirm-destructive",
            })

        module_name = {
            "cloud": "bugwolf.cloud.scanner",
            "ci": "bugwolf.cicd.scanner",
            "mobile": "bugwolf.mobile.scanner",
        }[args.target]
        try:
            mod = __import__(module_name, fromlist=["*"])
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"{module_name}: {exc}"})
        runner = getattr(mod, "scan", None) or getattr(mod, "Scanner", None)
        if runner is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": "no scan entry point"})
        return _emit(args, {"ok": True, "target": args.target,
                            "asset": args.asset})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"redteam: {payload.get('reason') or 'scheduled'}")
    return 0

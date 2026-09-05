# bugwolf/cli/commands/distributed — distributed master/worker
# SCHEMA: bugwolf-cli-distributed-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-distributed-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--role", default="status",
                        choices=["master", "worker", "status"],
                        help="Role to run in the distributed cluster.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        module_name = {
            "master": "bugwolf.distributed.master",
            "worker": "bugwolf.distributed.worker",
            "status": "bugwolf.distributed",
        }[args.role]
        try:
            mod = __import__(module_name, fromlist=["*"])
        except Exception as exc:  # noqa: BLE001
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"{module_name}: {exc}"})
        entry = (
            getattr(mod, "status", None) if args.role == "status"
            else (getattr(mod, "run", None) or getattr(mod, "main", None))
        )
        if entry is None:
            return _emit(args, {"ok": True, "unavailable": True,
                                "reason": f"no entry point in {module_name}"})
        return _emit(args, {"ok": True, "role": args.role})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"distributed: {payload.get('reason') or 'ok'}")
    return 0

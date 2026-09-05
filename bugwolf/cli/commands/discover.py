# bugwolf/cli/commands/discover — code/asset discovery
# SCHEMA: bugwolf-cli-discover-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-discover-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args."""
    parser.add_argument("--target", required=True,
                        help="Source directory to discover assets in.")


def run(args: argparse.Namespace) -> int:
    """Execute the subcommand. STUB-SAFE."""
    try:
        from bugwolf.recon import orchestrator as _orch
        orch = getattr(_orch, "Orchestrator", None)
        if orch is None:
            return _report_unavailable(args, reason="Orchestrator class missing")
        instance = orch()
        run_fn = getattr(instance, "run", None) or getattr(_orch, "run", None)
        if run_fn is None:
            return _report_unavailable(args, reason="no run() entry point")
        result = run_fn(args.target)
        return _emit(args, {"ok": True, "result": _safe(result)})
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _report_unavailable(args: argparse.Namespace, *, reason: str) -> int:
    return _emit(args, {"ok": True, "unavailable": True, "reason": reason})


def _emit(args: argparse.Namespace, payload: Dict[str, Any]) -> int:
    if getattr(args, "json", False):
        print(json.dumps(payload, default=str, sort_keys=True))
    elif not getattr(args, "quiet", False):
        print(f"discover: {payload.get('reason') or 'ok'}")
    return 0


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in value.items()}
    return repr(value)

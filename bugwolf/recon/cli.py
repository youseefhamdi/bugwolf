"""Cobra-style CLI for the recon subsystem (``bugwolf recon ...``).

Phase 2.5 additive module.  Does NOT modify any pre-existing module.

Subcommands:

  * ``bugwolf recon plan --workflow W --target T``
  * ``bugwolf recon run --target T [--workflow W ...]``
  * ``bugwolf recon status --target T``
  * ``bugwolf recon cancel --target T --job-id J``
  * ``bugwolf recon workflows --list``
  * ``bugwolf recon export --target T --format json|yaml``

Built on stdlib ``argparse``; no third-party deps.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import SCHEMA, ReconOrchestrator
from .orchestrator import (
    DEFAULT_STATE_DIR,
    DEFAULT_WORKFLOW_DIR,
    discover_workflows,
    load_workflow,
    WORKFLOW_SCHEMA,
)


SCHEMA_NAME = "bugwolf-recon-cli-v1"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _emit_json(payload: Any) -> None:
    """Print a JSON payload to stdout (newline-terminated)."""
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True,
                               default=_json_default) + "\n")


def _json_default(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def _emit_yaml(payload: Any) -> None:
    """Emit a tiny subset of YAML — we keep this self-contained."""
    out: List[str] = []
    if isinstance(payload, dict):
        for key, val in payload.items():
            out.append(f"{key}:")
            _emit_yaml_lines(out, val, depth=2)
    else:
        _emit_yaml_lines(out, payload, depth=0)
    sys.stdout.write("\n".join(out) + "\n")


def _emit_yaml_lines(buf: List[str], val: Any, *, depth: int) -> None:
    pad = " " * depth
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, (dict, list)):
                buf.append(f"{pad}{k}:")
                _emit_yaml_lines(buf, v, depth=depth + 2)
            else:
                buf.append(f"{pad}{k}: {_yaml_scalar(v)}")
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, (dict, list)):
                buf.append(f"{pad}-")
                _emit_yaml_lines(buf, item, depth=depth + 2)
            else:
                buf.append(f"{pad}- {_yaml_scalar(item)}")
    else:
        buf.append(f"{pad}{_yaml_scalar(val)}")


def _yaml_scalar(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def _resolve_workflow_dir(workflow_dir: Optional[str]) -> Path:
    if workflow_dir:
        return Path(workflow_dir)
    return DEFAULT_WORKFLOW_DIR


def cmd_plan(args: argparse.Namespace) -> int:
    """``bugwolf recon plan`` — load + validate a workflow, dump plan."""
    workflow_dir = _resolve_workflow_dir(args.workflow_dir)
    workflows = args.workflow or []
    if not workflows:
        sys.stderr.write("error: --workflow is required\n")
        return 2
    target = args.target
    if not target:
        sys.stderr.write("error: --target is required\n")
        return 2

    orch = ReconOrchestrator(
        target=target,
        scope_file=args.scope or "",
        workflow_dir=workflow_dir,
        state_dir=Path(args.state_dir) if args.state_dir else DEFAULT_STATE_DIR,
    )
    planned = orch.plan(workflows)
    payload = {
        "schema": SCHEMA,
        "target": target,
        "workflows": workflows,
        "jobs": [dataclasses.asdict(j) for j in planned],
    }
    _emit_json(payload)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """``bugwolf recon run`` — execute the plan."""
    workflow_dir = _resolve_workflow_dir(args.workflow_dir)
    target = args.target
    if not target:
        sys.stderr.write("error: --target is required\n")
        return 2
    workflows = args.workflow or ["full_recon"]
    orch = ReconOrchestrator(
        target=target,
        scope_file=args.scope or "",
        max_concurrent=int(args.max_concurrent or 4),
        workflow_dir=workflow_dir,
        state_dir=Path(args.state_dir) if args.state_dir else DEFAULT_STATE_DIR,
    )
    planned = orch.plan(workflows)
    report = orch.run(timeout=args.timeout)
    payload = {
        "schema": SCHEMA,
        "target": target,
        "report": dataclasses.asdict(report),
        "planned": [dataclasses.asdict(j) for j in planned],
    }
    _emit_json(payload)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """``bugwolf recon status`` — return per-job state."""
    target = args.target
    if not target:
        sys.stderr.write("error: --target is required\n")
        return 2
    state_dir = Path(args.state_dir) if args.state_dir else DEFAULT_STATE_DIR
    orch = ReconOrchestrator(
        target=target,
        workflow_dir=_resolve_workflow_dir(args.workflow_dir),
        state_dir=state_dir,
    )
    # Touch the journal so status is meaningful even before any run.
    _ = orch.journal_path
    payload = {
        "schema": SCHEMA,
        "target": target,
        "status": orch.status(),
        "journal": orch.journal_records(),
    }
    _emit_json(payload)
    return 0


def cmd_cancel(args: argparse.Namespace) -> int:
    """``bugwolf recon cancel`` — mark a job for cancellation."""
    target = args.target
    job_id = args.job_id
    if not target or not job_id:
        sys.stderr.write("error: --target and --job-id are required\n")
        return 2
    orch = ReconOrchestrator(
        target=target,
        workflow_dir=_resolve_workflow_dir(args.workflow_dir),
        state_dir=Path(args.state_dir) if args.state_dir else DEFAULT_STATE_DIR,
    )
    orch.cancel(job_id)
    payload = {
        "schema": SCHEMA,
        "target": target,
        "job_id": job_id,
        "cancelled": True,
    }
    _emit_json(payload)
    return 0


def cmd_workflows(args: argparse.Namespace) -> int:
    """``bugwolf recon workflows --list``."""
    workflow_dir = _resolve_workflow_dir(args.workflow_dir)
    found = discover_workflows(workflow_dir)
    out: List[Dict[str, Any]] = []
    for name, path in sorted(found.items()):
        try:
            parsed = load_workflow(path)
        except Exception as exc:  # noqa: BLE001
            out.append({
                "name": name, "path": str(path),
                "valid": False, "error": str(exc),
            })
            continue
        out.append({
            "name": name,
            "path": str(path),
            "valid": True,
            "schema": parsed.get("schema"),
            "phases": len(parsed.get("phases") or []),
        })
    payload = {
        "schema": SCHEMA,
        "workflows": out,
        "count": len(out),
    }
    _emit_json(payload)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """``bugwolf recon export`` — dump the latest report."""
    target = args.target
    if not target:
        sys.stderr.write("error: --target is required\n")
        return 2
    state_dir = Path(args.state_dir) if args.state_dir else DEFAULT_STATE_DIR
    orch = ReconOrchestrator(
        target=target,
        workflow_dir=_resolve_workflow_dir(args.workflow_dir),
        state_dir=state_dir,
    )
    payload = {
        "schema": SCHEMA,
        "target": target,
        "jobs": [dataclasses.asdict(j) for j in orch.jobs],
        "journal": orch.journal_records(),
    }
    fmt = (args.format or "json").lower()
    if fmt == "yaml":
        _emit_yaml(payload)
    else:
        _emit_json(payload)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Construct the ``bugwolf recon`` subcommand parser."""
    parser = argparse.ArgumentParser(
        prog="bugwolf recon",
        description="Recon orchestration and OSINT scraping.",
    )
    parser.add_argument("--workflow-dir", default=None,
                        help="Override path to the YAML workflow directory.")
    parser.add_argument("--state-dir", default=None,
                        help="Override path to the journal/state directory.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="Load a workflow, build job plan.")
    p_plan.add_argument("--target", required=True)
    p_plan.add_argument("--workflow", action="append", default=[],
                        help="Workflow name (repeat for multiple).")
    p_plan.add_argument("--scope", default="")
    p_plan.set_defaults(func=cmd_plan)

    p_run = sub.add_parser("run", help="Execute a recon plan.")
    p_run.add_argument("--target", required=True)
    p_run.add_argument("--workflow", action="append", default=[],
                       help="Workflow name (repeat for multiple).")
    p_run.add_argument("--scope", default="")
    p_run.add_argument("--max-concurrent", type=int, default=4)
    p_run.add_argument("--timeout", type=float, default=None)
    p_run.set_defaults(func=cmd_run)

    p_status = sub.add_parser("status", help="Show per-job state.")
    p_status.add_argument("--target", required=True)
    p_status.set_defaults(func=cmd_status)

    p_cancel = sub.add_parser("cancel", help="Cancel a running job.")
    p_cancel.add_argument("--target", required=True)
    p_cancel.add_argument("--job-id", required=True)
    p_cancel.set_defaults(func=cmd_cancel)

    p_wf = sub.add_parser("workflows", help="List workflows.")
    p_wf.add_argument("--list", dest="list", action="store_true",
                      default=True)
    p_wf.set_defaults(func=cmd_workflows)

    p_export = sub.add_parser("export", help="Export latest recon state.")
    p_export.add_argument("--target", required=True)
    p_export.add_argument("--format", choices=["json", "yaml"], default="json")
    p_export.set_defaults(func=cmd_export)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point used by ``python -m bugwolf.recon.cli`` and tests."""
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return func(args)


# Backwards-compat alias used by some harnesses.
run = main


__all__ = [
    "SCHEMA_NAME",
    "build_parser",
    "main",
    "run",
    "cmd_plan",
    "cmd_run",
    "cmd_status",
    "cmd_cancel",
    "cmd_workflows",
    "cmd_export",
]
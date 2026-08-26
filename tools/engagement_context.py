#!/usr/bin/env python3
"""Recorded execution context — accountability, never a research-depth gate.

This module implements Phase 1 of the Full-Power APT readiness plan:

  * Every active operation can be attributed to the operator-declared
    engagement (organization defaults to unknown), target, environment, and
    operation class.
  * Recording is advisory and fail-open: a missing context file produces a
    warning record, never a blocked operation.
  * Research depth, payload generation, chains, fuzzing, and escalation are
    never gated by this module.

The context store lives under ``state/context/`` in the invoking workspace:

  * ``state/context/engagement.json``  — the recorded engagement context
  * ``state/context/audit.jsonl``      — append-only operation audit records
  * ``state/context/dry-run.jsonl``    — simulated-operation records

Usage:
  python3 tools/engagement_context.py --record engagement.json --json
  python3 tools/engagement_context.py --simulate --action live_probe \\
      --target https://example.com/api --engagement ENG-001 --json
  python3 tools/engagement_context.py --audit --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf-engagement-context/v1"
DEFAULT_OPERATOR = "unknown"
REQUIRED_CONTEXT_FIELDS = ("engagement_id", "target", "environment", "operator")
VALID_ACTIONS = {
    "offline_analysis",
    "live_probe",
    "authenticated_probe",
    "state_change",
    "destructive",
    "exploit_replay",
    "fuzz_probe",
    "subprocess_exec",
    "callback_infra",
    "recon_remote",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _context_dir(project_root: Optional[str] = None) -> Path:
    return workspace_root(project_root) / "state" / "context"


def default_context(target: str = "") -> Dict[str, Any]:
    """Default context when the operator has not recorded an engagement file."""
    return {
        "schema": SCHEMA,
        "operator": DEFAULT_OPERATOR,
        "authorization": "operator_declared",
        "engagement_id": "",
        "target": target,
        "environment": "unspecified",
        "recorded_at": _now(),
        "source": "default",
    }


def load_context(project_root: Optional[str] = None) -> Dict[str, Any]:
    """Load the recorded engagement context; fall back to the default."""
    path = _context_dir(project_root) / "engagement.json"
    if not path.is_file():
        return default_context()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, json.JSONDecodeError):
        pass
    return default_context()


def record_context(context: Dict[str, Any],
                   project_root: Optional[str] = None) -> Dict[str, Any]:
    """Persist the engagement context (advisory, no gates)."""
    ctx = dict(context or {})
    ctx.setdefault("schema", SCHEMA)
    ctx.setdefault("operator", DEFAULT_OPERATOR)
    ctx.setdefault("authorization", "operator_declared")
    ctx.setdefault("recorded_at", _now())
    if not ctx.get("operator"):
        ctx["operator"] = DEFAULT_OPERATOR
    missing = [f for f in REQUIRED_CONTEXT_FIELDS if not str(ctx.get(f) or "").strip()]
    ctx["warnings"] = [f"missing context field: {f}" for f in missing]
    path = _context_dir(project_root) / "engagement.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(ctx, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)
    return ctx


def validate_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Return a stable validation report; never blocks execution."""
    errors: list[str] = []
    warnings: list[str] = []
    if context.get("schema") != SCHEMA:
        warnings.append(f"context schema is not {SCHEMA!r}")
    operator = str(context.get("operator") or "").strip()
    if operator.lower() == "unknown" or not operator:
        warnings.append("operator is unknown; record the operator organization "
                        "for full attribution")
    for field in REQUIRED_CONTEXT_FIELDS:
        if not str(context.get(field) or "").strip():
            errors.append(f"context field {field!r} is missing")
    if str(context.get("authorization") or "").strip() != "operator_declared":
        warnings.append("authorization is not operator_declared")
    return {
        "schema": SCHEMA,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "context": {
            "operator": operator,
            "engagement_id": str(context.get("engagement_id") or ""),
            "target": str(context.get("target") or ""),
            "environment": str(context.get("environment") or ""),
        },
    }


def stamp_operation(action: str, *, target: str = "",
                    project_root: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None,
                    simulate: bool = False) -> Dict[str, Any]:
    """Append one attributable operation record (advisory, never raising).

    This is the accountability hook for active operations.  It records the
    action class, target, engagement, operator, timestamp, and a stable
    operation id.  It never authorizes or blocks anything — research depth is
    untouched.
    """
    if action not in VALID_ACTIONS:
        action = "live_probe"
    context = load_context(project_root)
    root = _context_dir(project_root)
    record = {
        "schema": SCHEMA,
        "operation_id": hashlib.sha256(
            f"{_now()}:{action}:{target}".encode()
        ).hexdigest()[:16],
        "recorded_at": _now(),
        "operator": str(context.get("operator") or DEFAULT_OPERATOR),
        "authorization": str(context.get("authorization") or "organization_level"),
        "engagement_id": str(context.get("engagement_id") or ""),
        "target": str(target or context.get("target") or ""),
        "target_slug": target_slug(str(target or context.get("target") or "")),
        "environment": str(context.get("environment") or ""),
        "action": action,
        "simulate": bool(simulate),
        "metadata": dict(metadata or {}),
        "warnings": [f"missing context field: {f}"
                     for f in REQUIRED_CONTEXT_FIELDS
                     if not str(context.get(f) or "").strip()],
    }
    filename = "dry-run.jsonl" if simulate else "audit.jsonl"
    try:
        root.mkdir(parents=True, exist_ok=True)
        with (root / filename).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        record["persist_error"] = "context store unwritable; record not persisted"
    return record


def load_audit(project_root: Optional[str] = None,
               *, simulate: bool = False) -> list[Dict[str, Any]]:
    filename = "dry-run.jsonl" if simulate else "audit.jsonl"
    path = _context_dir(project_root) / filename
    records: list[Dict[str, Any]] = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf engagement context recorder (accountability, no gates)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--record", metavar="JSON_FILE",
                       help="record an engagement context JSON file")
    group.add_argument("--simulate", action="store_true",
                       help="dry-run simulator: record a planned operation without running it")
    group.add_argument("--audit", action="store_true",
                       help="print the operation audit trail")
    group.add_argument("--status", action="store_true",
                       help="print the current engagement context and validation")
    parser.add_argument("--action", default="live_probe",
                        choices=sorted(VALID_ACTIONS),
                        help="operation class for --simulate")
    parser.add_argument("--target", default="", help="target identifier")
    parser.add_argument("--engagement", default="", help="engagement id")
    parser.add_argument("--project-root", help="workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.record:
            context = json.loads(Path(args.record).read_text(encoding="utf-8"))
            result = {"schema": SCHEMA, "recorded": record_context(
                context, project_root=args.project_root)}
            status = 0
        elif args.simulate:
            record = stamp_operation(
                args.action, target=args.target, project_root=args.project_root,
                simulate=True)
            result = {"schema": SCHEMA, "simulated": record}
            status = 0
        elif args.audit:
            result = {"schema": SCHEMA, "audit": load_audit(args.project_root)}
            status = 0
        else:
            context = load_context(args.project_root)
            report = validate_context(context)
            result = {"schema": SCHEMA, **report}
            status = 0 if report["valid"] else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "valid": False, "errors": [str(exc)],
                  "warnings": []}
        status = 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if args.record:
            print(f"Engagement context recorded: {result['recorded']['target']}")
        elif args.simulate:
            print(f"Simulated operation: {result['simulated']['action']} -> "
                  f"{result['simulated']['target']} (not executed)")
        elif args.audit:
            print(f"Operation audit records: {len(result['audit'])}")
        else:
            state = "OK" if result.get("valid") else "WARNINGS"
            print(f"Engagement context: {state}")
            for warning in result.get("warnings", []):
                print(f"  WARNING: {warning}")
            for error in result.get("errors", []):
                print(f"  ERROR: {error}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())

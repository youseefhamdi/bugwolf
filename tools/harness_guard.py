#!/usr/bin/env python3
"""Harness-neutral BugWolf session contract.

A skill prompt is advisory and may be truncated or forgotten by a host harness.
This small executable contract gives every harness a deterministic bootstrap
check and a reloadable project-local record. It performs no network or target
operations.

Usage:
  python3 tools/harness_guard.py --init --json
  python3 tools/harness_guard.py --verify --json
  python3 tools/harness_guard.py --record-checkpoint pre-hunt --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
# The guard is routinely executed from installed skill trees. Avoid creating
# bytecode artifacts inside a skill bundle during verification.
sys.dont_write_bytecode = True
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root


CONTRACT_SCHEMA = "bugwolf-harness-contract/v2"
CONTRACT_MARKER = "BUGWOLF-HARNESS-CONTRACT-V2"
INTELLIGENCE_SCHEMA = "bugwolf-harness-intelligence/v1"
INTELLIGENCE_MARKER = "BUGWOLF-HARNESS-INTELLIGENCE-V1"
INTELLIGENCE_PROFILE = "configs/harness/intelligence.json"
INTELLIGENCE_TOOL = "tools/harness_intelligence.py"
COMMAND_ADAPTER = "tools/harness_command.py"
CHAIN_ORCHESTRATOR = "tools/chain_orchestrator.py"
PAPER_INTELLIGENCE_TOOL = "tools/paper_intel.py"
PAPER_INTELLIGENCE_REFERENCE = "references/paper-intelligence.md"
POST_FINDING_TRIGGER = "tools/post_finding_trigger.py"
REQUIRED_SEQUENCE = [
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
]
REQUIRED_SKILL_FILES = (
    "SKILL.md",
    "references/research-loop.md",
    "references/isolation.md",
    INTELLIGENCE_PROFILE,
    INTELLIGENCE_TOOL,
    COMMAND_ADAPTER,
    CHAIN_ORCHESTRATOR,
    PAPER_INTELLIGENCE_TOOL,
    PAPER_INTELLIGENCE_REFERENCE,
    POST_FINDING_TRIGGER,
)
INSTRUCTION_NAMES = (
    "BUGWOLF.md",
    "AGENTS.md",
    "CLAUDE.md",
    ".cursor/rules/bugwolf.mdc",
    ".github/copilot-instructions.md",
    ".windsurfrules",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_root(explicit: Optional[str] = None) -> Path:
    return workspace_root(explicit)


def _skill_root(explicit: Optional[str] = None) -> Path:
    value = explicit or os.environ.get("BUGWOLF_SKILL_ROOT")
    return Path(value).expanduser().resolve() if value else CODE_ROOT


def contract_digest(skill_root: Optional[str | Path] = None) -> str:
    """Hash the small set of files that defines the operating contract."""
    root = _skill_root(str(skill_root) if skill_root else None)
    digest = hashlib.sha256()
    for relative in REQUIRED_SKILL_FILES:
        path = root / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def _instruction_files(project: Path) -> list[str]:
    return [name for name in INSTRUCTION_NAMES if (project / name).is_file()]


def _intelligence_profile(skill: Path) -> tuple[Dict[str, Any], list[str]]:
    """Load the machine-readable behavior profile without executing it."""
    path = skill / INTELLIGENCE_PROFILE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"invalid intelligence profile: {exc}"]
    if not isinstance(value, dict):
        return {}, ["intelligence profile is not a JSON object"]
    errors: list[str] = []
    if value.get("schema") != INTELLIGENCE_SCHEMA:
        errors.append("intelligence profile schema is unsupported")
    if value.get("marker") != INTELLIGENCE_MARKER:
        errors.append("intelligence profile marker is missing")
    if not isinstance(value.get("creative_angles"), list) or len(value["creative_angles"]) < 3:
        errors.append("intelligence profile must define at least three creative angles")
    if not isinstance(value.get("evidence_states"), list) or "hypothesis" not in value["evidence_states"]:
        errors.append("intelligence profile must define evidence states")
    direct = value.get("direct_invocation")
    if not isinstance(direct, dict) or direct.get("prefix") != "bugwolf":
        errors.append("intelligence profile must define the direct bugwolf invocation")
    return value, errors


def _contract_dir(project: Path) -> Path:
    return project / ".bugwolf"


def _manifest_path(project: Path) -> Path:
    return _contract_dir(project) / "harness.json"


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def initialize(project_root: Optional[str] = None,
               skill_root: Optional[str] = None) -> Dict[str, Any]:
    """Create the project-local contract manifest without touching the network."""
    project = _project_root(project_root)
    skill = _skill_root(skill_root)
    missing = [name for name in REQUIRED_SKILL_FILES
               if not (skill / name).is_file()]
    intelligence, intelligence_errors = _intelligence_profile(skill)
    manifest = {
        "schema": CONTRACT_SCHEMA,
        "marker": CONTRACT_MARKER,
        "project_root": str(project),
        "skill_root": str(skill),
        "skill_contract_sha256": contract_digest(skill),
        "intelligence_schema": intelligence.get("schema", INTELLIGENCE_SCHEMA),
        "intelligence_marker": intelligence.get("marker", INTELLIGENCE_MARKER),
        "required_sequence": REQUIRED_SEQUENCE,
        "instruction_files": _instruction_files(project),
        "initialized_at": _now(),
        "network": "not performed",
        "ready": not missing and not intelligence_errors,
        "errors": [f"missing skill file: {name}" for name in missing] + intelligence_errors,
    }
    _write_json(_manifest_path(project), manifest)
    return manifest


def verify(project_root: Optional[str] = None,
           skill_root: Optional[str] = None) -> Dict[str, Any]:
    """Verify that the installed contract is present and has not drifted."""
    project = _project_root(project_root)
    skill = _skill_root(skill_root)
    errors: list[str] = []
    warnings: list[str] = []
    missing = [name for name in REQUIRED_SKILL_FILES
               if not (skill / name).is_file()]
    errors.extend(f"missing skill file: {name}" for name in missing)
    intelligence, intelligence_errors = _intelligence_profile(skill)
    errors.extend(intelligence_errors)

    manifest_path = _manifest_path(project)
    manifest: Dict[str, Any] = {}
    if not manifest_path.is_file():
        errors.append("contract is not initialized; run --init")
    else:
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = loaded
            else:
                errors.append("contract manifest is not a JSON object")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid contract manifest: {exc}")

    current_digest = contract_digest(skill)
    if manifest:
        if manifest.get("schema") != CONTRACT_SCHEMA:
            errors.append("contract manifest schema is unsupported")
        if manifest.get("marker") != CONTRACT_MARKER:
            errors.append("contract marker is missing")
        if manifest.get("skill_contract_sha256") != current_digest:
            errors.append("skill contract changed; re-run --init and reload instructions")
        if manifest.get("intelligence_schema") != intelligence.get("schema"):
            errors.append("intelligence profile changed; re-run --init and reload instructions")
        if manifest.get("intelligence_marker") != intelligence.get("marker"):
            errors.append("intelligence profile marker changed; reload the contract")
        if manifest.get("required_sequence") != REQUIRED_SEQUENCE:
            errors.append("research sequence in manifest is not the mandatory sequence")

    instruction_files = _instruction_files(project)
    if not instruction_files:
        warnings.append("no harness instruction file found; load BUGWOLF.md manually")
    if "BUGWOLF.md" not in instruction_files:
        warnings.append("BUGWOLF.md is not installed in the project")

    return {
        "schema": CONTRACT_SCHEMA,
        "marker": CONTRACT_MARKER,
        "project_root": str(project),
        "skill_root": str(skill),
        "skill_contract_sha256": current_digest,
        "intelligence_schema": intelligence.get("schema", INTELLIGENCE_SCHEMA),
        "intelligence_marker": intelligence.get("marker", INTELLIGENCE_MARKER),
        "instruction_files": instruction_files,
        "required_sequence": REQUIRED_SEQUENCE,
        "ready": not errors,
        "errors": errors,
        "warnings": warnings,
        "checked_at": _now(),
        "network": "not performed",
    }


def record_checkpoint(checkpoint: str, project_root: Optional[str] = None,
                      skill_root: Optional[str] = None) -> Dict[str, Any]:
    """Record an orchestrator checkpoint after verifying the contract."""
    if checkpoint not in REQUIRED_SEQUENCE:
        raise ValueError(
            f"unknown checkpoint '{checkpoint}'; valid: {', '.join(REQUIRED_SEQUENCE)}")
    result = verify(project_root, skill_root)
    if not result["ready"]:
        raise RuntimeError("; ".join(result["errors"]))
    project = _project_root(project_root)
    path = _contract_dir(project) / "checkpoints.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "schema": CONTRACT_SCHEMA,
        "checkpoint": checkpoint,
        "recorded_at": _now(),
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    return {**result, "recorded": event, "checkpoint_file": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf harness contract guard")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--init", action="store_true", help="initialize project contract")
    action.add_argument("--verify", action="store_true", help="verify contract and skill drift")
    action.add_argument("--record-checkpoint", choices=REQUIRED_SEQUENCE,
                        help="verify and record one research checkpoint")
    parser.add_argument("--project-root", help="project workspace (default: cwd)")
    parser.add_argument("--skill-root", help="installed skill root (default: bundled code root)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    try:
        if args.init:
            result = initialize(args.project_root, args.skill_root)
            status = 0 if result["ready"] else 2
        elif args.verify:
            result = verify(args.project_root, args.skill_root)
            status = 0 if result["ready"] else 2
        else:
            result = record_checkpoint(args.record_checkpoint,
                                       args.project_root, args.skill_root)
            status = 0
    except (OSError, RuntimeError, ValueError) as exc:
        result = {
            "schema": CONTRACT_SCHEMA,
            "ready": False,
            "errors": [str(exc)],
            "network": "not performed",
        }
        status = 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        state = "READY" if result.get("ready") else "NOT READY"
        print(f"BugWolf harness contract: {state}")
        for error in result.get("errors", []):
            print(f"  ERROR: {error}")
        for warning in result.get("warnings", []):
            print(f"  WARNING: {warning}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())

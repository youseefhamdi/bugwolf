#!/usr/bin/env python3
"""Persistent no-skip workflow controller for BugWolf (APT Commander, Stage 2).

A harness prompt is not a supervisor.  This module stores the current stage in
project-local state and refuses to complete or enter a later stage until the
previous stage has an auditable prerequisite and the expected artifact exists.
It performs no network activity and never enables active testing by itself.

The workflow is intentionally exhaustive:

  setup -> environment-preflight -> authorization -> passive-recon
  -> asset-intelligence -> technology-fingerprint -> maps -> research
  -> coverage-plan -> validation -> triage -> report

Execution is UNCENSORED: the authorization stage records the operator-declared
scope file but never blocks on scope membership — authorization and execution
are the operator's responsibility, not a controller gate.

Use ``--start`` once the target is known, then complete exactly one stage at a
time with ``--complete``.  A research freshness failure is recorded as pending;
it never permits the stage to be silently skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root


logger = logging.getLogger("bugwolf.stage_controller")


SCHEMA = "bugwolf-workflow/v1"
CONTRACT_MARKER = "BUGWOLF-HARNESS-CONTRACT-V2"

# Must match tools/research_loop.py MANDATORY_RESEARCH_SEQUENCE exactly.
RESEARCH_SEQUENCE = (
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
)

STAGES = (
    "setup",
    "environment-preflight",
    "authorization",
    "passive-recon",
    "asset-intelligence",
    "technology-fingerprint",
    "maps",
    "research",
    "coverage-plan",
    "validation",
    "triage",
    "report",
)

STAGE_DESCRIPTIONS = {
    "setup": "verify the harness contract and initialize target workflow",
    "environment-preflight": "record the operator-declared execution environment",
    "authorization": "load and record the operator-declared authorization scope",
    "passive-recon": "collect passive target intelligence",
    "asset-intelligence": "normalize and analyze the discovered assets",
    "technology-fingerprint": "identify technologies and exact versions for research",
    "maps": "build all five maps and invariants for contract targets",
    "research": "run the complete ordered latest-information research sequence",
    "coverage-plan": "build the complete mutation/discovery coverage plan",
    "validation": "perform bounded validation",
    "triage": "apply evidence, impact, novelty, and human-review gates",
    "report": "write the reviewed report and preserve provenance",
}

# Stages with a deterministic default artifact contract.  ``validation``,
# ``triage`` and ``report`` always require an explicit ``--artifact`` path.
_DEFAULT_ARTIFACT_STAGES = {
    "setup", "environment-preflight", "passive-recon", "asset-intelligence",
    "technology-fingerprint", "maps", "research", "coverage-plan",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _target_slug(target: str) -> str:
    value = str(target or "").strip()
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError("target must be a host or project name, not a path")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        raise ValueError("target contains unsupported characters")
    return value[:200]


def _atomic_write(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def _workflow_path(project: Path, target: str) -> Path:
    return project / ".bugwolf" / "workflows" / f"{_target_slug(target)}.json"


def _workflow_chain_path(project: Path, target: str) -> Path:
    return project / ".bugwolf" / "workflows" / f"{_target_slug(target)}.chain.jsonl"


def _manifest_digest(data: Dict[str, Any]) -> str:
    unsigned = dict(data)
    unsigned.pop("manifest_hash", None)
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _relative_or_absolute(project: Path, value: str) -> Path:
    """Resolve an artifact path, contained inside the project root.

    Containment is integrity hygiene (deterministic hashes, no external file
    reads recorded into state), not a scope gate — authorization is not
    enforced anywhere in this module.
    """
    base = project.expanduser().resolve()
    candidate = Path(value).expanduser()
    resolved = candidate.resolve(strict=False) if candidate.is_absolute() \
        else (base / candidate).resolve(strict=False)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise WorkflowError(f"artifact path escapes project root: {value}") from exc
    return resolved


def _artifact_digest(path: Path) -> str:
    """Hash an artifact file or deterministic directory tree."""
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(path.read_bytes())
    elif path.is_dir():
        for item in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(str(item.relative_to(path)).encode("utf-8"))
            digest.update(item.read_bytes())
    else:
        return ""
    return digest.hexdigest()


def _nonempty(path: Path) -> bool:
    if path.is_file():
        return path.stat().st_size > 0
    if path.is_dir():
        return any(item.is_file() and item.stat().st_size > 0
                   for item in path.rglob("*"))
    return False


def _paper_intelligence_sources(project: Path, target: str) -> Dict[str, Path]:
    recon = project / "recon" / _target_slug(target)
    traffic = next((path for path in (
        recon / "https-traffic.json", recon / "https-traffic.jsonl",
        recon / "traffic.json", recon / "traffic.jsonl",
    ) if path.is_file() and _nonempty(path)), None)
    profiles = next((path for path in (
        recon / "site-profiles.json", recon / "site-profiles.jsonl",
        project / "site-profiles.json", project / "site-profiles.jsonl",
    ) if path.is_file() and _nonempty(path)), None)
    agent = next((path for path in (
        recon / "agent-control-plane.json", recon / "agent-control-plane.jsonl",
        project / "agent-inventory.json", project / "agent-inventory.jsonl",
        project / "audit" / "agent-inventory.json",
        project / "audit" / "agent-inventory.jsonl",
        project / "audit" / _target_slug(target) / "agent-inventory.json",
        project / "audit" / _target_slug(target) / "agent-inventory.jsonl",
    ) if path.is_file() and _nonempty(path)), None)
    result: Dict[str, Path] = {}
    if traffic:
        result["https_traffic_file"] = traffic
        if profiles:
            result["site_profiles_file"] = profiles
    if agent:
        result["agent_control_plane_file"] = agent
    return result


def _paper_intelligence_inputs(project: Path, target: str) -> List[Path]:
    """Find conventional, operator-supplied paper-intelligence artifacts.

    Discovery is deliberately narrow and project-contained. The recon stage
    can process these files automatically, while arbitrary paths still require
    an explicit CLI invocation and remain outside this convenience hook.
    """
    return list(_paper_intelligence_sources(project, target).values())


def _paper_intelligence_output(project: Path, target: str) -> Path:
    return project / "recon" / _target_slug(target) / "paper-intelligence" / "paper-intelligence.json"


def _paper_intelligence_map(project: Path, target: str) -> Path:
    return project / "state" / "sessions" / _target_slug(target) / "maps" / "paper-intelligence.md"


def _record_template(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "description": STAGE_DESCRIPTIONS[name],
        "status": "pending",
        "attempts": 0,
        "completed_at": "",
        "artifacts": [],
        "notes": [],
        "quality": "pending",
    }


class WorkflowError(RuntimeError):
    """Raised when a workflow transition would skip a required stage."""


class WorkflowController:
    """Manage one target's persistent, ordered workflow."""

    def __init__(self, target: str, *, project_root: Optional[str] = None,
                 mode: str = "full", scope_file: Optional[str] = None):
        self.project = workspace_root(project_root)
        self.target = _target_slug(target)
        self.mode = mode or "full"
        self.scope_file = scope_file or ""
        self.path = _workflow_path(self.project, self.target)
        self.chain_path = _workflow_chain_path(self.project, self.target)

    @property
    def is_contract_target(self) -> bool:
        mode = self.mode
        # Completion commands often omit --mode. Reuse the mode captured when
        # the workflow was started so a contract hunt cannot skip invariants.
        if self.path.is_file():
            try:
                stored = json.loads(self.path.read_text(encoding="utf-8"))
                mode = str(stored.get("mode", mode))
            except (OSError, json.JSONDecodeError):
                pass
        return any(token in mode.lower()
                   for token in ("solidity", "move", "solana", "contract"))

    def _load(self) -> Dict[str, Any]:
        if not self.path.is_file():
            raise WorkflowError(
                f"workflow is not initialized for {self.target}; run --start first")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"invalid workflow manifest: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise WorkflowError("unsupported workflow manifest")
        if data.get("marker") != CONTRACT_MARKER:
            raise WorkflowError(
                "workflow manifest predates the restored contract; "
                "re-run with --start --force to rebuild it")
        if data.get("stages") is None:
            raise WorkflowError("workflow manifest has no stages")
        if not self._verify_manifest_chain(data):
            raise WorkflowError("workflow manifest integrity verification failed")
        return data

    def _verify_manifest_chain(self, data: Dict[str, Any]) -> bool:
        """Verify the manifest is the latest snapshot in its hash chain."""
        if not self.chain_path.is_file():
            return False
        previous = ""
        latest = ""
        expected = 1
        try:
            for line in self.chain_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("sequence") != expected \
                        or record.get("previous_hash", "") != previous:
                    return False
                unsigned = dict(record)
                stored_record_hash = unsigned.pop("record_hash", "")
                expected_record_hash = hashlib.sha256(
                    json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                if stored_record_hash and stored_record_hash != expected_record_hash:
                    return False
                latest = str(record["manifest_hash"])
                previous = stored_record_hash or latest
                expected += 1
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False
        return bool(latest) and latest == _manifest_digest(data) \
            and data.get("manifest_hash") == latest

    def _save(self, data: Dict[str, Any]) -> None:
        data["updated_at"] = _now()
        digest = _manifest_digest(data)
        data["manifest_hash"] = digest
        _atomic_write(self.path, data)
        previous = ""
        sequence = 1
        if self.chain_path.exists():
            lines = [line for line in self.chain_path.read_text(encoding="utf-8").splitlines()
                     if line.strip()]
            if lines:
                last = json.loads(lines[-1])
                previous = str(last.get("record_hash") or last.get("manifest_hash", ""))
                sequence = int(last.get("sequence", len(lines))) + 1
        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        chain_record = {
            "sequence": sequence,
            "previous_hash": previous,
            "manifest_hash": digest,
            "saved_at": data["updated_at"],
        }
        chain_record["record_hash"] = hashlib.sha256(
            json.dumps(chain_record, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        with self.chain_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(chain_record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def initialize(self, *, force: bool = False) -> Dict[str, Any]:
        if self.path.exists() and not force:
            return self._load()
        if force and self.chain_path.exists():
            self.chain_path.unlink()
        data = {
            "schema": SCHEMA,
            "marker": CONTRACT_MARKER,
            "target": self.target,
            "mode": self.mode,
            "project_root": str(self.project),
            "scope_file": self.scope_file,
            "created_at": _now(),
            "updated_at": _now(),
            "current_stage": STAGES[0],
            "stages": [_record_template(name) for name in STAGES],
            "history": [],
            "no_skip": True,
            "network": "not performed by controller",
        }
        self._save(data)
        return data

    def status(self) -> Dict[str, Any]:
        data = self._load()
        current = self.current_stage(data)
        return {
            "schema": SCHEMA,
            "target": self.target,
            "mode": data.get("mode", self.mode),
            "project_root": str(self.project),
            "scope_file": data.get("scope_file", ""),
            "current_stage": current,
            "missing_artifacts": self._missing_artifacts(current),
            "next_command": self.next_command(current),
            "stages": data["stages"],
            "history_count": len(data.get("history", [])),
            "no_skip": True,
            "network": "not performed by controller",
        }

    def _missing_artifacts(self, stage: Optional[str]) -> List[str]:
        """Default artifacts the current stage still needs (informational)."""
        if not stage or stage not in _DEFAULT_ARTIFACT_STAGES:
            return []
        return [
            str(path.relative_to(self.project))
            for path in self._default_artifacts(stage)
            if not _nonempty(path)
        ]

    @staticmethod
    def current_stage(data: Dict[str, Any]) -> Optional[str]:
        for stage in data.get("stages", []):
            if stage.get("status") not in {"complete", "complete_pending"}:
                return stage.get("name")
        return None

    def next_command(self, stage: Optional[str]) -> str:
        if not stage:
            return "workflow complete; review the report and preserve provenance"
        base = f"python3 tools/stage_controller.py --target {self.target}"
        if stage == "authorization":
            return base + " --complete authorization --scope-file scope.json --json"
        if stage in {"validation", "triage", "report"}:
            return base + f" --complete {stage} --artifact <verified-output> --json"
        return base + f" --complete {stage} --json"

    def require_stage(self, stage: str) -> Dict[str, Any]:
        data = self._load()
        self._validate_completed_integrity(data)
        if stage not in STAGES:
            raise WorkflowError(f"unknown workflow stage: {stage}")
        current = self.current_stage(data)
        if current != stage:
            # Recovery path: research recorded as complete_pending may be
            # re-completed (upgraded to complete) once the research sequence
            # is fresh — otherwise a stale research run would permanently lock
            # the validation gate with no way forward.
            if stage == "research":
                research = self._stage(data, "research")
                if research.get("status") == "complete_pending" \
                        and self._validate_research() == "complete":
                    return data
            raise WorkflowError(
                f"stage '{stage}' is blocked; current required stage is '{current}'")
        if stage == "validation":
            research = self._stage(data, "research")
            if research.get("status") != "complete":
                raise WorkflowError(
                    "validation is blocked until current research is available; "
                    "research status is " + str(research.get("status", "pending")))
        return data

    def refresh_artifact_hashes(self, stage_name: str) -> Dict[str, Any]:
        """Re-record artifact hashes for a completed stage after a controlled,
        campaign-driven update (e.g. maps refreshed during threat modeling).

        The update is explicit and audited: it appends a note and persists a
        new manifest snapshot through the hash chain, so the change is
        traceable rather than invisible.  Only the named stage is touched.
        """
        data = self._load()
        self._validate_completed_integrity(data)
        stage = self._stage(data, stage_name)
        if stage.get("status") != "complete":
            raise WorkflowError(
                f"stage '{stage_name}' is not complete; nothing to refresh")
        stage["artifact_hashes"] = {
            name: _artifact_digest(self.project / name)
            for name in stage.get("artifacts", [])
        }
        stage.setdefault("notes", []).append(
            "artifact hashes refreshed after campaign update at " + _now())
        self._save(data)
        logger.info("refreshed artifact hashes for stage %s", stage_name)
        return self.status()

    def _validate_completed_integrity(self, data: Dict[str, Any]) -> None:
        """Refuse to advance after a completed artifact was modified."""
        for stage in data.get("stages", []):
            if stage.get("status") not in {"complete", "complete_pending"}:
                continue
            recorded = stage.get("artifact_hashes", {})
            if not recorded:
                continue  # manifests created before integrity tracking
            for name, expected in recorded.items():
                actual = _artifact_digest(self.project / name)
                if not actual or actual != expected:
                    raise WorkflowError(
                        f"stage '{stage.get('name')}' artifact changed or disappeared: {name}")

    def _stage(self, data: Dict[str, Any], name: str) -> Dict[str, Any]:
        for stage in data["stages"]:
            if stage.get("name") == name:
                return stage
        raise WorkflowError(f"stage missing from manifest: {name}")

    def _default_artifacts(self, name: str) -> List[Path]:
        target = self.target
        root = self.project
        paths: Dict[str, List[Path]] = {
            "setup": [root / ".bugwolf" / "harness.json"],
            "environment-preflight": [root / "state" / "environment.json"],
            "passive-recon": [root / "recon" / target / "recon-complete.json"],
            "asset-intelligence": [root / "recon" / target / "asset-intel"],
            "technology-fingerprint": [root / "recon" / target / "tech-fingerprint.json"],
            "maps": [root / "state" / "sessions" / target / "maps" / name
                     for name in ("asset.md", "trust.md", "authz.md", "state.md",
                                  "capability.md")],
            "research": [root / "research" / target / "sequence.json"],
            "coverage-plan": [root / "recon" / target / "discovery"],
        }
        if self.is_contract_target:
            paths["maps"].append(root / "state" / "sessions" / target /
                                  "maps" / "invariants.md")
        if _paper_intelligence_inputs(root, target):
            if name == "maps":
                paths["maps"].extend([
                    _paper_intelligence_output(root, target),
                    _paper_intelligence_map(root, target),
                ])
            elif name == "passive-recon":
                # The recon completion marker is only valid after the
                # automatically discovered paper artifacts were analyzed.
                paths["passive-recon"].append(_paper_intelligence_output(root, target))
        return paths.get(name, [])

    def _validate_stage_artifacts(self, name: str, artifacts: Iterable[str]) -> List[str]:
        supplied = [_relative_or_absolute(self.project, value) for value in artifacts if value]
        paths = supplied or self._default_artifacts(name)
        if name in _DEFAULT_ARTIFACT_STAGES and not paths:
            raise WorkflowError(f"no artifact contract defined for stage '{name}'")
        if name in {"validation", "triage", "report"} and not supplied:
            raise WorkflowError(
                f"stage '{name}' requires at least one explicit --artifact path")
        missing = [str(path) for path in paths if not _nonempty(path)]
        if missing:
            raise WorkflowError(
                f"stage '{name}' is incomplete; missing/empty artifact(s): "
                + ", ".join(missing))
        return [str(path.relative_to(self.project))
                if path.is_relative_to(self.project) else str(path)
                for path in paths]

    def _validate_setup(self) -> None:
        manifest = self.project / ".bugwolf" / "harness.json"
        if not _nonempty(manifest):
            raise WorkflowError("setup requires .bugwolf/harness.json; run harness_guard --init")
        if not _nonempty(self.project / "BUGWOLF.md"):
            raise WorkflowError(
                "setup requires project BUGWOLF.md; install the harness contract first")
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"invalid harness manifest: {exc}") from exc
        if data.get("marker") != CONTRACT_MARKER or data.get("ready") is not True:
            raise WorkflowError("harness contract is not ready; verify and reload instructions")
        # Re-check the digest recorded by harness_guard so a compacted or
        # modified skill cannot silently continue under an old contract.
        try:
            from tools.harness_guard import verify
            checked = verify(str(self.project), data.get("skill_root"))
        except ImportError:  # direct script execution
            from harness_guard import verify
            checked = verify(str(self.project), data.get("skill_root"))
        if not checked.get("ready"):
            raise WorkflowError("harness verification failed: "
                                + "; ".join(checked.get("errors", [])))

    def _validate_recon(self) -> None:
        path = self.project / "recon" / self.target / "recon-complete.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"invalid recon completion marker: {exc}") from exc
        if data.get("complete") is False:
            raise WorkflowError(
                "recon completion marker is degraded; rerun failed phases before advancing")
        if _paper_intelligence_inputs(self.project, self.target):
            output = _paper_intelligence_output(self.project, self.target)
            map_path = _paper_intelligence_map(self.project, self.target)
            if not _nonempty(output) or not _nonempty(map_path):
                raise WorkflowError(
                    "recon has paper-intelligence inputs but no completed paper-intelligence artifact/map handoff")

    def _ensure_paper_intelligence(self) -> None:
        sources = _paper_intelligence_sources(self.project, self.target)
        if not sources:
            return
        output = _paper_intelligence_output(self.project, self.target)
        map_path = _paper_intelligence_map(self.project, self.target)
        try:
            from tools.paper_intel import build_artifact_intelligence_report
        except ImportError:  # direct script execution
            from paper_intel import build_artifact_intelligence_report
        kwargs = {key: str(value) for key, value in sources.items()}
        build_artifact_intelligence_report(
            **kwargs, output_dir=output.parent, map_output=map_path,
        )
        if not _nonempty(output) or not _nonempty(map_path):
            raise WorkflowError("automatic paper-intelligence generation produced no usable handoff")

    def _validate_environment(self) -> None:
        path = self.project / "state" / "environment.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"invalid environment profile: {exc}") from exc
        if data.get("location") not in {"local", "vps", "container_vm", "unknown"}:
            raise WorkflowError("environment profile has no operator-declared location")

    def _validate_authorization(self, scope_file: Optional[str]) -> str:
        """Record the operator-declared scope file.

        UNCENSORED: the file is required (it is the stage's artifact) and must
        parse as JSON, but target membership is deliberately NOT enforced.
        Authorization is the operator's declared responsibility.
        """
        chosen = scope_file or self.scope_file
        if not chosen:
            raise WorkflowError("authorization requires --scope-file")
        path = _relative_or_absolute(self.project, chosen)
        if not _nonempty(path):
            raise WorkflowError(f"scope file is missing or empty: {chosen}")
        try:
            scope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"scope file is not valid JSON: {exc}") from exc
        if not isinstance(scope, dict):
            raise WorkflowError("scope file must contain a JSON object")
        return str(path.relative_to(self.project))

    def _validate_research(self) -> str:
        path = self.project / "research" / self.target / "sequence.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"invalid research sequence manifest: {exc}") from exc
        required = list(RESEARCH_SEQUENCE)
        current = data.get("executions", [])[-1] if data.get("executions") else data
        sequence = current.get("sequence", [])
        if sequence != required:
            raise WorkflowError(
                "research stage requires the complete ordered sequence: "
                + " -> ".join(required))
        # Only the current execution controls freshness. A historical offline
        # run must not permanently poison a later successful execution.
        if not current.get("latest_ready", False):
            return "complete_pending"
        return "complete"

    def complete(self, name: str, *, artifacts: Optional[List[str]] = None,
                 scope_file: Optional[str] = None, notes: str = "") -> Dict[str, Any]:
        data = self.require_stage(name)
        stage = self._stage(data, name)
        stage["attempts"] = int(stage.get("attempts", 0)) + 1

        if name == "setup":
            self._validate_setup()
        elif name == "environment-preflight":
            self._validate_environment()
        elif name == "authorization":
            chosen = self._validate_authorization(scope_file)
            data["scope_file"] = chosen
        elif name == "passive-recon":
            self._ensure_paper_intelligence()
            self._validate_recon()
        artifact_names = self._validate_stage_artifacts(name, artifacts or [])
        artifact_hashes = {
            artifact: _artifact_digest(self.project / artifact)
            for artifact in artifact_names
        }
        quality = "complete"
        if name == "research":
            quality = self._validate_research()
        # complete_pending is by definition in-flux (fresh research will rewrite
        # its sequence.json) — only completed stages get integrity hashes.
        recorded_hashes = artifact_hashes if quality == "complete" else {}
        stage.update({
            "status": quality,
            "completed_at": _now(),
            "artifacts": artifact_names,
            "artifact_hashes": recorded_hashes,
            "quality": "pending_latest" if quality == "complete_pending" else "verified",
        })
        if notes:
            stage.setdefault("notes", []).append(notes[:1000])
        data["history"].append({
            "stage": name,
            "status": quality,
            "completed_at": stage["completed_at"],
            "artifacts": artifact_names,
        })
        data["current_stage"] = self.current_stage(data)
        self._save(data)
        logger.info("stage %s completed (%s) for %s", name, quality, self.target)
        return self.status()


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf no-skip workflow controller")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--start", action="store_true",
                        help="initialize the target workflow")
    action.add_argument("--status", action="store_true", help="show current stage")
    action.add_argument("--get-state", action="store_true",
                        help="alias for --status: current stage + missing artifacts")
    action.add_argument("--advance", action="store_true",
                        help="complete the current stage (default artifacts)")
    action.add_argument("--complete", metavar="STAGE", choices=STAGES,
                        help="complete only the current stage")
    parser.add_argument("--target", required=True, help="target host or local project name")
    parser.add_argument("--project-root", help="workspace root (default: cwd)")
    parser.add_argument("--mode", default="full", help="selected audit mode(s)")
    parser.add_argument("--scope-file", help="explicit authorization scope JSON")
    parser.add_argument("--artifact", action="append", default=[],
                        help="stage artifact path; repeat for multiple artifacts")
    parser.add_argument("--notes", default="", help="short operator note")
    parser.add_argument("--force", action="store_true",
                        help="with --start: rebuild a stale/foreign workflow manifest")
    parser.add_argument("--json", action="store_true", help="emit strict JSON")
    args = parser.parse_args()

    try:
        controller = WorkflowController(
            args.target, project_root=args.project_root,
            mode=args.mode, scope_file=args.scope_file)
        if args.start:
            controller.initialize(force=args.force)
            result = controller.status()
        elif args.status or args.get_state:
            result = controller.status()
        elif args.advance:
            data = controller._load()
            current = WorkflowController.current_stage(data)
            if current is None:
                result = controller.status()
                result["ready"] = True
                result["message"] = "workflow complete"
            else:
                result = controller.complete(
                    current, artifacts=args.artifact,
                    scope_file=args.scope_file, notes=args.notes)
        else:
            result = controller.complete(
                args.complete, artifacts=args.artifact,
                scope_file=args.scope_file, notes=args.notes)
        status = 0
    except (WorkflowError, ValueError, OSError) as exc:
        result = {
            "schema": SCHEMA, "target": args.target, "ready": False,
            "error": str(exc), "network": "not performed by controller",
        }
        status = 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if status:
            print(f"[!] Workflow blocked: {result['error']}")
        else:
            print(f"[*] Workflow {result.get('target')}: "
                  f"{result.get('current_stage') or 'complete'}")
            if result.get("next_command"):
                print(f"    {result['next_command']}")
            for stage in result.get("stages", []):
                print(f"    [{stage['status']}] {stage['name']} — {stage['description']}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())

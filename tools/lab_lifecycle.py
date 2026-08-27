#!/usr/bin/env python3
"""BugWolf private-lab lifecycle manager.

This module manages disposable local laboratory workspaces and fixture
processes. It intentionally does not enforce target authorization or scope;
those semantics belong to the private lab boundary. It does enforce local
resource accounting, workspace containment, process ownership, bounded process
startup, reset, and teardown.

The manager is fixture-agnostic. A campaign can register commands for local
fixtures, start them, inspect resource usage, reset the workspace, and tear
all owned processes down deterministically.

Runtime state is stored below::

    state/labs/<lab_id>/manifest.json
    state/labs/<lab_id>/events.jsonl
    state/labs/<lab_id>/workspace/
    state/labs/<lab_id>/logs/<process_id>.{stdout,stderr}

No network calls are made by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

try:
    from tools.reliability import (
        DEFAULT_OUTPUT_BYTES,
        DEFAULT_TIMEOUT_SECONDS,
        ResourceLimitError,
        append_jsonl,
        atomic_write_json,
        run_bounded_subprocess,
    )
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from reliability import (  # type: ignore
        DEFAULT_OUTPUT_BYTES,
        DEFAULT_TIMEOUT_SECONDS,
        ResourceLimitError,
        append_jsonl,
        atomic_write_json,
        run_bounded_subprocess,
    )
    from runtime_paths import target_slug, workspace_root  # type: ignore

SCHEMA = "bugwolf/private-lab/v1"
MANIFEST_NAME = "manifest.json"
EVENTS_NAME = "events.jsonl"


class LabLifecycleError(RuntimeError):
    """Raised when a lifecycle operation cannot be completed safely."""


@dataclass
class ResourceBudget:
    """Operational limits for one disposable lab."""

    max_processes: int = 16
    max_runtime_seconds: float = 3600.0
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES
    max_workspace_bytes: int = 250_000_000

    def validate(self) -> None:
        if self.max_processes < 1:
            raise ValueError("max_processes must be positive")
        if self.max_runtime_seconds <= 0:
            raise ValueError("max_runtime_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_workspace_bytes <= 0:
            raise ValueError("max_workspace_bytes must be positive")


@dataclass
class FixtureSpec:
    """A local fixture command registered with the lab."""

    fixture_id: str
    command: List[str]
    cwd: str = ""
    env: Dict[str, str] = field(default_factory=dict)
    startup_timeout_seconds: float = 30.0
    ready_file: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.fixture_id.strip():
            raise ValueError("fixture_id is required")
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise ValueError("fixture command must be a non-empty argv list")
        if self.startup_timeout_seconds <= 0:
            raise ValueError("startup_timeout_seconds must be positive")


@dataclass
class ProcessRecord:
    process_id: str
    fixture_id: str
    pid: int
    command: List[str]
    started_at: str
    start_ticks: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    status: str = "running"  # running | exited | terminated | unknown
    returncode: Optional[int] = None


@dataclass
class LabManifest:
    lab_id: str
    target: str
    status: str = "created"  # created | active | reset | teardown | failed
    created_at: str = ""
    updated_at: str = ""
    workspace: str = ""
    budget: Dict[str, Any] = field(default_factory=dict)
    fixtures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    processes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    generation: int = 0
    reset_count: int = 0
    teardown_count: int = 0
    failure: str = ""

    def __post_init__(self) -> None:
        now = _now()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}


@dataclass
class ResourceSnapshot:
    lab_id: str
    captured_at: str
    workspace_bytes: int
    workspace_files: int
    running_processes: int
    registered_processes: int
    elapsed_seconds: float
    budget: Dict[str, Any]
    over_budget: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _process_start_ticks(pid: int) -> str:
    """Read Linux process start ticks to avoid PID reuse during teardown."""
    try:
        fields = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8").split()
        return fields[21] if len(fields) > 21 else ""
    except (OSError, ValueError):
        return ""


def _is_running(pid: int, expected_ticks: str = "") -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    if expected_ticks:
        actual = _process_start_ticks(pid)
        return bool(actual and actual == expected_ticks)
    return True


def _directory_size(path: Path) -> tuple[int, int]:
    total = 0
    files = 0
    if not path.exists():
        return 0, 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
                files += 1
            except OSError:
                continue
    return total, files


def _stable_lab_id(target: str) -> str:
    slug = target_slug(target)
    digest = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}"


class LabManager:
    """Manage one isolated, disposable local lab workspace."""

    def __init__(self, target: str, *, project_root: Optional[str | Path] = None,
                 lab_id: Optional[str] = None,
                 budget: Optional[ResourceBudget] = None):
        self.project = workspace_root(project_root)
        self.target = str(target)
        self.lab_id = lab_id or _stable_lab_id(self.target)
        self.root = self.project / "state" / "labs" / target_slug(self.lab_id)
        self.workspace = self.root / "workspace"
        self.logs = self.root / "logs"
        self.manifest_path = self.root / MANIFEST_NAME
        self.events_path = self.root / EVENTS_NAME
        self.budget = budget or ResourceBudget()
        self.budget.validate()

    # ------------------------------------------------------------------
    # Manifest and event persistence
    # ------------------------------------------------------------------

    def _load(self) -> LabManifest:
        if not self.manifest_path.is_file():
            raise LabLifecycleError(
                f"lab is not initialized: {self.lab_id}; run create first")
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if data.get("schema") != SCHEMA:
                raise LabLifecycleError("unsupported lab manifest schema")
            data.pop("schema", None)
            return LabManifest(**data)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise LabLifecycleError(f"invalid lab manifest: {exc}") from exc

    def _save(self, manifest: LabManifest) -> None:
        manifest.updated_at = _now()
        atomic_write_json(self.manifest_path, manifest.to_dict())

    def _event(self, action: str, *, status: str = "ok",
               metadata: Optional[Mapping[str, Any]] = None) -> None:
        append_jsonl(self.events_path, {
            "schema": SCHEMA,
            "event_id": str(uuid.uuid4()),
            "lab_id": self.lab_id,
            "target": self.target,
            "action": action,
            "status": status,
            "timestamp": _now(),
            "metadata": dict(metadata or {}),
        })

    def create(self, *, force: bool = False) -> LabManifest:
        """Create or load a clean lab workspace."""
        if self.manifest_path.is_file() and not force:
            return self._load()
        if force and self.manifest_path.is_file():
            self.teardown(ignore_missing=True)
        self.root.mkdir(parents=True, exist_ok=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        manifest = LabManifest(
            lab_id=self.lab_id,
            target=self.target,
            workspace=str(self.workspace.relative_to(self.project)),
            budget=asdict(self.budget),
            generation=0,
        )
        self._save(manifest)
        self._event("create", metadata={"force": force})
        return manifest

    def status(self) -> Dict[str, Any]:
        manifest = self._load()
        self._refresh_process_status(manifest)
        snapshot = self.resource_snapshot(manifest=manifest)
        self._save(manifest)
        return {
            "manifest": manifest.to_dict(),
            "resources": snapshot.to_dict(),
            "paths": {
                "root": str(self.root),
                "workspace": str(self.workspace),
                "logs": str(self.logs),
                "manifest": str(self.manifest_path),
                "events": str(self.events_path),
            },
        }

    # ------------------------------------------------------------------
    # Fixtures and process lifecycle
    # ------------------------------------------------------------------

    def register_fixture(self, fixture: FixtureSpec) -> LabManifest:
        fixture.validate()
        manifest = self._load()
        if manifest.status in {"teardown", "failed"}:
            raise LabLifecycleError(f"cannot register fixture in lab status {manifest.status}")
        cwd = Path(fixture.cwd).expanduser() if fixture.cwd else self.workspace
        cwd = cwd.resolve()
        try:
            cwd.relative_to(self.project.resolve())
        except ValueError as exc:
            raise LabLifecycleError("fixture cwd escapes project root") from exc
        manifest.fixtures[fixture.fixture_id] = {
            "fixture_id": fixture.fixture_id,
            "command": list(fixture.command),
            "cwd": str(cwd),
            "env": dict(fixture.env),
            "startup_timeout_seconds": fixture.startup_timeout_seconds,
            "ready_file": fixture.ready_file,
            "metadata": dict(fixture.metadata),
        }
        self._save(manifest)
        self._event("register_fixture", metadata={"fixture_id": fixture.fixture_id})
        return manifest

    def start_fixture(self, fixture_id: str) -> ProcessRecord:
        """Start a registered fixture and track its owned process."""
        manifest = self._load()
        self._refresh_process_status(manifest)
        if manifest.status == "teardown":
            raise LabLifecycleError("cannot start a fixture after teardown")
        if fixture_id not in manifest.fixtures:
            raise LabLifecycleError(f"unknown fixture: {fixture_id}")
        running = [p for p in manifest.processes.values() if p.get("status") == "running"]
        if len(running) >= int(manifest.budget.get("max_processes", self.budget.max_processes)):
            raise ResourceLimitError("lab process budget exhausted")
        spec = manifest.fixtures[fixture_id]
        cwd = Path(spec["cwd"]).resolve()
        self.logs.mkdir(parents=True, exist_ok=True)
        process_id = f"{fixture_id}-{uuid.uuid4().hex[:12]}"
        stdout_path = self.logs / f"{process_id}.stdout"
        stderr_path = self.logs / f"{process_id}.stderr"
        stdout = stdout_path.open("wb")
        stderr = stderr_path.open("wb")
        env = os.environ.copy()
        env.update({str(k): str(v) for k, v in (spec.get("env") or {}).items()})
        try:
            process = subprocess.Popen(
                list(spec["command"]), cwd=str(cwd), env=env,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                start_new_session=True,
            )
        except OSError:
            stdout.close()
            stderr.close()
            raise
        finally:
            stdout.close()
            stderr.close()
        record = ProcessRecord(
            process_id=process_id,
            fixture_id=fixture_id,
            pid=process.pid,
            command=list(spec["command"]),
            started_at=_now(),
            start_ticks=_process_start_ticks(process.pid),
            stdout_path=str(stdout_path.relative_to(self.project)),
            stderr_path=str(stderr_path.relative_to(self.project)),
        )
        manifest.processes[process_id] = asdict(record)
        manifest.status = "active"
        self._save(manifest)
        self._event("start_fixture", metadata={
            "fixture_id": fixture_id,
            "process_id": process_id,
            "pid": process.pid,
        })
        return record

    def stop_fixture(self, process_id: str, *, timeout: float = 5.0) -> Dict[str, Any]:
        """Terminate one process only if it is still the recorded process."""
        manifest = self._load()
        data = manifest.processes.get(process_id)
        if not data:
            raise LabLifecycleError(f"unknown process: {process_id}")
        pid = int(data.get("pid") or 0)
        ticks = str(data.get("start_ticks") or "")
        result: Dict[str, Any] = {"process_id": process_id, "pid": pid, "stopped": False}
        if not _is_running(pid, ticks):
                data["status"] = "exited"
                result["status"] = "exited"

        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except (AttributeError, OSError):
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
            deadline = time.monotonic() + max(0.1, timeout)
            while time.monotonic() < deadline and _is_running(pid, ticks):
                time.sleep(0.05)
            if _is_running(pid, ticks):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except (AttributeError, OSError):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
            data["status"] = "terminated"
            result.update({"stopped": True, "status": "terminated"})
        manifest.processes[process_id] = data
        if not any(p.get("status") == "running" for p in manifest.processes.values()):
            manifest.status = "created" if manifest.status == "active" else manifest.status
        self._save(manifest)
        self._event("stop_fixture", status="ok", metadata=result)
        return result

    def _refresh_process_status(self, manifest: LabManifest) -> None:
        for process_id, data in manifest.processes.items():
            if data.get("status") != "running":
                continue
            pid = int(data.get("pid") or 0)
            if not _is_running(pid, str(data.get("start_ticks") or "")):
                data["status"] = "exited"
                data["returncode"] = None
                manifest.processes[process_id] = data

    # ------------------------------------------------------------------
    # Resource accounting, reset, teardown
    # ------------------------------------------------------------------

    def resource_snapshot(self, *, manifest: Optional[LabManifest] = None) -> ResourceSnapshot:
        manifest = manifest or self._load()
        self._refresh_process_status(manifest)
        workspace_bytes, workspace_files = _directory_size(self.workspace)
        running = sum(1 for p in manifest.processes.values() if p.get("status") == "running")
        try:
            created = datetime.fromisoformat(manifest.created_at)
            elapsed = max(0.0, (datetime.now(timezone.utc) - created).total_seconds())
        except (TypeError, ValueError):
            elapsed = 0.0
        budget = dict(manifest.budget or asdict(self.budget))
        over: List[str] = []
        if running > int(budget.get("max_processes", self.budget.max_processes)):
            over.append("max_processes")
        if elapsed > float(budget.get("max_runtime_seconds", self.budget.max_runtime_seconds)):
            over.append("max_runtime_seconds")
        if workspace_bytes > int(budget.get("max_workspace_bytes", self.budget.max_workspace_bytes)):
            over.append("max_workspace_bytes")
        return ResourceSnapshot(
            lab_id=self.lab_id,
            captured_at=_now(),
            workspace_bytes=workspace_bytes,
            workspace_files=workspace_files,
            running_processes=running,
            registered_processes=len(manifest.processes),
            elapsed_seconds=round(elapsed, 3),
            budget=budget,
            over_budget=over,
        )

    def reset(self) -> LabManifest:
        """Stop owned processes, remove fixture workspace, and create a new generation."""
        manifest = self._load()
        self._stop_all(manifest)
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        manifest.processes = {}
        manifest.status = "reset"
        manifest.generation += 1
        manifest.reset_count += 1
        manifest.failure = ""
        self._save(manifest)
        self._event("reset", metadata={"generation": manifest.generation})
        return manifest

    def teardown(self, *, ignore_missing: bool = False) -> Dict[str, Any]:
        """Stop only owned processes and remove this lab's workspace/logs."""
        if not self.manifest_path.is_file():
            if ignore_missing:
                return {"lab_id": self.lab_id, "status": "missing"}
            raise LabLifecycleError(f"lab is not initialized: {self.lab_id}")
        manifest = self._load()
        self._stop_all(manifest)
        removed: List[str] = []
        for directory in (self.workspace, self.logs):
            if directory.exists():
                shutil.rmtree(directory)
                removed.append(str(directory))
        manifest.processes = {}
        manifest.status = "teardown"
        manifest.teardown_count += 1
        self._save(manifest)
        self._event("teardown", metadata={"removed": removed})
        return {"lab_id": self.lab_id, "status": "teardown", "removed": removed}

    def _stop_all(self, manifest: LabManifest) -> None:
        for process_id, data in list(manifest.processes.items()):
            if data.get("status") == "running":
                try:
                    self.stop_fixture(process_id)
                except LabLifecycleError:
                    data["status"] = "unknown"
                    manifest.processes[process_id] = data

    # ------------------------------------------------------------------
    # CLI helpers
    # ------------------------------------------------------------------

    def register_from_dict(self, data: Mapping[str, Any]) -> LabManifest:
        fixture = FixtureSpec(
            fixture_id=str(data.get("fixture_id") or data.get("id") or ""),
            command=[str(value) for value in data.get("command") or []],
            cwd=str(data.get("cwd") or ""),
            env={str(k): str(v) for k, v in (data.get("env") or {}).items()},
            startup_timeout_seconds=float(data.get("startup_timeout_seconds", 30.0)),
            ready_file=str(data.get("ready_file") or ""),
            metadata=dict(data.get("metadata") or {}),
        )
        return self.register_fixture(fixture)


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="BugWolf private lab lifecycle manager")
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--lab-id", default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--fixture-file", help="JSON fixture specification")
    parser.add_argument("--fixture-id", help="Registered fixture id")
    parser.add_argument("--action", choices=("create", "status", "register", "start",
                                               "stop", "reset", "teardown"),
                        required=True)
    parser.add_argument("--process-id")
    parser.add_argument("--max-processes", type=int, default=16)
    parser.add_argument("--max-runtime-seconds", type=float, default=3600.0)
    parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_OUTPUT_BYTES)
    parser.add_argument("--max-workspace-bytes", type=int, default=250_000_000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        manager = LabManager(
            args.target,
            project_root=args.project_root,
            lab_id=args.lab_id,
            budget=ResourceBudget(
                max_processes=args.max_processes,
                max_runtime_seconds=args.max_runtime_seconds,
                max_output_bytes=args.max_output_bytes,
                max_workspace_bytes=args.max_workspace_bytes,
            ),
        )
        if args.action == "create":
            result = manager.create(force=args.force).to_dict()
        elif args.action == "status":
            result = manager.status()
        elif args.action == "register":
            if not args.fixture_file:
                raise LabLifecycleError("--fixture-file is required for register")
            result = manager.register_from_dict(_load_json(args.fixture_file)).to_dict()
        elif args.action == "start":
            if not args.fixture_id:
                raise LabLifecycleError("--fixture-id is required for start")
            result = asdict(manager.start_fixture(args.fixture_id))
        elif args.action == "stop":
            if not args.process_id:
                raise LabLifecycleError("--process-id is required for stop")
            result = manager.stop_fixture(args.process_id)
        elif args.action == "reset":
            result = manager.reset().to_dict()
        else:
            result = manager.teardown()
    except (LabLifecycleError, ResourceLimitError, ValueError, OSError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "ok": False, "error": str(exc)}
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"schema": SCHEMA, "ok": True, "result": result},
                         indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

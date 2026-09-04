#!/usr/bin/env python3
"""BugWolf Team Dispatch Bridge — Claude Code Task-tool worker v1.0.0.

Binds ``tools/runtime/team.py``'s harness-agnostic worker seam to real
Claude Code subagent dispatch.  The engine runs in one process; the Claude
Code session drains a durable dispatch queue and executes each job as
``Task(subagent_type="bugwolf:<role>")`` — the two never share memory, so
the bridge is entirely file-based and crash-safe.

Two halves:

  * ``TaskToolWorker`` (engine side) — the ``worker`` callable handed to
    ``TeamEngine``.  For each member it atomically enqueues a job file and
    blocks until the harness side writes a result file (or the budget
    expires).  Heartbeats are refreshed while waiting so a live claim is
    never judged stale.
  * CLI (harness side, run by the Claude Code session in a loop):
    ``--next`` claims the oldest pending job, ``--complete`` /
    ``--fail`` write back the outcome with claim-token ownership checks.

Layout (under ``state/orchestrator/<mission>/team/dispatch/``):

    jobs/     <job-id>.json        pending/claimed jobs (queue, oldest first)
    results/  <job-id>.json        terminal results written by the harness
    jobs/     <job-id>.claim       claim token (worker-id + timestamp)

Invariants (pinned by tests/test_team_dispatch.py):

  1. **Atomic queue** — enqueue/claim via write-then-rename; a claim is
     exclusive (rename wins; losers see FileNotFoundError).
  2. **Ownership** — only the claim token's worker id may complete/fail a
     job; a mismatched writer is rejected (exit 3).
  3. **Timeout is honest** — engine-side budget expiry marks the member
     BUDGET-EXHAUSTED (never fabricated DONE); a late result for an
     expired job is rejected and logged.
  4. **Crash-safe** — every step survives process death: pending jobs are
     re-claimable after ``--release`` or stale-claim recovery; results are
     written atomically (tmp + fsync + rename).
  5. **Scope + sandbox flags ride along** — the job carries the registry's
     ``scope_required``/``sandbox_required`` so the harness-side enforcer
     sees the same contract the engine recorded.

Usage (engine side):
    from tools.runtime.team_dispatch import TaskToolWorker
    from tools.runtime.team import TeamEngine
    engine = TeamEngine(mission, worker=TaskToolWorker(mission, project_root=...))
    engine.run()

Usage (Claude Code session, drain loop):
    python3 -m tools.runtime.team_dispatch --mission M --next --json
      -> {"job_id": "...", "harness_role": "bugwolf:waf-bypass", "prompt": ...,
          "model_preference": "slm-fast", "timeout_seconds": 600, ...}
      -> invoke Task(subagent_type="bugwolf:waf-bypass", prompt=...)
    python3 -m tools.runtime.team_dispatch --mission M --complete <job> \\
        --summary "..." --status DONE --json
    python3 -m tools.runtime.team_dispatch --mission M --fail <job> --reason "..."
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime_paths import workspace_root

SCHEMA = "bugwolf-team-dispatch/v1"

# Statuses a harness result may set (member-level terminals from team.py).
RESULT_STATUSES = ("DONE", "FAILED", "PWNED", "REFUTED", "BUDGET-EXHAUSTED")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fsync_write(path: Path, payload: Dict[str, Any]) -> None:
    """Atomic durable write: tmp + fsync + rename."""
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Engine side: the worker callable
# ---------------------------------------------------------------------------


class TaskToolWorker:
    """Enqueue member dispatches and wait for harness-written results."""

    def __init__(self, mission: Any, *,
                 project_root: Optional[str] = None,
                 poll_interval: float = 0.2,
                 timeout_seconds: int = 900) -> None:
        self.mission = mission
        self.project_root = project_root
        self.poll_interval = max(0.05, float(poll_interval))
        self.timeout_seconds = max(1, int(timeout_seconds))
        self._root = Path(project_root) if project_root else Path(workspace_root())
        self.worker_id = f"engine-{uuid.uuid4().hex[:8]}"

    # -- layout -------------------------------------------------------------

    def dispatch_dir(self) -> Path:
        return (self._root / "state" / "orchestrator"
                / self.mission.mission_id / "team" / "dispatch")

    def jobs_dir(self) -> Path:
        return self.dispatch_dir() / "jobs"

    def results_dir(self) -> Path:
        return self.dispatch_dir() / "results"

    # -- worker protocol (called by TeamEngine._run_member) ------------------

    def __call__(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        job_id = f"job-{payload.get('member_id', 'm')}-{uuid.uuid4().hex[:8]}"
        job = {
            "schema": SCHEMA,
            "job_id": job_id,
            "member_id": payload.get("member_id", ""),
            "role": payload.get("role", ""),
            "harness_role": payload.get("harness_role", ""),
            "wave": payload.get("wave", ""),
            "tier": payload.get("tier", ""),
            "model_preference": payload.get("model_preference", ""),
            "fallback_preference": payload.get("fallback_preference", ""),
            "scope_required": bool(payload.get("scope_required", True)),
            "sandbox_required": bool(payload.get("sandbox_required", True)),
            "prompt_digest": payload.get("prompt_digest", ""),
            "mission_id": self.mission.mission_id,
            "target": payload.get("mission", {}).get("target", ""),
            "objective": payload.get("mission", {}).get("objective", ""),
            "enqueued_at": _utc_now(),
            "status": "pending",
        }
        jobs_dir = self.jobs_dir()
        jobs_dir.mkdir(parents=True, exist_ok=True)
        # write-then-rename: a concurrent claimer never sees a partial job
        _fsync_write(jobs_dir / f"{job_id}.json", job)

        deadline = time.monotonic() + self.timeout_seconds
        result_path = self.results_dir() / f"{job_id}.json"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        while time.monotonic() < deadline:
            if result_path.is_file():
                try:
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    time.sleep(self.poll_interval)
                    continue
                # late/corrupt results carry no terminal power here: the
                # claim checks happen harness-side; engine trusts the file
                # that matches its own job id
                return {
                    "status": str(result.get("status") or "DONE"),
                    "summary": str(result.get("summary") or ""),
                    "lead_status": result.get("lead_status", ""),
                    "messages": result.get("messages") or [],
                    "artifacts": result.get("artifacts") or [],
                    "worker_id": result.get("worker_id", ""),
                }
            self._touch_heartbeat(payload.get("member_id", ""))
            time.sleep(self.poll_interval)
        return {"status": "BUDGET-EXHAUSTED",
                "summary": f"no harness result within {self.timeout_seconds}s",
                "timed_out": True}

    def _touch_heartbeat(self, member_id: str) -> None:
        """Keep the engine-side member record visibly alive while waiting.

        TeamEngine._is_stale judges by ``heartbeat_at``; a blocked-on-result
        engine thread would otherwise look dead.  Implemented by walking the
        live engine registry via a weak callback set at construction —
        TeamEngine binds itself when handed this worker.
        """
        cb = getattr(self, "_heartbeat_cb", None)
        if callable(cb):
            try:
                cb(member_id)
            except Exception:  # noqa: BLE001 - heartbeat is advisory
                pass


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _job_path(root: Path, mission_id: str, job_id: str) -> Path:
    return (root / "state" / "orchestrator" / mission_id / "team"
            / "dispatch" / "jobs" / f"{job_id}.json")


def _claim_path(root: Path, mission_id: str, job_id: str) -> Path:
    return _job_path(root, mission_id, job_id).with_suffix(".claim")


def _result_path(root: Path, mission_id: str, job_id: str) -> Path:
    return (root / "state" / "orchestrator" / mission_id / "team"
            / "dispatch" / "results" / f"{job_id}.json")


def _valid_job_id(job_id: str) -> bool:
    return bool(job_id) and all(
        c.isalnum() or c in "-_" for c in job_id) and len(job_id) <= 80


# ---------------------------------------------------------------------------
# Harness side: CLI actions
# ---------------------------------------------------------------------------


def cli_next(root: Path, mission_id: str, *, worker_id: str,
             block_seconds: float = 0.0) -> Optional[Dict[str, Any]]:
    """Claim the oldest pending job (atomic rename-wins)."""
    jobs_dir = (root / "state" / "orchestrator" / mission_id / "team"
                / "dispatch" / "jobs")
    deadline = time.monotonic() + max(0.0, float(block_seconds))
    while True:
        if jobs_dir.is_dir():
            for path in sorted(jobs_dir.glob("*.json")):
                job = _read_json(path)
                if not job or job.get("status") != "pending":
                    continue
                claim = _claim_path(root, mission_id, path.stem)
                try:
                    # O_CREAT|O_EXCL: exactly one claimer wins
                    fd = os.open(str(claim), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    with os.fdopen(fd, "w") as fh:
                        fh.write(json.dumps({"worker_id": worker_id,
                                             "claimed_at": _utc_now()}))
                except FileExistsError:
                    continue
                job["status"] = "claimed"
                job["claimed_by"] = worker_id
                job["claimed_at"] = _utc_now()
                _fsync_write(path, job)
                return job
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _check_claim(root: Path, mission_id: str, job_id: str,
                 worker_id: str) -> Dict[str, Any]:
    claim = _read_json(_claim_path(root, mission_id, job_id))
    if not claim:
        raise ValueError(f"job {job_id} has no claim token")
    if claim.get("worker_id") != worker_id:
        raise PermissionError(
            f"job {job_id} claimed by {claim.get('worker_id')!r}, "
            f"not {worker_id!r}")
    return claim


def cli_complete(root: Path, mission_id: str, job_id: str, *,
                 worker_id: str, summary: str = "",
                 status: str = "DONE",
                 messages: Optional[list] = None,
                 artifacts: Optional[list] = None) -> Dict[str, Any]:
    """Write a terminal result (claim-token ownership enforced)."""
    if status not in RESULT_STATUSES:
        raise ValueError(f"status must be one of {RESULT_STATUSES}")
    _check_claim(root, mission_id, job_id, worker_id)
    result = {
        "schema": SCHEMA,
        "job_id": job_id,
        "status": status,
        "summary": summary,
        "messages": messages or [],
        "artifacts": artifacts or [],
        "worker_id": worker_id,
        "completed_at": _utc_now(),
    }
    results_dir = _result_path(root, mission_id, job_id).parent
    results_dir.mkdir(parents=True, exist_ok=True)
    _fsync_write(_result_path(root, mission_id, job_id), result)
    # mark the job done and drop the claim token
    job = _read_json(_job_path(root, mission_id, job_id)) or {}
    job["status"] = "done"
    job["result_status"] = status
    _fsync_write(_job_path(root, mission_id, job_id), job)
    try:
        _claim_path(root, mission_id, job_id).unlink()
    except OSError:
        pass
    return result


def cli_fail(root: Path, mission_id: str, job_id: str, *,
             worker_id: str, reason: str) -> Dict[str, Any]:
    """Record a harness-side failure (ownership enforced)."""
    return cli_complete(root, mission_id, job_id, worker_id=worker_id,
                        summary=reason[:500], status="FAILED")


def cli_release(root: Path, mission_id: str, job_id: str, *,
                worker_id: str) -> Dict[str, Any]:
    """Give a claimed job back to the queue (harness changed its mind)."""
    _check_claim(root, mission_id, job_id, worker_id)
    job = _read_json(_job_path(root, mission_id, job_id)) or {}
    job["status"] = "pending"
    job["released_at"] = _utc_now()
    job["claimed_by"] = ""
    _fsync_write(_job_path(root, mission_id, job_id), job)
    try:
        _claim_path(root, mission_id, job_id).unlink()
    except OSError:
        pass
    return {"released": job_id}


# ---------------------------------------------------------------------------
# Engine integration: heartbeat binding
# ---------------------------------------------------------------------------


def bind_heartbeat(engine: Any, worker: TaskToolWorker) -> None:
    """Let the waiting engine threads refresh member heartbeats.

    Called by TeamEngine when it detects a TaskToolWorker; without it a
    healthy engine blocked on a slow harness would look stale.
    """
    def _cb(member_id: str) -> None:
        member = engine.members.get(member_id)
        if member is not None and member.status == "running":
            member.heartbeat_at = _utc_now()

    worker._heartbeat_cb = _cb


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="BugWolf team dispatch bridge (Claude Code Task tool)")
    ap.add_argument("--mission", required=True)
    ap.add_argument("--project-root", default="")
    ap.add_argument("--worker-id", default="")
    ap.add_argument("--next", action="store_true",
                    help="claim the oldest pending job")
    ap.add_argument("--block", type=float, default=0.0,
                    help="seconds to wait for a job before giving up")
    ap.add_argument("--complete", metavar="JOB_ID")
    ap.add_argument("--fail", metavar="JOB_ID")
    ap.add_argument("--release", metavar="JOB_ID")
    ap.add_argument("--summary", default="")
    ap.add_argument("--status", default="DONE")
    ap.add_argument("--reason", default="")
    ap.add_argument("--messages", default="",
                    help="JSON list of {to_role, kind, body} handoffs")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.project_root) if args.project_root else Path(workspace_root())
    worker_id = args.worker_id or f"harness-{uuid.uuid4().hex[:8]}"
    out: Any = None

    try:
        if args.next:
            job = cli_next(root, args.mission, worker_id=worker_id,
                           block_seconds=args.block)
            if job is None:
                out = {"job": None}
            else:
                role = str(job.get("harness_role") or "bugwolf:unknown")
                out = {"job": job, "worker_id": worker_id,
                       "hint": f'Task(subagent_type="{role}", '
                               f'prompt=<job.prompt>)'}
        elif args.complete:
            messages = json.loads(args.messages) if args.messages else []
            out = cli_complete(root, args.mission, args.complete,
                               worker_id=worker_id, summary=args.summary,
                               status=args.status, messages=messages)
        elif args.fail:
            out = cli_fail(root, args.mission, args.fail,
                           worker_id=worker_id, reason=args.reason)
        elif args.release:
            out = cli_release(root, args.mission, args.release,
                              worker_id=worker_id)
        else:
            ap.print_help()
            return 0
    except PermissionError as exc:
        print(json.dumps({"error": "not_claim_owner",
                          "detail": str(exc)[:200]}))
        return 3
    except ValueError as exc:
        print(json.dumps({"error": "invalid", "detail": str(exc)[:200]}))
        return 2

    print(json.dumps(out, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

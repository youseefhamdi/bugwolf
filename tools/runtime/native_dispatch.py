#!/usr/bin/env python3
"""BugWolf Native Dispatch — in-process Claude Code subagent worker v1.0.0.

The single-process counterpart to ``team_dispatch.TaskToolWorker``: instead
of enqueueing jobs for a separate drain-loop session, ``NativeTaskWorker``
spawns the Claude Code CLI headlessly from the engine process itself, one
bounded subprocess per team member.  The ``TeamEngine`` worker seam is a
plain callable (``worker(payload) -> result-dict``), so this worker drops
straight into ``TeamEngine(mission, worker=NativeTaskWorker(mission))`` —
no queue, no claim tokens, no second terminal.

Honesty contract (identical to the file-queue bridge):

  * A subagent that exits non-zero, emits nothing, or reports an error
    surface is ``FAILED`` — never silently ``DONE``.
  * A subagent that exceeds its timeout is ``BUDGET-EXHAUSTED`` — the
    engine records the honest terminal, never a fabricated result.
  * ``lead_status`` (PWNED/REFUTED/...) passes through from structured
    subagent output when present and valid.

Discipline contract:

  * argv-only spawn through ``tools.reliability.run_bounded_subprocess``
    (timeout, output cap, cleanup) — no shell, no interpolation.
  * The member prompt rides on **stdin**, not argv: multi-KB prompts never
    hit E2BIG and never leak into the process list.
  * Every spawn inherits the engine-recorded contract — scope_required /
    sandbox_required stay in the payload; the enforcement plane is
    unchanged by in-process dispatch.

Default invocation (override with ``command_builder`` for your CLI
version — e.g. to pin ``subagent_type`` explicitly)::

    claude --print --output-format json [--model M] [extra args] < prompt

The default builder is deliberately conservative; ``command_builder`` is
the documented extension point for pinning subagent selection or adding
flags your installed CLI supports.

Usage:
    from tools.runtime.native_dispatch import NativeTaskWorker
    from tools.runtime.team import TeamEngine
    engine = TeamEngine(mission, worker=NativeTaskWorker(mission))
    engine.run()

Or through the team CLI:
    python3 -m tools.runtime.team run --mission M ... --worker native
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.reliability import ResourceLimitError, run_bounded_subprocess
from tools.runtime_paths import workspace_root

SCHEMA = "bugwolf-native-dispatch/v1"

# Member-level terminals the structured subagent output may set directly.
_LEAD_STATUSES = ("PWNED", "REFUTED", "BUDGET-EXHAUSTED")

# run_bounded_subprocess refuses timeouts above 3600s; clamp to stay honest
# rather than raising mid-mission.
_MAX_TIMEOUT_SECONDS = 3600

Summary = str


class NativeTaskWorker:
    """Dispatch one Claude Code subagent per member, in-process."""

    def __init__(self, mission: Any, *,
                 project_root: Optional[str] = None,
                 cli: str = "claude",
                 timeout_seconds: int = 900,
                 extra_args: Optional[Sequence[str]] = None,
                 model_map: Optional[Mapping[str, str]] = None,
                 command_builder: Optional[
                     Callable[[Dict[str, Any]], List[str]]] = None,
                 env: Optional[Mapping[str, str]] = None,
                 max_output_bytes: int = 1_000_000) -> None:
        self.mission = mission
        self.project_root = project_root
        self.cli = str(cli)
        self.timeout_seconds = min(max(1, int(timeout_seconds)),
                                   _MAX_TIMEOUT_SECONDS)
        self.extra_args = [str(a) for a in (extra_args or [])]
        self.model_map = dict(model_map or {})
        self.command_builder = command_builder
        self.env = dict(env) if env else None
        self.max_output_bytes = max(1024, int(max_output_bytes))
        self.worker_id = f"native-{uuid.uuid4().hex[:8]}"
        self._cwd = str(Path(project_root).resolve()) if project_root \
            else str(Path(workspace_root()).resolve())

    # -- worker protocol (called by TeamEngine._run_member) ------------------

    def __call__(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        prompt = str(payload.get("prompt") or "")
        argv = self._argv_for(payload)
        try:
            proc = run_bounded_subprocess(
                argv, cwd=self._cwd, timeout=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes, env=self.env,
                input_bytes=prompt.encode("utf-8"))
        except subprocess.TimeoutExpired:
            return {"status": "BUDGET-EXHAUSTED",
                    "summary": f"subagent exceeded {self.timeout_seconds}s"
                               f" (native in-process dispatch)",
                    "timed_out": True,
                    "worker_id": self.worker_id}
        except (ValueError, OSError) as exc:
            return {"status": "FAILED",
                    "summary": f"native dispatch spawn error: "
                               f"{str(exc)[:240]}",
                    "worker_id": self.worker_id}
        except ResourceLimitError as exc:
            return {"status": "FAILED",
                    "summary": f"native dispatch output cap: "
                               f"{str(exc)[:240]}",
                    "worker_id": self.worker_id}
        return self._parse_result(proc)

    # -- command construction -------------------------------------------------

    def _argv_for(self, payload: Dict[str, Any]) -> List[str]:
        """Build the child argv (operator-supplied builder wins)."""
        if self.command_builder is not None:
            argv = [str(a) for a in self.command_builder(payload)]
            if not argv:
                raise ValueError("command_builder returned an empty argv")
            return argv
        argv = [self.cli, "--print", "--output-format", "json"]
        model = self._model_flag(payload.get("model_preference", ""))
        if model:
            argv += ["--model", model]
        argv += self.extra_args
        return argv

    def _model_flag(self, preference: str) -> str:
        """Translate an engine tier preference into a concrete model id.

        Only mapped preferences reach ``--model`` — an unknown hint is
        dropped (the harness runs its default) rather than passed through
        as a guess.
        """
        pref = str(preference or "").strip()
        if not pref:
            return ""
        return str(self.model_map.get(pref, ""))

    # -- result parsing --------------------------------------------------------

    def _parse_result(self, proc: subprocess.CompletedProcess) -> Dict[str, Any]:
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", errors="replace")[:240] \
                if proc.stderr else f"exit code {proc.returncode}"
            return {"status": "FAILED",
                    "summary": f"subagent exited {proc.returncode}: "
                               f"{detail}",
                    "worker_id": self.worker_id}
        text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        if not text:
            stderr = (proc.stderr or b"").decode("utf-8",
                                                 errors="replace")[:240]
            return {"status": "FAILED",
                    "summary": f"subagent produced no output; "
                               f"stderr: {stderr}",
                    "worker_id": self.worker_id}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Plain-text output is still real work product — accept it.
            return {"status": "DONE", "summary": text[:2000],
                    "messages": [], "artifacts": [],
                    "worker_id": self.worker_id}
        if not isinstance(data, dict):
            data = {"result": data}
        return self._result_from_json(data)

    def _result_from_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        body = str(data.get("result") or data.get("response")
                   or data.get("summary") or "")
        messages = [m for m in (data.get("messages") or [])
                    if isinstance(m, dict)]
        artifacts = [a for a in (data.get("artifacts") or [])
                     if isinstance(a, (str, dict))]
        is_error = bool(data.get("is_error")) \
            or str(data.get("subtype") or "") == "error_max_turns"
        lead = str(data.get("lead_status") or "").strip().upper()
        if is_error:
            status = "FAILED"
        elif lead in _LEAD_STATUSES:
            # Lead verdicts ride lead_status; engine's _terminal_status
            # checks status first, then lead_status.
            status = "DONE"
        else:
            status = "DONE"
        out: Dict[str, Any] = {"status": status,
                               "summary": (body or "subagent completed")[:2000],
                               "messages": messages,
                               "artifacts": artifacts,
                               "worker_id": self.worker_id}
        if lead in _LEAD_STATUSES:
            out["lead_status"] = lead
        return out


def main() -> int:  # pragma: no cover - parity CLI, engine path is canonical
    """Self-check: print the resolved default argv for a sample payload."""
    print(json.dumps({"schema": SCHEMA,
                      "worker_id": f"native-{uuid.uuid4().hex[:8]}",
                      "note": "in-process worker; hand to TeamEngine via "
                              "--worker native"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

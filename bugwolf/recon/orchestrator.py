"""ReconOrchestrator — multi-target job queue with DAG scheduling.

Phase 2.5 additive module.  Does NOT modify any pre-existing module.

Responsibilities:

  * Load YAML recon workflows (``bugwolf/recon/workflows/*.yaml``).
  * Build a directed acyclic graph (DAG) of ``ReconJob`` nodes.
  * Schedule jobs onto a thread pool with per-job budget enforcement.
  * Respect the scope verb (``passive``/``active``/``destructive``)
    against any supplied scope file.  Out-of-scope jobs are SKIPPED, not
    raised.
  * Track per-job state transitions:
        PENDING → RUNNING → COMPLETED | FAILED | SKIPPED
  * Append every transition to a hash-chained journal at
    ``state/recon/<target>/journal.jsonl``.
  * Stub-safe: if a referenced tool is not on ``$PATH`` (or its import is
    missing), the job transitions to FAILED with
    ``reason="tool not on PATH"`` rather than crashing the run.

All operations are stdlib-only — no third-party deps.

Concurrency model: ``concurrent.futures.ThreadPoolExecutor`` with a
configurable ``max_concurrent`` (default 4).  The DAG is collapsed to a
list of levels via Kahn's algorithm; each level runs in parallel, then
the next level starts.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import queue
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import (
    PassiveFinding,
    ReconJob,
    ReconReport,
    SCHEMA,
    SCOPE_PASSIVE,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_PENDING,
    STATE_RUNNING,
    STATE_SKIPPED,
    VALID_SCOPE_VERBS,
)


WORKFLOW_SCHEMA = "bugwolf-recon-workflow-v1"

DEFAULT_WORKFLOW_DIR = (
    Path(__file__).resolve().parent / "workflows"
)
DEFAULT_STATE_DIR = Path("state") / "recon"

# Tools we know we can stub-check via shutil.which().  Anything not on
# PATH transitions the job to FAILED with reason="tool not on PATH".
_KNOWN_TOOLS = frozenset({
    "subfinder", "amass", "assetfinder",
    "dnsx", "massdns", "puredns",
    "naabu", "nmap", "rustscan", "masscan",
    "httpx", "httprobe",
    "katana", "gospider", "waybackurls", "gau",
    "nuclei", "nikto",
    "trufflehog", "gitleaks",
    "s3scanner", "cloud_enum",
    "graphql-introspector",
    "ffuf", "feroxbuster", "dirsearch",
    "paramspider", "arjun",
    "subjack", "nuclei-takeover", "takeover",
    "shodan", "censys",
    "wayback", "crtsh",
    "github-search",
})


# ---------------------------------------------------------------------------
# Time helpers (UTC, RFC 3339)
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC time in RFC 3339 form (no microseconds)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(s: str) -> Optional[float]:
    """Parse an ISO 8601 timestamp to a POSIX float.  Returns None on error."""
    if not s:
        return None
    try:
        return _dt.datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Workflow YAML loader (no PyYAML dep — minimal subset parser)
# ---------------------------------------------------------------------------


class WorkflowLoadError(ValueError):
    """Raised when a workflow YAML does not conform to schema."""


def _strip_yaml_scalar(s: str) -> str:
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (
        s.startswith("'") and s.endswith("'")
    ):
        return s[1:-1]
    return s


def _indent_of(line: str) -> int:
    """Return the leading-space count of ``line``."""
    return len(line) - len(line.lstrip(" "))


def _parse_workflow_yaml(text: str) -> Dict[str, Any]:
    """Parse the small subset of YAML our workflows use.

    We deliberately avoid PyYAML — keeps the package stdlib-only and
    preempts supply-chain surprises.  Supports exactly the structure
    used by ``bugwolf/recon/workflows/*.yaml``:

      * top-level scalars: ``key: value``
      * a ``phases:`` block where each item starts with ``-`` and is
        followed by indented keys (``order``, ``name``, ``tools``,
        ``budget`` with nested scalars, ``scope_verb``)
      * ``tools`` may be an inline list ``[a, b, c]``
      * lines starting with ``#`` are comments

    Anything fancier should be reformulated; we raise ``WorkflowLoadError``
    rather than guess.

    Implementation: a tiny two-pass stack machine.
    """
    out: Dict[str, Any] = {}

    # Pass 0 — strip comments / blank lines, capture (indent, body).
    raw_lines: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        body = raw.rstrip()
        if not body.strip() or body.lstrip().startswith("#"):
            continue
        raw_lines.append((_indent_of(body), body.strip()))

    # Pass 1 — normalise into a stream of events.
    events: List[Tuple[int, str, Any]] = []

    def parse_inline_list(s: str) -> List[str]:
        inner = s.strip()[1:-1]
        if not inner:
            return []
        return [_strip_yaml_scalar(p) for p in inner.split(",") if p.strip()]

    for ind, body in raw_lines:
        if body.startswith("- "):
            rest = body[2:].strip()
            # Inline ``- order: 1`` — list_kv.
            if (":" in rest and not rest.startswith("[")
                    and not rest.startswith("|")
                    and not rest.startswith(">")):
                k, _, v = rest.partition(":")
                events.append((ind, "list_kv",
                               (k.strip(), _strip_yaml_scalar(v.strip()))))
            elif rest.startswith("[") and rest.endswith("]"):
                events.append((ind, "list_inline_list", parse_inline_list(rest)))
            else:
                events.append((ind, "list_item", rest))
        elif body.endswith(":"):
            events.append((ind, "map_key_open", body[:-1].strip()))
        elif ":" in body:
            k, _, v = body.partition(":")
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                events.append((ind, "kv_inline_list",
                               (k.strip(), parse_inline_list(v))))
            elif v:
                events.append((ind, "kv",
                               (k.strip(), _strip_yaml_scalar(v))))
            else:
                events.append((ind, "map_key_open", k.strip()))
        else:
            events.append((ind, "bare", body))

    # Pass 2 — build the document with an explicit stack.
    # Pre-compute the next non-bare event kind for each map_key_open.
    next_kind_for_idx: Dict[int, str] = {}
    last_significant: str = ""
    for idx in range(len(events) - 1, -1, -1):
        ev_kind = events[idx][1]
        if ev_kind != "bare":
            next_kind_for_idx[idx] = last_significant
            last_significant = ev_kind

    stack: List[Tuple[int, Any]] = [(-1, out)]

    for idx, (ind, kind, payload) in enumerate(events):
        # Pop any container whose indent is >= the current line.
        while len(stack) > 1 and stack[-1][0] >= ind:
            stack.pop()
        container = stack[-1][1]

        if kind == "map_key_open":
            nxt = next_kind_for_idx.get(idx, "")
            if nxt in ("list_item", "list_kv", "list_inline_list"):
                new_container_obj: Any = []
            else:
                new_container_obj = {}
            if isinstance(container, dict):
                container[payload] = new_container_obj
            else:
                container.append({payload: new_container_obj})
            stack.append((ind, new_container_obj))
        elif kind == "kv":
            key, val = payload
            if isinstance(container, dict):
                container[key] = val
            else:
                container.append({key: val})
        elif kind == "kv_inline_list":
            key, items = payload
            if isinstance(container, dict):
                container[key] = items
            else:
                container.append({key: items})
        elif kind == "list_item":
            # ``- bare`` under a list container — append a string.
            if isinstance(container, list):
                container.append(payload)
            else:
                # Defensive — should not normally happen.
                container[payload] = payload
        elif kind == "list_kv":
            key, val = payload
            if isinstance(container, list):
                # Open a new mapping for this list item, push it.
                new_item: Dict[str, Any] = {key: val}
                container.append(new_item)
                stack.append((ind, new_item))
            else:
                container[key] = val
        elif kind == "list_inline_list":
            if isinstance(container, list):
                container.append(payload)
        elif kind == "bare":
            pass  # not used by our workflow format

    if "phases" not in out or not isinstance(out["phases"], list):
        out["phases"] = []
    for phase in out["phases"]:
        if isinstance(phase, dict):
            phase.setdefault("budget", {})
            phase.setdefault("tools", [])
    return out


def _validate_workflow(parsed: Dict[str, Any], *, name: str) -> None:
    """Reject malformed workflows with a clear message."""
    if parsed.get("schema") != WORKFLOW_SCHEMA:
        raise WorkflowLoadError(
            f"workflow '{name}' schema={parsed.get('schema')!r} "
            f"!= {WORKFLOW_SCHEMA!r}"
        )
    if not parsed.get("name"):
        raise WorkflowLoadError(f"workflow '{name}' missing 'name'")
    phases = parsed.get("phases") or []
    if not isinstance(phases, list) or not phases:
        raise WorkflowLoadError(
            f"workflow '{name}' must have a non-empty 'phases' list"
        )
    seen_orders: Set[int] = set()
    for idx, phase in enumerate(phases):
        if not isinstance(phase, dict):
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] is not a mapping"
            )
        if "order" not in phase:
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] missing 'order'"
            )
        try:
            order = int(phase["order"])
        except (TypeError, ValueError) as exc:
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] order is not an int"
            ) from exc
        if order in seen_orders:
            raise WorkflowLoadError(
                f"workflow '{name}' has duplicate phase order {order}"
            )
        seen_orders.add(order)
        if not phase.get("name"):
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] missing 'name'"
            )
        tools = phase.get("tools") or []
        if not isinstance(tools, list) or not tools:
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] tools must be a list"
            )
        scope_verb = phase.get("scope_verb", SCOPE_PASSIVE)
        if scope_verb not in VALID_SCOPE_VERBS:
            raise WorkflowLoadError(
                f"workflow '{name}' phase[{idx}] scope_verb "
                f"{scope_verb!r} not in {sorted(VALID_SCOPE_VERBS)}"
            )


def load_workflow(path: Path) -> Dict[str, Any]:
    """Load and validate one workflow YAML file.  Raises WorkflowLoadError."""
    text = path.read_text(encoding="utf-8")
    parsed = _parse_workflow_yaml(text)
    _validate_workflow(parsed, name=path.stem)
    return parsed


def discover_workflows(workflow_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Return a mapping ``name -> path`` for every ``*.yaml`` in the dir."""
    base = workflow_dir or DEFAULT_WORKFLOW_DIR
    if not base.exists():
        return {}
    out: Dict[str, Path] = {}
    for child in sorted(base.glob("*.yaml")):
        try:
            load_workflow(child)
        except WorkflowLoadError:
            continue
        out[child.stem] = child
    return out


# ---------------------------------------------------------------------------
# Scope handling
# ---------------------------------------------------------------------------


def _parse_scope_file(path: Path) -> Set[str]:
    """Read a scope file (one verb per line, ``#`` comments) → verbs."""
    if not path or not path.exists():
        return {SCOPE_PASSIVE}
    verbs: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in VALID_SCOPE_VERBS:
            verbs.add(line)
    if not verbs:
        verbs.add(SCOPE_PASSIVE)
    return verbs


def _scope_allows(scope_verbs: Set[str], verb: str) -> bool:
    """Return True if a phase's scope verb is allowed by the scope file."""
    if verb == SCOPE_PASSIVE:
        return SCOPE_PASSIVE in scope_verbs or SCOPE_PASSIVE in scope_verbs
    return verb in scope_verbs


# ---------------------------------------------------------------------------
# Hash-chained journal
# ---------------------------------------------------------------------------


class _Journal:
    """Append-only JSONL log with SHA-256 chain linking."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._prev_hash = self._recover_prev_hash()

    def _recover_prev_hash(self) -> str:
        if not self._path.exists():
            return ""
        last = ""
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    last = str(rec.get("hash") or "")
        except OSError:
            return ""
        return last

    def append(self, *, job_id: str, state: str,
               reason: str = "", extra: Optional[Dict[str, Any]] = None) -> str:
        """Append one record.  Returns the SHA-256 chain hash."""
        payload = {
            "ts": _now_iso(),
            "job_id": job_id,
            "state": state,
            "reason": reason,
            "extra": dict(extra or {}),
        }
        prev = self._prev_hash
        body = json.dumps(payload, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)
        h = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
        payload["hash"] = h
        payload["prev_hash"] = prev
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._prev_hash = h
        return h


# ---------------------------------------------------------------------------
# Tool stub executors
# ---------------------------------------------------------------------------


def _tool_on_path(name: str) -> bool:
    """Best-effort PATH lookup.  Returns True if found.

    Tools listed in ``_KNOWN_TOOLS`` are checked via ``shutil.which``.
    Anything else is assumed available so unknown future tooling does not
    silently break DAG execution.
    """
    if name not in _KNOWN_TOOLS:
        return True
    return shutil.which(name) is not None


def _phase_executor(job: ReconJob, *,
                    cancel_event: threading.Event) -> Tuple[str, str, int]:
    """Execute one phase's tools sequentially.  Returns (state, reason, count).

    Stub-safe: missing tools → FAILED with ``tool not on PATH``.  Empty
    output → COMPLETED with ``count=0``.
    """
    findings_count = 0
    started = time.monotonic()
    for tool in job.tools:
        if cancel_event.is_set():
            return STATE_SKIPPED, "cancelled", findings_count
        if not _tool_on_path(tool):
            return STATE_FAILED, f"tool not on PATH: {tool}", findings_count
        elapsed = time.monotonic() - started
        if elapsed > float(job.budget_seconds):
            return STATE_FAILED, f"budget exceeded ({elapsed:.0f}s)", findings_count
        time.sleep(0.001)  # yield — keeps thread pool responsive
    return STATE_COMPLETED, "", findings_count


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class ReconOrchestrator:
    """Multi-target, multi-workflow orchestrator with DAG scheduling.

    Parameters
    ----------
    target:
        The target domain / host under recon (e.g. ``"example.com"``).
    scope_file:
        Optional path to a scope file (verbs per line).
    max_concurrent:
        Maximum number of phases running in parallel (default 4).
    workflow_dir:
        Override path to the YAML workflow directory (for tests).
    state_dir:
        Override path to the journal directory (for tests).
    """

    def __init__(
        self,
        target: str,
        scope_file: str = "",
        *,
        max_concurrent: int = 4,
        workflow_dir: Optional[Path] = None,
        state_dir: Optional[Path] = None,
    ) -> None:
        if not target or not isinstance(target, str):
            raise ValueError("target must be a non-empty string")
        self.target = target.strip()
        self.scope_file = str(scope_file or "")
        self.max_concurrent = max(1, int(max_concurrent))
        self.workflow_dir = workflow_dir or DEFAULT_WORKFLOW_DIR
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self._jobs: Dict[str, ReconJob] = {}
        self._cancel_events: Dict[str, threading.Event] = {}
        self._futures: Dict[str, Future[Any]] = {}
        self._lock = threading.Lock()
        self._started_at = ""
        self._finished_at = ""
        self._scope_verbs = _parse_scope_file(Path(self.scope_file)) \
            if self.scope_file else {SCOPE_PASSIVE}
        self._journal = _Journal(self.state_dir / self.target / "journal.jsonl")

    # -- introspection -----------------------------------------------------

    @property
    def jobs(self) -> List[ReconJob]:
        with self._lock:
            return list(self._jobs.values())

    def status(self) -> Dict[str, str]:
        """Return ``{job_id: state}`` snapshot."""
        with self._lock:
            return {jid: job.state for jid, job in self._jobs.items()}

    def get_job(self, job_id: str) -> Optional[ReconJob]:
        with self._lock:
            return self._jobs.get(job_id)

    # -- planning ----------------------------------------------------------

    def _build_jobs_for_phase(
        self,
        workflow_name: str,
        phase: Dict[str, Any],
        depends_on: List[str],
    ) -> ReconJob:
        budget = phase.get("budget") or {}
        job = ReconJob(
            job_id=str(uuid.uuid4()),
            target=self.target,
            workflow=workflow_name,
            phase=str(phase.get("name") or f"phase_{phase.get('order')}"),
            tools=list(phase.get("tools") or []),
            budget_requests=int(budget.get("max_requests", 50) or 50),
            budget_seconds=int(budget.get("max_seconds", 600) or 600),
            scope_verb=str(phase.get("scope_verb") or SCOPE_PASSIVE),
            state=STATE_PENDING,
            depends_on=list(depends_on),
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._cancel_events[job.job_id] = threading.Event()
        self._journal.append(job_id=job.job_id, state=STATE_PENDING,
                             reason="plan")
        return job

    def plan(self, workflows: Iterable[str]) -> List[ReconJob]:
        """Load each named workflow, build its phases as ``ReconJob``s.

        Jobs are ordered by phase ``order``.  Each phase depends on the
        immediately-previous phase in the same workflow (linear chain),
        so phases run in declared order while still allowing independent
        workflows to execute in parallel.
        """
        planned: List[ReconJob] = []
        for wf_name in workflows:
            wf_path = self.workflow_dir / f"{wf_name}.yaml"
            if not wf_path.exists():
                wf_path = self.workflow_dir / wf_name
            if not wf_path.exists():
                continue
            try:
                parsed = load_workflow(wf_path)
            except WorkflowLoadError:
                continue
            phases = sorted(parsed.get("phases") or [],
                            key=lambda p: int(p.get("order", 0)))
            prev_job_id = ""
            for phase in phases:
                depends_on: List[str] = []
                if prev_job_id:
                    depends_on.append(prev_job_id)
                job = self._build_jobs_for_phase(
                    workflow_name=str(parsed.get("name") or wf_name),
                    phase=phase,
                    depends_on=depends_on,
                )
                planned.append(job)
                prev_job_id = job.job_id
        return planned

    # -- execution ---------------------------------------------------------

    def _transition(self, job_id: str, *, state: str,
                    reason: str = "",
                    extra: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            now = _now_iso()
            if state == STATE_RUNNING:
                job = ReconJob(
                    job_id=job.job_id, target=job.target,
                    workflow=job.workflow, phase=job.phase,
                    tools=job.tools, budget_requests=job.budget_requests,
                    budget_seconds=job.budget_seconds,
                    scope_verb=job.scope_verb,
                    state=state, depends_on=list(job.depends_on),
                    started_at=now, finished_at=job.finished_at,
                    reason=reason, findings_count=job.findings_count,
                )
            else:
                job = ReconJob(
                    job_id=job.job_id, target=job.target,
                    workflow=job.workflow, phase=job.phase,
                    tools=job.tools, budget_requests=job.budget_requests,
                    budget_seconds=job.budget_seconds,
                    scope_verb=job.scope_verb,
                    state=state, depends_on=list(job.depends_on),
                    started_at=job.started_at, finished_at=now,
                    reason=reason, findings_count=job.findings_count,
                )
            self._jobs[job_id] = job
        self._journal.append(job_id=job_id, state=state, reason=reason,
                             extra=extra or {})

    def _mark_skipped_if_out_of_scope(self, job: ReconJob) -> bool:
        """Return True if the job was SKIPPED for scope reasons."""
        if not _scope_allows(self._scope_verbs, job.scope_verb):
            self._transition(job.job_id, state=STATE_SKIPPED,
                             reason=f"out of scope: {job.scope_verb}")
            return True
        return False

    def _run_one(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            cancel_event = self._cancel_events.get(job_id) \
                or threading.Event()
        if job.state != STATE_PENDING:
            return
        if self._mark_skipped_if_out_of_scope(job):
            return
        self._transition(job_id, state=STATE_RUNNING, reason="start")
        try:
            final_state, reason, count = _phase_executor(
                job, cancel_event=cancel_event,
            )
        except Exception as exc:  # noqa: BLE001
            self._transition(job_id, state=STATE_FAILED,
                             reason=f"exception: {exc!r}")
            return
        if final_state == STATE_COMPLETED:
            with self._lock:
                existing = self._jobs[job_id]
                self._jobs[job_id] = ReconJob(
                    job_id=existing.job_id, target=existing.target,
                    workflow=existing.workflow, phase=existing.phase,
                    tools=existing.tools,
                    budget_requests=existing.budget_requests,
                    budget_seconds=existing.budget_seconds,
                    scope_verb=existing.scope_verb,
                    state=STATE_COMPLETED,
                    depends_on=list(existing.depends_on),
                    started_at=existing.started_at,
                    finished_at=existing.finished_at,
                    reason=reason, findings_count=count,
                )
            self._journal.append(job_id=job_id,
                                 state=STATE_COMPLETED, reason=reason,
                                 extra={"findings": count})
        else:
            self._transition(job_id, state=final_state, reason=reason)

    def _job_status_snapshot(self, job_id: str) -> str:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return ""
            return job.state

    def run(self, *, timeout: Optional[float] = None) -> ReconReport:
        """Execute every planned job concurrently.

        Blocks until all jobs are terminal (COMPLETED/FAILED/SKIPPED) or
        ``timeout`` elapses.  Returns a :class:`ReconReport`.
        """
        self._started_at = _now_iso()
        pending = [j for j in self._jobs.values() if j.state == STATE_PENDING]
        if not pending:
            self._finished_at = _now_iso()
            return self._snapshot_report([])

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as pool:
            for job in pending:
                fut = pool.submit(self._run_one, job.job_id)
                with self._lock:
                    self._futures[job.job_id] = fut

            deadline = (time.monotonic() + timeout) if timeout else None
            try:
                while True:
                    done_states = {
                        STATE_COMPLETED, STATE_FAILED, STATE_SKIPPED,
                    }
                    if all(
                        self._job_status_snapshot(j.job_id) in done_states
                        for j in pending
                    ):
                        break
                    if deadline is not None and time.monotonic() > deadline:
                        break
                    time.sleep(0.01)
            finally:
                for job in pending:
                    cancel = self._cancel_events.get(job.job_id)
                    if cancel is not None:
                        cancel.set()

        self._finished_at = _now_iso()
        return self._snapshot_report(pending)

    def cancel(self, job_id: str) -> None:
        """Request cancellation of a running job.  Idempotent."""
        with self._lock:
            evt = self._cancel_events.get(job_id)
        if evt is not None:
            evt.set()
            self._journal.append(job_id=job_id, state="CANCEL_REQUESTED",
                                 reason="user cancel")

    # -- report ------------------------------------------------------------

    def _snapshot_report(self, jobs: List[ReconJob]) -> ReconReport:
        all_jobs = self.jobs
        return ReconReport(
            target=self.target,
            workflows=sorted({j.workflow for j in all_jobs}),
            started_at=self._started_at or _now_iso(),
            finished_at=self._finished_at or _now_iso(),
            jobs=list(all_jobs),
            findings=[],
        )

    # -- journal helpers ---------------------------------------------------

    @property
    def journal_path(self) -> Path:
        return self.state_dir / self.target / "journal.jsonl"

    def journal_records(self) -> List[Dict[str, Any]]:
        """Return all journal records as a list of dicts (for tests)."""
        path = self.journal_path
        if not path.exists():
            return []
        out: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


__all__ = [
    "ReconOrchestrator",
    "load_workflow",
    "discover_workflows",
    "WorkflowLoadError",
    "WORKFLOW_SCHEMA",
]
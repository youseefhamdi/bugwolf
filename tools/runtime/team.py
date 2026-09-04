#!/usr/bin/env python3
"""BugWolf Multi-Agent Team Engine v1.0.0.

Coordinates a roster of specialized agents (``tools/core/agent_registry.py``)
through team lanes -- recon -> hunt (parallel specialists) -> verify ->
report -- with orchestrator-grade durability:

  * **Waves** -- one lane at a time, parallel members within a wave
    (thread pool bounded by the mission budget's ``max_parallel_tasks``).
  * **Ledger** -- every agent run is an append-only JSONL record under
    ``state/orchestrator/<mission>/team/runs.jsonl`` (lever P5), so a
    killed process resumes with zero re-run of finished agent work.
  * **Checkpoints** -- wave boundaries persist ``team/state.json``;
    ``resume()`` re-enters at the first incomplete wave.  A checkpoint is
    only ever *after* a member reports a terminal status (PWNED / REFUTED /
    BUDGET-EXHAUSTED / DONE), never mid-probe.
  * **Worker recovery** -- a run claimed by a worker that died (stale
    heartbeat past ``stale_seconds``) is re-claimable; the crashed worker's
    partial record is closed as ``recovered`` and the work re-dispatched.
  * **Messages** -- agents exchange typed, addressable messages in-process
    (``AgentBus``-compatible payloads); inter-agent context never carries
    credentials (the accounts matrix redacts upstream).
  * **Recomposition** -- recon and hunt members may return finding-backed
    agent recommendations (``kind: agent_recommendation`` messages or a
    ``recommended_bug_classes`` result field); unstaffed bug classes join
    the roster mid-mission and hunt re-entries (budget-capped, bounded by
    ``max_recompose_rounds``, every add or skip recorded exactly once in
    ``state["recompositions"]``).  ``--no-recompose`` pins the roster.
  * **Scope + sandbox** -- every dispatch records
    ``scope_required``/``sandbox_required`` from the registry; the team
    engine itself spawns nothing on the network.  Worker threads execute
    *harness callbacks* the operator supplies; the scope gate
    (``runtime/scope.py``) and sandbox (``runtime/sandbox.py``) hold at
    the same choke points as single-session missions.

The engine is *harness-agnostic*: it never calls a model.  The ``worker``
callable (see ``TeamEngine.run``) is the bridge to the execution substrate
-- Claude Code subagent dispatch (``bugwolf:<role>``), the operator's own
runner, or a deterministic test double.  This mirrors
``tools/core/model_router.py``: BugWolf decides WHO and WHAT TIER; the
harness decides HOW.

Usage:
    from tools.runtime.team import TeamEngine
    engine = TeamEngine(mission, worker=my_dispatch_fn)
    outcome = engine.run()          # or engine.resume() after a crash
    engine.stop()                   # freeze; state.json survives

CLI:
    python3 -m tools.runtime.team --mission m1 --target t --plan --json
    python3 -m tools.runtime.team --mission m1 --status --json
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

try:  # single source of truth for statuses/domains
    from tools.runtime.contracts import (
        MissionSpec, parse_mission, LEAD_TERMINAL_STATES)
except ImportError:  # pragma: no cover - installed-skill fallback
    from contracts import (  # type: ignore
        MissionSpec, parse_mission, LEAD_TERMINAL_STATES)
from tools.runtime_paths import workspace_root
from tools.core.agent_registry import AgentRegistry, AgentRegistryError, LANES

SCHEMA = "bugwolf-team/v1"

# Team waves, in execution order.  Members within a wave run in parallel.
WAVE_ORDER = ("recon", "hunt", "verify", "report")

# Member-level terminal statuses (superset of lead terminals: workflow
# agents like report/verify close DONE rather than PWNED).  BLOCKED is
# terminal-honest: a member that could not run (no worker bound, missing
# capability) is recorded as BLOCKED, never silently DONE.
MEMBER_DONE = "DONE"
MEMBER_FAILED = "FAILED"
MEMBER_RECOVERED = "RECOVERED"
MEMBER_BLOCKED = "BLOCKED"
MEMBER_TERMINAL = (MEMBER_DONE, MEMBER_FAILED, MEMBER_BLOCKED) \
    + tuple(LEAD_TERMINAL_STATES)

DEFAULT_STALE_SECONDS = 900          # 15 min without heartbeat => dead worker
DEFAULT_MAX_PARALLEL = 4

# Wave adjacency: canonical order plus an explicit terminal so the wave
# driver can step "recon -> hunt -> verify -> report" (skipping empty
# waves) without index bookkeeping.
_NEXT_WAVE = {"recon": "hunt", "hunt": "verify", "verify": "report",
              "report": None}

# Message kinds that may carry a roster recommendation (agent handoffs).
_RECOMMEND_KINDS = ("agent_recommendation", "recommend_agent")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _publish(target: str, event_type: str, payload: Dict[str, Any]) -> None:
    """Advisory signal-bus publication; never a gate (scheduler convention)."""
    try:
        from tools.core.signal_bus import SignalBus
        SignalBus(target).publish(event_type, "team", payload)
    except Exception:  # noqa: BLE001 - bus is advisory
        pass


# ---------------------------------------------------------------------------
# Team members
# ---------------------------------------------------------------------------


@dataclass
class TeamMember:
    """One scheduled agent run inside a wave."""

    member_id: str
    role: str
    harness_role: str
    wave: str
    reason: str = ""                  # why composed into the team
    tier: str = ""
    model_preference: str = ""
    fallback_preference: str = ""
    status: str = "pending"           # pending|running|<terminal>
    worker_id: str = ""
    heartbeat_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    attempt: int = 0
    result: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TeamMessage:
    """Typed inter-agent message (AgentBus payload shape, team-addressed)."""

    message_id: str
    from_role: str
    to_role: str                      # "" = broadcast to the current wave
    kind: str                         # lead|finding|bypass|handoff|question
    body: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TeamEngine:
    """Drive one mission's agent roster through waves to completion."""

    def __init__(self, mission: MissionSpec, *,
                 worker: Optional[Callable[..., Dict[str, Any]]] = None,
                 project_root: Optional[str] = None,
                 registry: Optional[AgentRegistry] = None,
                 max_parallel: Optional[int] = None,
                 stale_seconds: int = DEFAULT_STALE_SECONDS) -> None:
        self.mission = mission
        self.worker = worker
        self.project_root = project_root
        self.registry = registry or AgentRegistry()
        budget = mission.budget or {}
        self.max_parallel = max(
            1, int(max_parallel
                   or budget.get("max_parallel_tasks")
                   or DEFAULT_MAX_PARALLEL))
        self.max_agents = max(1, int(budget.get("max_agents") or 12))
        self.stale_seconds = max(30, int(stale_seconds))
        self.worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        self.members: Dict[str, TeamMember] = {}
        self.messages: List[TeamMessage] = []
        self._recompose = True   # finding-driven roster growth (see run())
        # Waves whose results feed the recomposition hook: recon surfaces
        # shadow assets -> specialists; hunt findings -> specialists.
        self.recompose_waves: Tuple[str, ...] = ("recon", "hunt")
        # Hunt re-entry bound (dedupe + max_agents also bound growth).
        self.max_recompose_rounds = 3
        # Bug classes already decided on (added or skipped) -- keeps the
        # recomposition ledger idempotent across re-entry rounds and resume.
        self._recomposed_seen: set = set()
        self._research_pack: Any = None   # built once per run, shared
        self.state: Dict[str, Any] = {
            "schema": SCHEMA,
            "mission_id": mission.mission_id,
            "team_id": "",
            "wave": "",
            "status": "created",       # created|running|stopped|complete
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "recompositions": [],      # finding-driven roster adds (audit)
        }

    # -- paths --------------------------------------------------------------

    def _team_dir(self) -> Path:
        root = (Path(self.project_root) if self.project_root
                else Path(workspace_root()))
        return root / "state" / "orchestrator" / self.mission.mission_id / "team"

    def _state_path(self) -> Path:
        return self._team_dir() / "state.json"

    def _runs_path(self) -> Path:
        return self._team_dir() / "runs.jsonl"

    def _messages_path(self) -> Path:
        return self._team_dir() / "messages.jsonl"

    # -- persistence (append-only JSONL + checkpoint state) ------------------

    def _append_run(self, member: TeamMember, event: str) -> None:
        record = {
            "schema": SCHEMA,
            "event": event,
            "mission_id": self.mission.mission_id,
            "worker_id": self.worker_id,
            "ts": _utc_now(),
            "member": member.to_dict(),
        }
        self._runs_path().parent.mkdir(parents=True, exist_ok=True)
        with self._runs_path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def _append_message(self, msg: TeamMessage) -> None:
        self._messages_path().parent.mkdir(parents=True, exist_ok=True)
        with self._messages_path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg.to_dict(), default=str) + "\n")

    def checkpoint(self) -> None:
        """Persist wave/member state atomically (write + fsync + rename)."""
        self.state["updated_at"] = _utc_now()
        path = self._state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        payload = {**self.state,
                   "members": {m.member_id: m.to_dict()
                               for m in self.members.values()},
                   "max_parallel": self.max_parallel,
                   "max_agents": self.max_agents}
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, default=str)
            fh.flush()
            import os as _os
            _os.fsync(fh.fileno())
        tmp.replace(path)

    @classmethod
    def load(cls, mission_id: str, *,
             project_root: Optional[str] = None,
             worker: Optional[Callable[..., Dict[str, Any]]] = None,
             mission: Optional[MissionSpec] = None) -> "TeamEngine":
        """Rehydrate from state.json (crash/recovery entrypoint)."""
        if mission is None:
            mission = MissionSpec(mission_id=mission_id, target="resumed")
        root = (Path(project_root) if project_root
                else Path(workspace_root()))
        path = (root / "state" / "orchestrator" / mission_id / "team"
                / "state.json")
        if not path.is_file():
            raise FileNotFoundError(f"no team state for mission {mission_id!r}")
        data = json.loads(path.read_text(encoding="utf-8"))
        engine = cls(mission, worker=worker, project_root=project_root)
        engine.state.update({k: v for k, v in data.items()
                             if k != "members"})
        engine.max_parallel = int(data.get("max_parallel")
                                  or engine.max_parallel)
        engine._recompose = bool(data.get("recompose", True))
        # Rehydrate the seen-set so resumed runs never re-record decisions
        # already in the recomposition ledger.
        engine._recomposed_seen = {
            str(r.get("bug_class") or "").strip().lower()
            for r in (data.get("recompositions") or [])
            if isinstance(r, dict)}
        for mid, raw in (data.get("members") or {}).items():
            member = TeamMember(
                member_id=mid, role=str(raw.get("role")),
                harness_role=str(raw.get("harness_role")),
                wave=str(raw.get("wave")), reason=str(raw.get("reason") or ""),
                tier=str(raw.get("tier") or ""),
                model_preference=str(raw.get("model_preference") or ""),
                fallback_preference=str(raw.get("fallback_preference") or ""),
                status=str(raw.get("status") or "pending"),
                worker_id=str(raw.get("worker_id") or ""),
                heartbeat_at=str(raw.get("heartbeat_at") or ""),
                started_at=str(raw.get("started_at") or ""),
                finished_at=str(raw.get("finished_at") or ""),
                attempt=int(raw.get("attempt") or 0),
                result=dict(raw.get("result") or {}),
            )
            engine.members[mid] = member
        return engine

    # -- composition --------------------------------------------------------

    def plan(self, *, bug_classes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Compose the roster and lay it out into waves (idempotent)."""
        if self.members:
            return self.status()
        # Persist the recomposition preference so --resume honors it
        # (the flag is engine state, not a per-run decision).
        self.state["recompose"] = self._recompose
        domains = list(self.mission.domains or [])
        team = self.registry.compose_team(
            domains=domains, bug_classes=bug_classes or [],
            max_agents=self.max_agents)
        # Canonical checklist slice: the operator-approved test catalog this
        # mission must close (or explain) per endpoint — corpus v3 contract.
        try:
            from tools.core import checklists as _cl
            self.state["checklist_slice"] = _cl.slice_for_bug_classes(
                list(bug_classes or []))
            self.state["checklist_attest"] = _cl.attest_ids(
                self.state["checklist_slice"])
        except Exception:  # noqa: BLE001 - checklists never gate composition
            pass
        # Workflow agents anchor their home lanes; entry agents slot into
        # the hunt wave (with recon/verify agents into their own lanes).
        lane_buckets: Dict[str, List[TeamMember]] = {w: [] for w in WAVE_ORDER}
        seq = 0
        for spec_dict in team["agents"]:
            role = spec_dict["role"]
            spec = self.registry.get(role)
            home = next((w for w in WAVE_ORDER if w in spec.lanes), "hunt")
            seq += 1
            routing = self._route_member(spec)
            member = TeamMember(
                member_id=f"tm-{seq:03d}",
                role=spec.role,
                harness_role=spec.harness_role,
                wave=home,
                reason=team["reasons"].get(role, ""),
                tier=routing["tier"],
                model_preference=routing["model_preference"],
                fallback_preference=routing["fallback_preference"],
            )
            lane_buckets[home].append(member)
            self.members[member.member_id] = member
        if not self.state.get("team_id"):
            digest = hashlib.sha256(json.dumps(
                sorted(m.role for m in self.members.values()),
                sort_keys=True).encode()).hexdigest()[:16]
            self.state["team_id"] = f"team-{digest}"
        self.state["status"] = "stopped"
        self.checkpoint()
        _publish(self.mission.target, "MISSION_CREATED",
                 {"team_id": self.state["team_id"],
                  "roster": [m.role for m in self.members.values()]})
        return self.status()

    def _route_member(self, spec: Any) -> Dict[str, Any]:
        """Per-member tier routing (affinity floor aware, never gates)."""
        try:
            from tools.core.model_router import route_agent_dispatch
            return route_agent_dispatch(
                bug_class=(spec.bug_classes[0] if spec.bug_classes else ""),
                domain=(spec.domains[0] if spec.domains else ""),
                affinity=spec.tier_affinity)
        except Exception:  # noqa: BLE001 - degrade to affinity
            return {"tier": spec.tier_affinity,
                    "model_preference": "",
                    "fallback_preference": ""}

    # -- finding-driven recomposition -----------------------------------------

    def _add_specialist(self, bug_class: str, reason: str = "",
                        first_seen: bool = True) -> Optional[TeamMember]:
        """Add one specialist for ``bug_class`` to the roster (budget-capped).

        Selection is the registry's deterministic bug-class resolution, so a
        recommended class staffs the same specialist a planned mission
        would have.  Workflow agents are never re-added (already shipped).
        Every decision -- added or skipped, with why -- is appended to
        ``state["recompositions"]``; refusal is recorded, never silent.
        """
        bug = str(bug_class or "").strip().lower()
        added: List[Dict[str, Any]] = []
        role = ""
        try:
            spec = self.registry.select(bug_class=bug, lane="hunt")
            role = spec.role
        except AgentRegistryError:
            spec = None
        if not bug:
            added.append({"bug_class": bug, "reason": reason[:300],
                          "outcome": "skipped",
                          "detail": "empty bug class"})
        elif not spec:
            added.append({"bug_class": bug, "reason": reason[:300],
                          "outcome": "skipped",
                          "detail": "no agent owns this bug class"})
        elif spec.entry == "workflow":
            # Only reachable via select()'s workflow fallback (workflow
            # agents own no bug classes) -- i.e. nobody owns this class.
            added.append({"bug_class": bug, "role": role,
                          "reason": reason[:300], "outcome": "skipped",
                          "detail": "no specialist owns this bug class "
                                    "(workflow fallback)"})
        elif role in {m.role for m in self.members.values()}:
            added.append({"bug_class": bug, "role": role,
                          "reason": reason[:300], "outcome": "skipped",
                          "detail": "already staffed"})
        elif len(self.members) >= self.max_agents:
            added.append({"bug_class": bug, "role": role,
                          "reason": reason[:300], "outcome": "skipped",
                          "detail": f"max_agents={self.max_agents} reached"})
        else:
            routing = self._route_member(spec)
            seq = 0
            for m in self.members.values():
                try:
                    seq = max(seq, int(m.member_id.split("-")[1]))
                except (IndexError, ValueError):
                    continue
            member = TeamMember(
                member_id=f"tm-{seq + 1:03d}",
                role=spec.role,
                harness_role=spec.harness_role,
                wave="hunt",
                reason=reason[:300],
                tier=routing["tier"],
                model_preference=routing["model_preference"],
                fallback_preference=routing["fallback_preference"],
            )
            self.members[member.member_id] = member
            self._append_run(member, "recomposed")
            added.append({"bug_class": bug, "role": role,
                          "member_id": member.member_id,
                          "reason": reason[:300], "outcome": "added"})
            _publish(self.mission.target, "TEAM_RECOMPOSED",
                     {"team_id": self.state.get("team_id", ""),
                      "bug_class": bug, "role": role,
                      "member_id": member.member_id})
        if first_seen or (added and added[-1].get("outcome") == "added"):
            # Record each bug class's decision exactly once: repeats
            # (hunt re-entry rounds, resume re-runs) re-evaluate but
            # never re-append.  A repeat that actually adds (budget
            # changed under it) is still recorded -- observable.
            self.state.setdefault("recompositions", []).extend(added)
        self.checkpoint()
        if added and added[-1].get("outcome") == "added":
            return self.members.get(str(added[-1].get("member_id")))
        return None

    @classmethod
    def _recommendations_from_results(
            cls, results: List[Any]) -> List[Dict[str, Any]]:
        """Extract finding-backed (bug_class, reason) pairs from results.

        Recognized shapes (agent-facing contract, documented in
        commands/bugwolf-team.md):

          * ``result["recommended_bug_classes"]`` -- list of bug-class
            strings or ``{"bug_class": ..., "reason": ...}`` dicts
          * messages with ``kind: "agent_recommendation"`` and body
            ``{"bug_class": ..., "reason": ...}``

        Unrecognized shapes are ignored; extraction never raises.
        """
        recs: List[Dict[str, Any]] = []
        for result in results or []:
            if not isinstance(result, dict):
                continue
            raw = result.get("recommended_bug_classes") or []
            if isinstance(raw, (str, dict)):
                raw = [raw]
            for item in raw:
                if isinstance(item, str) and item.strip():
                    recs.append({"bug_class": item,
                                 "reason": "member result recommendation"})
                elif isinstance(item, dict) and str(
                        item.get("bug_class") or "").strip():
                    recs.append({"bug_class": item["bug_class"],
                                 "reason": str(item.get("reason") or "")})
            for msg in result.get("messages") or []:
                if not isinstance(msg, dict):
                    continue
                if str(msg.get("kind") or "") not in _RECOMMEND_KINDS:
                    continue
                body = msg.get("body") or {}
                if isinstance(body, dict) and str(
                        body.get("bug_class") or "").strip():
                    recs.append({"bug_class": body["bug_class"],
                                 "reason": str(body.get("reason") or "")})
        return recs

    def _apply_recommendations(
            self, recs: List[Dict[str, Any]]) -> List[TeamMember]:
        """Staff specialists for recommendation dicts (single apply path).

        Every decision (added or skipped) lands in
        ``state["recompositions"]`` -- recomposition is observable, never
        silent.  A bug class already decided on in an earlier round is
        re-evaluated WITHOUT re-appending its record, so the ledger is
        idempotent across hunt re-entry rounds and resume.
        """
        before = set(self.members)
        for rec in recs or []:
            bug = str(rec.get("bug_class") or "").strip().lower()
            if bug in self._recomposed_seen:
                self._add_specialist(first_seen=False, **rec)
            else:
                self._recomposed_seen.add(bug)
                self._add_specialist(**rec)
        return [m for mid, m in self.members.items() if mid not in before]

    def _maybe_recompose(self, results: List[Any]) -> List[TeamMember]:
        """Grow the roster from this wave's recommendations; return adds."""
        return self._apply_recommendations(
            self._recommendations_from_results(results))

    def _recompose_hook(self, wave: str, rounds: int = 0) -> bool:
        """Run the finding-driven recomposition hook after ``wave``.

        Returns True when the roster grew and another hunt round is
        warranted; False when disabled, the wave is not a recommendation
        source (``recompose_waves``, default recon+hunt), no growth
        occurred, or the re-entry cap (``max_recompose_rounds``) is hit
        (recorded as ``state["recompose_capped"]``).
        """
        if not self._recompose or wave not in self.recompose_waves:
            return False
        if rounds >= self.max_recompose_rounds:
            self.state["recompose_capped"] = True
            return False
        recs = self._recommendations_from_results(
            [m.result for m in self.members.values() if m.wave == wave])
        # Evidence cross-reference: recorded recon depth-census evidence
        # (bucket hostnames, WAF signatures, secrets in bundles, mobile
        # endpoints) staffs specialists automatically -- same dedupe,
        # budget cap, and idempotent ledger as member recommendations.
        try:
            from tools.recon.depth_ladder import ReconDepthLedger
            led = ReconDepthLedger(
                self.mission.mission_id,
                project_root=self.project_root).load()
            recs = recs + led.recommendations()
        except Exception:  # noqa: BLE001 - evidence pass never gates
            pass
        return bool(self._apply_recommendations(recs))

    # -- worker health ------------------------------------------------------

    def _is_stale(self, member: TeamMember) -> bool:
        if member.status != "running" or not member.heartbeat_at:
            return False
        try:
            then = datetime.strptime(
                member.heartbeat_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
        except ValueError:
            return True  # unparseable heartbeat: fail closed
        age = (datetime.now(timezone.utc) - then).total_seconds()
        return age > self.stale_seconds

    def _recover_stale(self) -> List[str]:
        recovered: List[str] = []
        for member in self.members.values():
            if self._is_stale(member):
                member.status = "pending"
                member.attempt += 1
                member.worker_id = ""
                member.heartbeat_at = ""
                self._append_run(member, "recovered")
                recovered.append(member.member_id)
        if recovered:
            self.checkpoint()
        return recovered

    # -- execution ----------------------------------------------------------

    def _drive_waves(self, context: Dict[str, Any]) -> None:
        """Single wave driver shared by run() and resume().

        Executes each wave in canonical order (skipping waves with no
        runnable members), runs the recomposition hook after source
        waves, and re-enters hunt when the roster grew -- bounded by
        ``max_recompose_rounds`` (dedupe + budget also bound growth).
        Verify and report always run after every hunt re-entry round;
        terminal members are never re-run; every transition checkpoints.
        """
        wave = "recon"
        rounds = 0
        while wave:
            members = [m for m in self.members.values()
                       if m.wave == wave and m.status not in MEMBER_TERMINAL]
            if members:
                self.state["wave"] = wave
                self.checkpoint()
                self._run_wave(wave, members, context)
            if self._recompose_hook(wave, rounds):
                rounds += 1
                continue          # re-enter hunt with the grown roster
            wave = _NEXT_WAVE.get(wave)
        # Operational visibility: how many re-entry rounds actually ran
        # (bounded by max_recompose_rounds; surfaced in status/preflight).
        self.state["recompose_rounds"] = rounds

    def _complete(self) -> Dict[str, Any]:
        """Close the mission: mark complete, compute the coverage gate,
        checkpoint, and report status."""
        self.state["status"] = "complete"
        self.state["coverage_gate"] = self._coverage_gate()
        self.state["wave"] = ""
        self.checkpoint()
        return self.status()

    def run(self, *, bug_classes: Optional[List[str]] = None,
            context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Plan (if needed) then drive every wave to completion.

        Finding-backed recommendations from recon and hunt members may
        grow the roster mid-mission; a grown roster re-enters the hunt
        wave before verify (dedupe + budget + ``max_recompose_rounds``
        bound the loop).  Disable with ``--no-recompose``.
        """
        if not self.members:
            self.plan(bug_classes=bug_classes)
        self.state["status"] = "running"
        self.checkpoint()
        self._drive_waves(context or {})
        return self._complete()

    def resume(self, *, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Recover stale claims then continue from the first pending wave.

        Recomposition is honored on resume exactly as in ``run()`` (the
        ``recompose`` preference and the decision ledger persist via
        ``state.json``).  Only recovery differs from run(); the wave
        driver is shared.
        """
        self._recover_stale()
        if self.state.get("status") == "complete":
            return self.status()
        self.state["status"] = "running"
        self.checkpoint()
        self._drive_waves(context or {})
        return self._complete()

    def _coverage_gate(self) -> Dict[str, Any]:
        """Honest corpus-v3 gate: which closeable checklist IDs remain open.

        Reads the mission coverage ledger if one exists; a mission that
        never wrote coverage reports the checklist slice with untested
        counts — visible, never silently dropped.
        """
        slice_ids = list(self.state.get("checklist_slice") or [])
        if not slice_ids:
            return {"applicable": False, "slice": [], "open": []}
        gate: Dict[str, Any] = {"applicable": True, "slice": slice_ids,
                                "open": [], "ledger": False}
        try:
            from tools.core.coverage_ledger import CoverageLedger
            root = (Path(self.project_root) if self.project_root
                    else Path(workspace_root()))
            led = CoverageLedger(
                root / "state" / "orchestrator" / self.mission.mission_id)
            keys = list(led._data["entries"].keys())
            if keys:
                gate["ledger"] = True
                open_ids: List[str] = []
                for key in keys:
                    ep, method, auth = key.split("::", 2)
                    open_ids.extend(
                        led.holes(slice_ids, ep, method, auth))
                gate["open"] = sorted(set(open_ids))
            else:
                gate["open"] = slice_ids  # nothing closed anywhere yet
        except Exception:  # noqa: BLE001 - gate never crashes the run
            gate["open"] = slice_ids
        return gate

    def _run_wave(self, wave: str, members: List[TeamMember],
                  context: Dict[str, Any]) -> None:
        workers = min(self.max_parallel, max(1, len(members)))
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix=f"bugwolf-{wave}") as pool:
            futures = {pool.submit(self._run_member, m, context): m
                       for m in members}
            for future in as_completed(futures):
                member = futures[future]
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001 - a member failing
                    member.status = MEMBER_FAILED           # never sinks
                    member.finished_at = _utc_now()         # the wave
                    member.result = {"error": str(exc)[:300]}
                    self._append_run(member, "failed")
        self.checkpoint()

    def _run_member(self, member: TeamMember,
                    context: Dict[str, Any]) -> None:
        member.status = "running"
        member.attempt += 1
        member.worker_id = self.worker_id
        member.started_at = _utc_now()
        member.heartbeat_at = member.started_at
        self._append_run(member, "started")
        spec = self._spec_for(member.role)
        payload = {
            "member_id": member.member_id,
            "role": member.role,
            "harness_role": member.harness_role,
            "wave": member.wave,
            "tier": member.tier,
            "model_preference": member.model_preference,
            "fallback_preference": member.fallback_preference,
            "attempt": member.attempt,
            "prompt": self.registry.load_prompt(member.role),
            "prompt_digest": self.registry.prompt_digest(member.role),
            "scope_required": getattr(spec, "scope_required", True),
            "sandbox_required": getattr(spec, "sandbox_required", True),
            "mission": {
                "mission_id": self.mission.mission_id,
                "target": self.mission.target,
                "objective": self.mission.objective,
                "domains": list(self.mission.domains or []),
            },
            "context": context,
            "messages": [m.to_dict() for m in self.messages
                         if m.to_role in ("", member.role)],
        }
        try:
            result = dict(self._invoke_worker(member, payload) or {})
        except Exception as exc:  # noqa: BLE001
            member.status = MEMBER_FAILED
            member.finished_at = _utc_now()
            member.result = {"error": str(exc)[:300]}
            self._append_run(member, "failed")
            return
        member.result = result
        member.status = self._terminal_status(result)
        member.finished_at = _utc_now()
        self._append_run(member, "finished")
        for msg in self._drain_messages(result, member):
            self.messages.append(msg)
            self._append_message(msg)
        _publish(self.mission.target, "TASK_COMPLETED",
                 {"team_id": self.state["team_id"],
                  "member_id": member.member_id,
                  "role": member.role, "status": member.status})

    def _build_research_context(self, member_role: str,
                                member_bug_classes: tuple) -> Dict[str, Any]:
        """Compile the intel slice for one member (never raises).

        Carries the research pack (CVE/PoC/community digest) and ONLY the
        ledger techniques an operator has approved for this member's bug
        classes — quarantine entries never ride a dispatch payload.
        """
        intel: Dict[str, Any] = {"research_pack": None,
                                 "approved_techniques": []}
        try:
            from tools.intel.research_engine import ResearchEngine
            pack = self._research_pack
            if pack is None:
                pack = ResearchEngine().build_pack(
                    tech_stack=list(getattr(self.mission, "tech_stack", [])
                                    or []),
                    bug_classes=list(member_bug_classes))
                self._research_pack = pack
            intel["research_pack"] = pack.to_dict()
        except Exception:  # noqa: BLE001 - intel is never a gate
            pass
        try:
            from tools.intel.technique_ledger import TechniqueLedger
            ledger = TechniqueLedger(project_root=self.project_root)
            for cls in member_bug_classes:
                for tech in ledger.active(vuln_class=cls):
                    entry = tech.to_dict()
                    if entry["technique_id"] not in [
                            t["technique_id"]
                            for t in intel["approved_techniques"]]:
                        intel["approved_techniques"].append(entry)
        except Exception:  # noqa: BLE001
            pass
        intel["member_role"] = member_role
        # Checklist slice: canonical IDs this member owns (from its bug
        # classes) plus the mission-level slice and attest-gated pending
        # set. Coverage ledger lives at the mission dir; agents write
        # verdicts through it, the report wave reads the gate.
        try:
            from tools.core import checklists as _cl
            member_ids = _cl.slice_for_bug_classes(
                list(member_bug_classes or []))
            intel["checklist"] = {
                "member_ids": member_ids,
                "mission_ids": list(self.state.get("checklist_slice")
                                     or []),
                "attest_pending": _cl.attest_ids(member_ids),
            }
        except Exception:  # noqa: BLE001 - checklists never gate dispatch
            pass
        # Recon depth contract: recon-lane members receive the D0-D3
        # technique slice plus live ledger coverage, so depth is a
        # dispatched obligation (anti-satisficing), never improvisation.
        try:
            spec = self._spec_for(member_role)
            if "recon" in (getattr(spec, "lanes", ()) or ()):
                from tools.recon.depth_ladder import (
                    ReconDepthLedger, DEPTHS)
                led = ReconDepthLedger(
                    self.mission.mission_id,
                    project_root=self.project_root).load()
                intel["recon_depth"] = {
                    "slice": list(DEPTHS),
                    "coverage": led.coverage(list(DEPTHS)),
                    "close_blockers": led.close_blockers(list(DEPTHS)),
                }
        except Exception:  # noqa: BLE001 - depth intel never gates dispatch
            pass
        return intel

    def _invoke_worker(self, member: TeamMember,
                       payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.worker is None:
            # No harness bound: explicit degraded outcome, never a fake one
            # (same doctrine as browser_driver blocked-browser evidence).
            return {"status": "BLOCKED",
                    "summary": "no worker bound; dispatch payload recorded",
                    "dispatch_payload_keys": sorted(payload)}
        # File-queue workers (team_dispatch.TaskToolWorker) refresh the
        # member heartbeat from their waiting thread so a live claim is
        # never judged stale while the harness works.
        if hasattr(self.worker, "_heartbeat_cb"):
            from tools.runtime.team_dispatch import bind_heartbeat
            bind_heartbeat(self, self.worker)
        # Deep-research slice: pack + operator-approved techniques for this
        # member's bug classes (quarantine never rides along).
        spec = self._spec_for(member.role)
        payload["intel"] = self._build_research_context(
            member.role, tuple(getattr(spec, "bug_classes", ()) or ()))
        return self.worker(payload) or {}

    @staticmethod
    def _terminal_status(result: Dict[str, Any]) -> str:
        for key in ("status", "lead_status", "outcome"):
            val = str(result.get(key) or "").strip().upper()
            if val in MEMBER_TERMINAL:
                return val
        return MEMBER_DONE
    def _spec_for(self, role: str) -> Any:
        try:
            return self.registry.get(role)
        except AgentRegistryError:
            return None

    @staticmethod
    def _drain_messages(result: Dict[str, Any],
                        member: TeamMember) -> List[TeamMessage]:
        out: List[TeamMessage] = []
        for raw in result.get("messages") or []:
            if not isinstance(raw, dict):
                continue
            out.append(TeamMessage(
                message_id=f"msg-{uuid.uuid4().hex[:10]}",
                from_role=member.role,
                to_role=str(raw.get("to_role") or ""),
                kind=str(raw.get("kind") or "handoff"),
                body=dict(raw.get("body") or {})))
        return out

    # -- stop / status ------------------------------------------------------

    def stop(self) -> Dict[str, Any]:
        """Freeze at the next wave boundary (crash-safe by construction)."""
        self.state["status"] = "stopped"
        self.checkpoint()
        return self.status()

    def status(self) -> Dict[str, Any]:
        by_wave: Dict[str, List[Dict[str, Any]]] = {w: [] for w in WAVE_ORDER}
        for m in self.members.values():
            by_wave.setdefault(m.wave, []).append({
                "member_id": m.member_id, "role": m.role,
                "status": m.status, "tier": m.tier,
                "attempt": m.attempt, "model_preference": m.model_preference})
        return {
            "schema": SCHEMA,
            "team_id": self.state.get("team_id", ""),
            "mission_id": self.mission.mission_id,
            "status": self.state.get("status", ""),
            "wave": self.state.get("wave", ""),
            "worker_id": self.worker_id,
            "recompositions": list(self.state.get("recompositions") or []),
            "recompose_capped": bool(self.state.get("recompose_capped")),
            "recon_depth": self._recon_depth_report(),
            "waves": {w: by_wave[w] for w in WAVE_ORDER if by_wave.get(w)},
            "totals": self._totals(),
            "coverage_gate": self.state.get("coverage_gate"),
        }

    def _recon_depth_report(self) -> Dict[str, Any]:
        """Recon depth coverage + evidence recommendations (never raises).

        Advisory section for status()/preflight(): per-depth coverage
        counts, honest close blockers, and the depth ledger's
        evidence-driven recommendations annotated with staffing state
        (which recommended specialist is already on the roster).  A
        missing journal reports ``journal: false`` with zero events --
        depth intel informs operators, never gates reporting.
        """
        report: Dict[str, Any] = {"journal": False, "events": 0,
                                  "depths": {}, "close_blockers": [],
                                  "recommendations": []}
        try:
            from tools.recon.depth_ladder import ReconDepthLedger, DEPTHS
            led = ReconDepthLedger(
                self.mission.mission_id,
                project_root=self.project_root).load()
            report["journal"] = led.journal_path().is_file()
            cov = led.coverage(list(DEPTHS))
            report["events"] = cov["events"]
            if report["journal"]:
                # Close blockers are the in-flight exit exam: claimed only
                # once recon has started (a journal exists).  Before any
                # recon activity, no blockers are asserted -- depth intel
                # informs, it never pre-fails a mission that hasn't begun.
                report["close_blockers"] = list(cov["close_blockers"])
            depths: Dict[str, Any] = {}
            for depth, info in cov["depths"].items():
                depths[depth] = {
                    "covered": len(info["covered"]),
                    "total": len(info["techniques"]),
                    "untried": list(info["untried"]),
                    "waived": list(info["waived"]),
                }
            report["depths"] = depths
            recs: List[Dict[str, Any]] = []
            for rec in led.recommendations():
                entry = {"bug_class": rec["bug_class"],
                         "reason": rec["reason"], "staffed": False,
                         "role": ""}
                try:
                    spec = self.registry.select(
                        bug_class=rec["bug_class"], lane="hunt")
                    entry["role"] = spec.role
                    entry["staffed"] = any(
                        m.role == spec.role
                        for m in self.members.values())
                except Exception:  # noqa: BLE001 - unresolved class stays
                    pass             # visible with staffed=false
                recs.append(entry)
            report["recommendations"] = recs
        except Exception:  # noqa: BLE001 - depth intel never gates reporting
            pass
        return report

    def preflight(self) -> Dict[str, Any]:
        """Operational readiness report (never executes, never raises).

        Surfaces what an operator needs before --run: persisted engine
        status, recomposition policy and ledger size, worker binding,
        roster counts, the coverage gate, and recon depth coverage with
        evidence-driven recommendations.  Degraded facts are reported as
        degraded -- never fabricated as ready.
        """
        totals = self._totals()
        return {
            "schema": SCHEMA,
            "mission_id": self.mission.mission_id,
            "target": getattr(self.mission, "target", ""),
            "status": self.state.get("status", ""),
            "team_id": self.state.get("team_id", ""),
            "members": totals.get("members", 0),
            "member_status": {k: v for k, v in totals.items()
                              if k != "members"},
            "worker_binding": (
                "bound" if self.worker is not None
                else "none (members will close BLOCKED honestly)"),
            "stale_seconds": self.stale_seconds,
            "max_parallel": self.max_parallel,
            "max_agents": self.max_agents,
            "recompose": {
                "enabled": bool(self._recompose),
                "source_waves": list(self.recompose_waves),
                "max_rounds": self.max_recompose_rounds,
                "rounds_run": int(self.state.get("recompose_rounds") or 0),
                "recorded": len(self.state.get("recompositions") or []),
                "capped": bool(self.state.get("recompose_capped")),
            },
            "recon_depth": self._recon_depth_report(),
            "coverage_gate": self.state.get("coverage_gate"),
        }

    def _totals(self) -> Dict[str, int]:
        totals: Dict[str, int] = {}
        for m in self.members.values():
            totals[m.status] = totals.get(m.status, 0) + 1
        totals["members"] = len(self.members)
        return totals


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="BugWolf multi-agent team engine")
    ap.add_argument("--mission", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--objective", default="")
    ap.add_argument("--domains", default="")
    ap.add_argument("--bugs", default="")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--worker", default="", choices=("", "task-tool", "native"),
                    help="execution binding: task-tool = enqueue to the "
                         "file queue drained by the Claude Code session "
                         "(tools/runtime/team_dispatch.py); native = "
                         "in-process headless Claude Code spawns, no queue "
                         "(tools/runtime/native_dispatch.py)")
    ap.add_argument("--timeout", type=int, default=900,
                    help="per-member dispatch budget in seconds "
                         "(task-tool worker)")
    ap.add_argument("--no-recompose", action="store_true",
                    help="disable finding-driven roster recomposition "
                         "(pin the planned roster)")
    ap.add_argument("--preflight", action="store_true",
                    help="print an operational readiness report (state, "
                         "worker binding, recomposition policy, coverage "
                         "gate) without executing")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    mission = MissionSpec(
        mission_id=args.mission, target=args.target,
        objective=args.objective,
        domains=[d for d in args.domains.split(",") if d],
        budget={"max_agents": 12, "max_parallel_tasks": 4})
    if not mission.target:
        print("--target is required for --plan/--run", file=sys.stderr)
        return 2

    if args.status:
        engine = TeamEngine.load(args.mission)
        print(json.dumps(engine.status(), indent=2))
        return 0

    worker = None
    if args.worker == "task-tool":
        from tools.runtime.team_dispatch import TaskToolWorker
        worker = TaskToolWorker(mission, timeout_seconds=args.timeout)
    elif args.worker == "native":
        from tools.runtime.native_dispatch import NativeTaskWorker
        worker = NativeTaskWorker(mission, timeout_seconds=args.timeout)
    engine = TeamEngine(mission, worker=worker)
    engine._recompose = not args.no_recompose
    if args.preflight:
        try:  # report on persisted state when the mission exists
            engine = TeamEngine.load(args.mission, worker=worker)
            engine._recompose = not args.no_recompose
        except FileNotFoundError:
            pass  # fresh mission: report on the not-yet-planned team
        report = engine.preflight()
        print(json.dumps(report, indent=2) if args.json else
              f"preflight: mission={report['mission_id']} "
              f"status={report['status']} members={report['members']} "
              f"worker={report['worker_binding']} "
              f"recompose={report['recompose']['enabled']}")
        return 0
    if args.plan:
        engine.plan(bug_classes=[b for b in args.bugs.split(",") if b])
        print(json.dumps(engine.status(), indent=2) if args.json
              else f"team {engine.status()['team_id']} planned: "
                   + ", ".join(m.role for m in engine.members.values()))
        return 0
    if args.resume:
        engine = TeamEngine.load(args.mission)
        outcome = engine.resume()
        print(json.dumps(outcome, indent=2) if args.json
              else f"team {outcome['team_id']} resumed to "
                   f"{outcome['status']}: {outcome['totals']}")
        return 0
    if args.run:
        engine.run(bug_classes=[b for b in args.bugs.split(",") if b])
        outcome = engine.stop() if engine.state["status"] != "complete" \
            else engine.status()
        print(json.dumps(outcome, indent=2) if args.json
              else f"team {outcome['team_id']}: {outcome['status']} "
                   f"{outcome['totals']}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

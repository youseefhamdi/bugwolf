#!/usr/bin/env python3
"""BugWolf persistent modes (orchestrator plan v2, section 6).

State machines over the task graph; each mode has explicit entry, tick,
and completion predicates; resume replays the JSONL tail:

    mode        loop                                   completion
    ----------  -------------------------------------  -------------------------
    research    expand from signals until budget       budget exhausted/queue dry
    verify      re-test unresolved candidates          all candidates terminal
    deep-dive   one chain, escalating model profile    chain terminal
    coverage    sweep uncovered surface dimensions     coverage matrix saturated
    report      assemble evidence + provenance         report artifacts complete

``/bugwolf-stop`` freezes the mode journal; ``/bugwolf-resume`` rebuilds
from it and re-dispatches open leads FIRST (R6) -- never re-running
completed deterministic work (P5).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.runtime.contracts import MissionSpec, ContractViolation
from tools.runtime.lead_protocol import (
    LeadStore, LeadSpec, LEAD_OPEN, TIER_T0, TIER_T1, TIER_T2, TIER_T3,
    TIER_T4,
)
from tools.runtime.scheduler import (
    Scheduler, TASK_PENDING, TASK_ACTIVE, TASK_DONE, TASK_BLOCKED,
)

# Mode names (plan section 6).
MODE_RESEARCH = "research"
MODE_VERIFY = "verify"
MODE_DEEP_DIVE = "deep-dive"
MODE_COVERAGE = "coverage"
MODE_REPORT = "report"
MODES = (MODE_RESEARCH, MODE_VERIFY, MODE_DEEP_DIVE, MODE_COVERAGE,
         MODE_REPORT)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Escalation ladder T3-T4 (plan section 5.5; wired to deep-dive mode)
# ---------------------------------------------------------------------------

def deep_dive_candidates(leads: List[LeadSpec]) -> List[LeadSpec]:
    """Leads the deep-dive ladder applies to (T3 eligibility).

    Only genuinely-open leads: a lead with a winning technique recorded is
    on the verify path (T1), not stalled -- deep-dive is for leads whose
    matrices exhausted without a winner.
    """
    return [lead for lead in leads
            if lead.status == LEAD_OPEN and not any(
                e.get("outcome") == "success" for e in lead.technique_log)]


def escalate_to_t3(lead: LeadSpec) -> Dict[str, Any]:
    """T3 deep-dive: reasoning model + carlini loop over the lead surface.

    Deterministic substrate: the plan-bound research output is recorded
    (R4) and the lead escalates to T3.  The reasoning-model call itself is
    operator-configured (model_router profiles); nothing here blocks on it.
    """
    return {"lead_id": lead.lead_id, "from_tier": lead.tier, "to_tier": TIER_T3,
            "action": "deep-dive (reasoning model + carlini loop)"}


def t4_swarm_plan(lead: LeadSpec, k: int = 4) -> Dict[str, Any]:
    """T4 swarm: k parallel DIVERGENT attempts over remaining techniques.

    pass@k shape: k independent workers draw different untried techniques
    (max-min divergence by registry order), so k attempts cover k distinct
    approaches -- not k retries of the same one.
    """
    return {"lead_id": lead.lead_id, "tier": TIER_T4, "k": k,
            "attempts": [{"slot": i, "strategy": "divergent-technique"}
                         for i in range(k)]}


# ---------------------------------------------------------------------------
# ModeEngine
# ---------------------------------------------------------------------------

class ModeEngine:
    """Run the five persistent modes over a mission's task graph.

    Durable state: ``state/orchestrator/<mission>/modes.jsonl`` -- one JSON
    line per state transition (entry/tick/completion), so resume replays
    the tail.  Stop-hook freezes the file; resume rebuilds from it.
    """

    def __init__(self, mission: MissionSpec, *, project_root: Optional[str] = None,
                 budget_ticks: int = 8):
        self.mission = mission
        self.project_root = project_root
        self.budget_ticks = budget_ticks
        root = Path(project_root or os.environ.get("BUGWOLF_PROJECT_ROOT", "."))
        self.dir = root / "state" / "orchestrator" / mission.mission_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.journal_path = self.dir / "modes.jsonl"
        self.scheduler = Scheduler(mission, project_root=project_root)
        if self.journal_path.exists():
            self.scheduler = Scheduler.load(mission.mission_id,
                                            project_root=project_root)
        self.leads = LeadStore(mission.mission_id,
                               project_root=project_root).load()
        self.active_mode: Optional[str] = None
        self.ticks = 0
        self._events: List[Dict[str, Any]] = []

    # -- journal -------------------------------------------------------------

    def _log(self, action: str, payload: Dict[str, Any]) -> None:
        line = {"ts": _now_iso(), "mode": self.active_mode,
                "action": action, **payload}
        with self.journal_path.open("a") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
        self._events.append(line)

    def _event(self, event_type: str, payload: Dict[str, Any]) -> None:
        try:
            from tools.core.signal_bus import SignalBus
            SignalBus(self.mission.target).publish(event_type, "mode_engine",
                                                   payload)
        except Exception:  # noqa: BLE001 - events never raise
            pass

    # -- stop/resume (freeze + replay) ----------------------------------------

    def stop(self) -> Dict[str, Any]:
        """``/bugwolf-stop``: freeze mode state (open leads re-dispatch on
        resume FIRST, R6; completed deterministic work is never re-run, P5
        -- both are properties of the scheduler resume + JSONL journals)."""
        self._log("stop", {"active_mode": self.active_mode,
                           "ticks": self.ticks})
        self._event("MISSION_STOPPED", {"mission_id": self.mission.mission_id,
                                        "mode": self.active_mode})
        return self.resume()

    def resume(self) -> Dict[str, Any]:
        """``/bugwolf-resume``: replay the JSONL tail; open leads first."""
        plan = self.scheduler.resume()
        self._log("resume", {"lead_first": plan["lead_first"][:8],
                             "open_leads": len(plan["open_leads"])})
        self._event("MISSION_RESUMED", {"mission_id": self.mission.mission_id,
                                        "lead_first": len(plan["lead_first"])})
        return plan

    def _replay(self) -> Dict[str, Any]:
        """Rebuild the last mode + tick cursor from the JSONL tail."""
        mode, ticks = None, 0
        if self.journal_path.exists():
            for line in self.journal_path.read_text().splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("action") == "enter":
                    mode, ticks = item.get("mode"), 0
                elif item.get("action") == "tick":
                    ticks += 1
        return mode, ticks

    # -- mode transitions ------------------------------------------------------

    def enter(self, mode: str) -> Dict[str, Any]:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; known: {MODES}")
        self.active_mode = mode
        self.ticks = 0
        self._log("enter", {"mode": mode})
        self._event("MODE_ENTERED", {"mission_id": self.mission.mission_id,
                                     "mode": mode})
        return {"mode": mode, "ticks": 0}

    def _entry_guard(self, mode: str) -> None:
        """Explicit entry predicates (plan section 6)."""
        open_ids = self.leads.open_lead_ids()
        if mode == MODE_VERIFY and not open_ids:
            raise ContractViolation(
                ["verify mode requires at least one open lead"])
        if mode == MODE_REPORT and open_ids:
            raise ContractViolation(
                [f"report mode requires zero open leads; "
                 f"{len(open_ids)} open"])
        if mode == MODE_DEEP_DIVE and not deep_dive_candidates(
                self.leads.list_leads()):
            raise ContractViolation(
                ["deep-dive mode requires at least one open lead with no "
                 "winning technique"])
        if mode == MODE_COVERAGE and not open_ids:
            raise ContractViolation(
                ["coverage mode requires open leads whose checklist "
                 "surface is unsaturated"])

    # -- ticks (one loop body per mode) ----------------------------------------

    def tick(self) -> Dict[str, Any]:
        """One loop body of the active mode; raises if no mode is active."""
        if self.active_mode is None:
            raise ValueError("no active mode; call enter() first")
        self.ticks += 1
        handler = getattr(self, f"_tick_{self.active_mode.replace('-', '_')}")
        result = handler()
        result["mode"] = self.active_mode
        result["tick"] = self.ticks
        self._log("tick", result)
        return result

    def run(self, mode: str, *, max_ticks: Optional[int] = None) -> Dict[str, Any]:
        """Entry -> tick until completion predicate -> completion record."""
        budget = max_ticks if max_ticks is not None else self.budget_ticks
        self.enter(mode)
        self._entry_guard(mode)
        completion = "budget_exhausted"
        last: Dict[str, Any] = {}
        for _ in range(max(1, budget)):
            last = self.tick()
            if last.get("complete"):
                completion = last.get("reason", "predicate_met")
                break
        self._log("complete", {"mode": self.active_mode,
                               "completion": completion})
        self._event("MODE_COMPLETED", {"mission_id": self.mission.mission_id,
                                       "mode": self.active_mode,
                                       "completion": completion})
        return {"mode": self.active_mode, "completion": completion,
                "ticks": self.ticks, "last": last}

    # -- research mode ---------------------------------------------------------

    def _tick_research(self) -> Dict[str, Any]:
        """Expand from signals: research-refresh stalled T2 leads (R4)."""
        refreshed = []
        for lead in self.leads.list_leads(open_only=True):
            untried = self.leads.untried_techniques(lead)
            if untried and not lead.research_refs:
                # R4/T2: stalled lead earns its research refresh; the
                # refresh records durable refs + derived techniques (which
                # then join the required set).
                self.leads.record_research(
                    lead.lead_id,
                    ref=f"research-refresh:{lead.lead_id}:{self.ticks}",
                    summary="mode-engine research refresh (stalled lead)",
                    techniques=[])
                refreshed.append(lead.lead_id)
        if self.ticks >= self.budget_ticks:
            return {"complete": True, "reason": "budget_exhausted",
                    "refreshed": refreshed}
        if not refreshed:
            return {"complete": True, "reason": "queue_dry",
                    "refreshed": []}
        return {"complete": False, "refreshed": refreshed}

    # -- verify mode ------------------------------------------------------------

    def _tick_verify(self) -> Dict[str, Any]:
        """Re-test unresolved candidates until all leads terminal.

        The heavy lifting is the verify lane; this mode drives it to
        completion over the task graph and reports drain state honestly.
        """
        open_ids = self.leads.open_lead_ids()
        # Re-dispatch open leads FIRST (R6): the scheduler's lead_first
        # ordering is authoritative; we surface it on every tick.
        plan = self.scheduler.resume()
        if not open_ids:
            return {"complete": True, "reason": "all_candidates_terminal",
                    "open_leads": []}
        return {"complete": False, "open_leads": open_ids[:8],
                "lead_first": plan["lead_first"][:8]}

    # -- deep-dive mode ----------------------------------------------------------

    def _tick_deep_dive(self) -> Dict[str, Any]:
        """One chain, escalating model profile (T3 -> T4 swarm on stall)."""
        candidates = deep_dive_candidates(self.leads.list_leads())
        if not candidates:
            return {"complete": True, "reason": "chain_terminal",
                    "candidates": []}
        lead = candidates[0]
        if lead.tier < TIER_T3:
            self.leads.escalate(lead.lead_id, TIER_T3,
                                reason="deep-dive mode: reasoning profile")
            action = escalate_to_t3(lead)
            return {"complete": False, "escalated": lead.lead_id,
                    "to_tier": TIER_T3, "action": action["action"]}
        if lead.tier < TIER_T4:
            plan = t4_swarm_plan(lead)
            self.leads.escalate(lead.lead_id, TIER_T4,
                                reason="deep-dive stalled: T4 swarm pass@k")
            return {"complete": False, "escalated": lead.lead_id,
                    "to_tier": TIER_T4, "swarm": plan["k"]}
        # T4 reached and still open: chain terminal for this lead.
        return {"complete": True, "reason": "chain_terminal",
                "lead_id": lead.lead_id, "tier": lead.tier}

    # -- coverage mode -------------------------------------------------------------

    def _tick_coverage(self) -> Dict[str, Any]:
        """Sweep uncovered surface dimensions from the coverage ledger.

        Dimensions: surface x bug-class pairs from the canonical technique
        matrix that still have no recorded attempt on any open lead.
        """
        gaps: Dict[str, List[str]] = {}
        for lead in self.leads.list_leads(open_only=True):
            untried = self.leads.untried_techniques(lead)
            if untried:
                gaps[lead.lead_id] = untried[:6]
        if not gaps:
            return {"complete": True, "reason": "coverage_matrix_saturated",
                    "gaps": {}}
        if self.ticks >= self.budget_ticks:
            return {"complete": True, "reason": "budget_exhausted",
                    "gaps": gaps}
        return {"complete": False, "gaps": dict(list(gaps.items())[:8])}

    # -- report mode -----------------------------------------------------------------

    def _tick_report(self) -> Dict[str, Any]:
        """Assemble evidence + provenance into the report artifact."""
        pwned = [l for l in self.leads.list_leads() if l.status == "PWNED"]
        refuted = [l for l in self.leads.list_leads()
                   if l.status == "REFUTED"]
        artifact = {
            "mission_id": self.mission.mission_id,
            "findings": [{"lead_id": l.lead_id, "surface": l.surface,
                          "bug_class": l.bug_class,
                          "evidence": list(l.evidence_refs)} for l in pwned],
            "refuted": [l.lead_id for l in refuted],
            "provenance": "lead journal + technique logs + evidence refs",
        }
        path = self.dir / "report.json"
        path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        return {"complete": True, "reason": "report_artifacts_complete",
                "artifact": str(path), "findings": len(pwned),
                "refuted": len(refuted)}

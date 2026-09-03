#!/usr/bin/env python3
"""BugWolf lead protocol (orchestrator plan v2, section 5.5 - MANDATORY).

The anti-satisficing layer: LLM agents try the most plausible exploit once,
fail, and move on.  This module makes "gave up too early" structurally
impossible:

  R1  Insights cannot be "noted" -- every recognized pattern becomes a
      durable LeadSpec here (the contracts validator already rejects any
      TaskResult that mentions an insight without a lead ref).
  R2  Three terminal states only:
        PWNED              replayable evidence (F0.5 / verify_reproducibility)
        REFUTED            deterministic counter-evidence only ("feels
                           unexploitable" is not refutation)
        BUDGET-EXHAUSTED   only after the technique matrix is recorded-tried,
                           the research refresh ran (T2), and the ladder
                           reached T4
  R3  Technique matrix: every lead carries the canonical technique families
      for its bug class; each must be recorded-tried or explained before the
      lead can close.
  R4  Research refresh: T2 mandates internet research; fresh technique
      entries generated there must be tried before the lead can close.
  R5  Digest-gated: lead artifacts are append-only JSONL (lever P5), so
      stop/resume loses nothing.
  R6  Scheduler contract: open leads re-dispatch first after any restart --
      Scheduler.record() stores them in node.lead_ids and resume() surfaces
      them.

Composes tools/leads.py (the campaign Lead Ledger with OPEN/MUTATING/
FINDING/PARKED/KILLED states) rather than duplicating it: LeadSpec is the
mission-scoped protocol object; the ledger holds campaign continuity.
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import workspace_root

try:  # single source of truth for statuses
    from tools.runtime.contracts import (
        LEAD_OPEN, LEAD_PWNED, LEAD_REFUTED, LEAD_BUDGET_EXHAUSTED,
        LEAD_STATUSES,
    )
except ImportError:  # pragma: no cover - installed-skill fallback
    from contracts import (  # type: ignore
        LEAD_OPEN, LEAD_PWNED, LEAD_REFUTED, LEAD_BUDGET_EXHAUSTED,
        LEAD_STATUSES,
    )

SCHEMA = "bugwolf-lead-protocol/v1"

# Escalation ladder tiers (plan section 5.5).
TIER_T0 = 0   # first plausible technique
TIER_T1 = 1   # full technique matrix
TIER_T2 = 2   # mandatory internet research refresh
TIER_T3 = 3   # deep-dive (reasoning model + carlini loop)
TIER_T4 = 4   # swarm: k parallel divergent attempts (pass@k)

LADDER_TIERS = (TIER_T0, TIER_T1, TIER_T2, TIER_T3, TIER_T4)

# Phase 4 ships T0-T2; T3-T4 arrive with deep-dive mode (Phase 6).  A lead
# whose ladder is capped below T4 can never close as BUDGET-EXHAUSTED -- it
# stays OPEN (plan consistency fix: strengthens the mandate).
EXHAUSTION_REQUIRED_TIER = TIER_T4

# Canonical technique families per bug class (plan section 5.6 registry;
# extend as configs/checklists/*.json land -- IDs here are family labels).
TECHNIQUE_MATRIX: Dict[str, tuple] = {
    "auth_bypass": (
        "direct-access", "header-trust", "path-normalization", "verb-tampering",
        "parameter-pollution", "session-confusion", "jwt-manipulation",
    ),
    "access_control": (
        "direct-object-reference", "id-enumeration", "role-override",
        "mass-assignment", "hidden-field", "scope-confusion",
    ),
    "waf_bypass": (
        "header-original-url", "path-obfuscation", "encoding-variants",
        "parser-differential", "case-rotation", "payload-splitting",
    ),
    "injection": (
        "boolean-based", "error-based", "time-based", "union-based",
        "out-of-band", "sandbox-escape",
    ),
    # FIN matrix (plan S5) -- key-for-key with mission_runner.FIN_TECHNIQUES
    # so R2 exhaustion accounting matches the swarm exactly.
    "business_logic": (
        "quantity-mutation", "currency-arbitrage", "toctou-race", "replay",
        "negative-values", "rounding-abuse", "voucher-stacking",
        "price-trust", "test-gateway-forcing", "format-mutation-matrix",
        "signature-forgery",
    ),
    "fuzzing": (
        "boundary-length", "grammar-family", "type-confusion",
        "format-strings", "unicode-normalization",
    ),
    "recon": (),
    "generic": (
        "direct-attempt", "parameter-mutation", "context-switch",
        "encoding-variant",
    ),
    # Web3 contract lane -- key-for-key with mission_runner CONTRACT_TECHNIQUES.
    "contract_logic": (
        "argument-fuzzing", "role-override", "sequence-mutation",
        "reentrancy-probe", "impact-verb-analysis", "payable-flow",
    ),
    # Cloud/CI-CD lane -- key-for-key with mission_runner CLOUD_TECHNIQUES.
    "cloud_iam": (
        "policy-dump-analysis", "privesc-graph", "wildcard-scope",
        "action-mapping", "exposure-review",
    ),
    # LLM/agentic lane -- key-for-key with mission_runner LLM_TECHNIQUES.
    "llm_tooling": (
        "tool-inventory", "call-site-analysis", "auth-plan-diff",
        "injection-probe", "context-boundary",
    ),
}

# Signal -> ladder response: which tier a recognized signal demands.
SIGNAL_ESCALATION = {
    "waf_block": TIER_T1,        # every WAF block opens the bypass matrix
    "anomaly": TIER_T1,
    "auth_oddity": TIER_T1,
    "timing_skew": TIER_T1,
    "verbose_error": TIER_T0,
    "differential": TIER_T1,
    "gut_feeling": TIER_T2,      # even intuition earns the research refresh
}


@dataclass
class LeadSpec:
    """Mission-scoped lead object (durable, append-only journal)."""

    lead_id: str
    mission_id: str
    target: str
    title: str
    bug_class: str = "generic"
    surface: str = ""                    # endpoint / component under test
    status: str = LEAD_OPEN              # LEAD_* statuses only
    tier: int = TIER_T0                  # current ladder tier
    evidence_refs: List[str] = field(default_factory=list)
    technique_log: List[Dict[str, Any]] = field(default_factory=list)
    research_refs: List[str] = field(default_factory=list)   # R4 (T2) outputs
    escalation_history: List[Dict[str, Any]] = field(default_factory=list)
    terminal_reason: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lead_id": self.lead_id, "mission_id": self.mission_id,
            "target": self.target, "title": self.title,
            "bug_class": self.bug_class, "surface": self.surface,
            "status": self.status, "tier": self.tier,
            "evidence_refs": list(self.evidence_refs),
            "technique_log": list(self.technique_log),
            "research_refs": list(self.research_refs),
            "escalation_history": list(self.escalation_history),
            "terminal_reason": self.terminal_reason,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LeadSpec":
        return cls(
            lead_id=str(data.get("lead_id") or ""),
            mission_id=str(data.get("mission_id") or ""),
            target=str(data.get("target") or ""),
            title=str(data.get("title") or ""),
            bug_class=str(data.get("bug_class") or "generic"),
            surface=str(data.get("surface") or ""),
            status=str(data.get("status") or LEAD_OPEN),
            tier=int(data.get("tier") or TIER_T0),
            evidence_refs=list(data.get("evidence_refs") or []),
            technique_log=list(data.get("technique_log") or []),
            research_refs=list(data.get("research_refs") or []),
            escalation_history=list(data.get("escalation_history") or []),
            terminal_reason=str(data.get("terminal_reason") or ""),
            created_at=str(data.get("created_at") or ""),
            updated_at=str(data.get("updated_at") or ""),
        )


# ---------------------------------------------------------------------------
# Store (append-only JSONL journal, lever P5)
# ---------------------------------------------------------------------------


def leads_dir(*, project_root: Optional[str] = None) -> Path:
    return workspace_root(project_root) / "state" / "orchestrator" / "leads"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class LeadStore:
    """Durable lead journal for one mission (append-only per lever P5)."""

    def __init__(self, mission_id: str, *, project_root: Optional[str] = None):
        self.mission_id = mission_id
        self._dir = leads_dir(project_root=project_root)
        self._journal = self._dir / f"{mission_id}.jsonl"
        self._leads: Dict[str, LeadSpec] = {}

    # -- persistence --------------------------------------------------------

    def journal_path(self) -> Path:
        return self._journal

    def load(self) -> "LeadStore":
        """Rebuild in-memory state from the journal (stop/resume, R5)."""
        if self._journal.is_file():
            for line in self._journal.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue  # torn tail write: skip
                lead = LeadSpec.from_dict(record)
                self._leads[lead.lead_id] = lead  # last write wins
        return self

    def get(self, lead_id: str) -> LeadSpec:
        return self._leads[lead_id]

    def list_leads(self, *, open_only: bool = False) -> List[LeadSpec]:
        leads = sorted(self._leads.values(), key=lambda l: l.lead_id)
        if open_only:
            leads = [l for l in leads if l.status == LEAD_OPEN]
        return leads

    def open_lead_ids(self) -> List[str]:
        return [l.lead_id for l in self.list_leads(open_only=True)]

    def _append(self, lead: LeadSpec) -> None:
        lead.updated_at = _now_iso()
        self._leads[lead.lead_id] = lead
        self._journal.parent.mkdir(parents=True, exist_ok=True)
        with open(self._journal, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(lead.to_dict(), sort_keys=True, default=str) + "\n")

    # -- R1: creation ---------------------------------------------------------

    def open_lead(self, *, title: str, mission_id: str, target: str,
                  bug_class: str = "generic", surface: str = "",
                  evidence_refs: Optional[List[str]] = None,
                  signal: str = "gut_feeling") -> LeadSpec:
        """R1: the only way an insight becomes durable.  Never refuses."""
        lead_id = ("LEAD-" + str(len(self._leads) + 1).zfill(4)
                   + "-" + re.sub(r"[^a-z0-9]+", "-",
                                  (title or "lead").lower())[:32])
        lead = LeadSpec(
            lead_id=lead_id, mission_id=mission_id, target=target,
            title=title, bug_class=bug_class or "generic", surface=surface,
            status=LEAD_OPEN, tier=TIER_T0,
            evidence_refs=list(evidence_refs or []),
            created_at=_now_iso(),
        )
        self._append(lead)
        _publish("LEAD_OPENED", lead, {"signal": signal})
        return lead

    # -- R3: technique matrix -------------------------------------------------

    def required_techniques(self, lead: LeadSpec) -> List[str]:
        return list(TECHNIQUE_MATRIX.get(lead.bug_class, ())
                    or TECHNIQUE_MATRIX["generic"])

    def record_technique(self, lead_id: str, technique: str, outcome: str,
                         *, evidence_ref: str = "", detail: str = "",
                         registry_ids: Optional[List[str]] = None) -> LeadSpec:
        """Record one matrix attempt (tried + result).  Returns the lead."""
        lead = self._leads[lead_id]
        entry = {
            "technique": technique, "outcome": outcome,
            "evidence_ref": evidence_ref, "detail": detail[:500],
            "ts": _now_iso(),
        }
        if registry_ids:
            # Registry linkage (e.g. FIN-PARAM-02) kept structured on the
            # attempt so reports can cite the canonical checklist entries.
            entry["registry_ids"] = [str(r) for r in registry_ids][:16]
        lead.technique_log.append(entry)
        self._append(lead)
        return lead

    def record_research(self, lead_id: str, ref: str, *, summary: str = "",
                        techniques: Optional[List[str]] = None) -> LeadSpec:
        """R4/T2: record one research-refresh output on the lead.

        ``ref`` is a durable pointer (query hash, URL, report id);
        ``techniques`` are research-derived technique names -- they join the
        required set via untried_techniques() (matrix growth from research
        is consumed before close, R2/R3).
        """
        lead = self._leads[lead_id]
        entry = {"ref": str(ref)[:300], "summary": str(summary)[:500],
                 "ts": _now_iso()}
        if techniques:
            entry["techniques"] = [str(t)[:120] for t in techniques][:16]
        if entry not in lead.research_refs:
            lead.research_refs.append(entry)
        self._append(lead)
        _publish("LEAD_RESEARCH", lead, {"ref": entry["ref"]})
        return lead

    def untried_techniques(self, lead: LeadSpec) -> List[str]:
        tried = {e["technique"] for e in lead.technique_log
                 if e.get("outcome") not in ("error",)}
        # R4: research-derived techniques join the required set (they are
        # NOT tried just because research surfaced them).
        research_names = [
            t for entry in (lead.research_refs or []) if isinstance(entry, dict)
            for t in (entry.get("techniques") or []) if isinstance(t, str)]
        extra = [t for t in research_names if t and t not in tried]
        required = [t for t in self.required_techniques(lead)
                    if t not in tried]
        return required + [t for t in extra if t not in required]

    def escalate(self, lead_id: str, to_tier: int, *, reason: str = "") -> LeadSpec:
        """Move a lead up the ladder (T0->T4).  Never moves down."""
        lead = self._leads[lead_id]
        if to_tier > lead.tier:
            lead.escalation_history.append({
                "from_tier": lead.tier, "to_tier": to_tier,
                "reason": reason[:300], "ts": _now_iso()})
            lead.tier = to_tier
            self._append(lead)
            _publish("LEAD_ESCALATED", lead,
                     {"to_tier": to_tier, "reason": reason})
        return lead

    # -- R2: terminal states ---------------------------------------------------

    def close_pwned(self, lead_id: str, *, evidence_ref: str) -> LeadSpec:
        lead = self._leads[lead_id]
        lead.status = LEAD_PWNED
        if evidence_ref and evidence_ref not in lead.evidence_refs:
            lead.evidence_refs.append(evidence_ref)
        lead.terminal_reason = "replayable evidence recorded"
        self._append(lead)
        _publish("LEAD_TERMINAL", lead, {"terminal": "PWNED"})
        return lead

    def close_refuted(self, lead_id: str, *, counter_evidence: str) -> LeadSpec:
        lead = self._leads[lead_id]
        if lead.status not in (LEAD_OPEN, LEAD_REFUTED):
            # Terminal states are FINAL: BUDGET-EXHAUSTED and PWNED carry
            # recorded operator-visible history that a later replay must
            # never overwrite with REFUTED.
            return lead
        lead.status = LEAD_REFUTED
        lead.terminal_reason = counter_evidence[:500]
        self._append(lead)
        _publish("LEAD_TERMINAL", lead, {"terminal": "REFUTED"})
        return lead

    def close_exhausted(self, lead_id: str, *, operator_note: str = "") -> LeadSpec:
        """R2: only after matrix done + research refreshed + ladder at T4."""
        lead = self._leads[lead_id]
        issues = self.exhaustion_blockers(lead)
        if issues:
            raise ValueError(
                "cannot close BUDGET-EXHAUSTED: " + "; ".join(issues))
        lead.status = LEAD_BUDGET_EXHAUSTED
        lead.terminal_reason = (operator_note or "matrix + research + ladder "
                                "complete")[:500]
        self._append(lead)
        _publish("LEAD_TERMINAL", lead, {"terminal": "BUDGET-EXHAUSTED"})
        return lead

    # -- R2/R3/R4: closure guards ----------------------------------------------

    def exhaustion_blockers(self, lead: LeadSpec) -> List[str]:
        """Why this lead cannot close as BUDGET-EXHAUSTED yet (may be empty)."""
        blockers: List[str] = []
        untried = self.untried_techniques(lead)
        if untried:
            blockers.append(f"untried techniques remain: {untried[:5]}")
        if not lead.research_refs:
            blockers.append("no research refresh recorded (R4/T2)")
        if lead.tier < EXHAUSTION_REQUIRED_TIER:
            blockers.append(
                f"ladder at T{lead.tier}, exhaustion requires "
                f"T{EXHAUSTION_REQUIRED_TIER}")
        return blockers

    def closeability(self, lead: LeadSpec) -> Dict[str, Any]:
        """Operator-visible summary of what stands between the lead and each terminal state."""
        return {
            "lead_id": lead.lead_id,
            "status": lead.status,
            "tier": lead.tier,
            "can_close_pwned": bool(lead.evidence_refs),
            "can_close_refuted": True,
            "exhaustion_blockers": self.exhaustion_blockers(lead),
        }


# ---------------------------------------------------------------------------
# Events (advisory, never raise)
# ---------------------------------------------------------------------------


def _publish(event_type: str, lead: LeadSpec, payload: Dict[str, Any]) -> None:
    try:
        from tools.core.signal_bus import SignalBus
        SignalBus(lead.target).publish(event_type, "lead_protocol",
                                       {"lead_id": lead.lead_id,
                                        "mission_id": lead.mission_id,
                                        **payload})
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf lead protocol (R2 terminal states + T0-T4 ladder)")
    parser.add_argument("--mission-id", required=True)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    store = LeadStore(args.mission_id).load()
    leads = store.list_leads()
    if args.json:
        print(json.dumps([l.to_dict() for l in leads], indent=2, default=str))
    else:
        for lead in leads:
            print(f"[{lead.status:17s}] T{lead.tier} {lead.lead_id} {lead.title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

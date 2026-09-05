#!/usr/bin/env python3
"""
F0.5 precision-first refutation engine — confidence-gated by default.

Strict mode (default, ``--strict``): every finding is scored deterministically
from its evidence (reproducible trigger trace, impact trace, evidence refs,
endpoint, confirmed behavior).  Findings at or above
``STRICT_CONFIDENCE_THRESHOLD`` are CONFIRMED and eligible for the final
report; findings below it are DEMOTED, marked not report-eligible, and
quarantined as candidate records under ``state/learning/<target>.jsonl`` for
operator review.

Strict mode is the only mode. There is no auto-confirm shortcut; findings
below threshold are quarantined.

The gate is a *reporting* gate only: "uncensored execution" is untouched
(no scope/network/execution gates exist here), while precision over recall
(F0.5) governs what may reach the final report.

Usage:
  python3 tools/refutation.py --target T --finding-file F --json
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:
    from runtime_paths import CODE_ROOT, workspace_root

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

REFUTATION_DIR = ROOT / "state" / "refutations"

# F0.5 precision-first gate: findings scoring below this are quarantined
# rather than allowed into the final report.
STRICT_CONFIDENCE_THRESHOLD = 0.6

# Confidence is a reporting decision, never an execution gate.  The store is
# the same quarantined adaptive-learning store the rest of the platform uses.
LEARNING_STORE = "state/learning"


class GateResult(str, Enum):
    CLEARED = "cleared"
    REJECTED = "rejected"
    DEMOTED = "demoted"
    UNCERTAIN = "uncertain"


class FindingVerdict(str, Enum):
    CONFIRMED = "confirmed"
    DEMOTED = "demoted"
    UNCERTAIN = "uncertain"


@dataclass
class GateEvaluation:
    gate: str
    result: GateResult = GateResult.CLEARED
    reasoning: str = ""
    guard_trace: str = ""
    is_speculative: bool = False
    confidence: float = 1.0


@dataclass
class RefutationPass:
    pass_number: int = 0
    model: str = "uncensored"
    started_at: str = ""
    completed_at: str = ""
    verdict: FindingVerdict = FindingVerdict.CONFIRMED
    gate_results: List[GateEvaluation] = field(default_factory=list)
    kill_argument: str = ""
    survival_argument: str = ""
    affected_code: List[str] = field(default_factory=list)
    chain_parent: Optional[str] = None
    pass_hash: str = ""

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()
        if not self.completed_at:
            self.completed_at = datetime.now(timezone.utc).isoformat()
        if not self.pass_hash:
            raw = f"{self.pass_number}:{self.model}:{self.started_at}"
            self.pass_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class RefutationRecord:
    finding_id: str
    target: str
    title: str = ""
    bug_class: str = ""
    severity: str = "info"
    endpoint: str = ""
    passes: List[RefutationPass] = field(default_factory=list)
    final_verdict: FindingVerdict = FindingVerdict.CONFIRMED
    total_passes: int = 0
    survived_passes: int = 0
    killed_passes: int = 0
    confidence: float = 0.0
    eligible_for_report: bool = True
    quarantined: bool = False
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


def recorded_evidence_block(finding: Dict) -> Optional[Dict]:
    """Return the recorded request/response evidence block, or None.

    Live execution (``tools/core/live_executor.py``) packages evidence as
    ``{"request": {...}, "response": {...}, "replay_key": "..."}`` — the
    reproducible proof that the finding is not a one-off.  Findings whose
    ``evidence`` is a list of ids (legacy evidence refs) carry no recorded
    block and are treated as unverified.
    """
    evidence = finding.get("evidence") or finding.get("probe_evidence") or {}
    if not isinstance(evidence, dict):
        return None
    if evidence.get("request") and evidence.get("response"):
        return evidence
    return None


def has_reproducible_evidence(finding: Dict) -> bool:
    """True when the finding carries a recorded request/response + replay key."""
    block = recorded_evidence_block(finding)
    return bool(block and block.get("replay_key"))


def confidence_score(finding: Dict) -> float:
    """Deterministic F0.5 confidence score for a finding dict (0.0–1.0).

    Signals, in descending weight: a recorded request/response evidence
    block (live executor — the strongest proof), reproducible evidence refs,
    a trigger trace (reproduction), an impact trace, confirmed behavior, a
    concrete endpoint, and high/critical severity.  No model call — the
    score is derived purely from what the finding actually carries.
    """
    score = 0.0
    block = recorded_evidence_block(finding)
    if block is not None:
        # Recorded HTTP request + response is the strongest reproducible
        # signal: it outranks a bare list of evidence refs.
        score += 0.40
        if block.get("replay_key"):
            score += 0.10
        response = block.get("response") or {}
        if response.get("status") in (200, 201):
            score += 0.10
    evidence = finding.get("evidence") or finding.get("evidence_ids") or []
    if isinstance(evidence, (list, tuple)) and evidence:
        score += 0.30
        if len(evidence) >= 2:
            score += 0.10
    trigger = (finding.get("trigger_trace") or finding.get("reproduction")
               or finding.get("trigger"))
    if trigger and str(trigger).strip():
        score += 0.25
    impact = finding.get("impact_trace") or finding.get("impact")
    if impact and str(impact).strip():
        score += 0.20
    confirmed = finding.get("confirmed_behavior")
    if confirmed and str(confirmed).strip():
        score += 0.10
    if finding.get("endpoint") and str(finding.get("endpoint")).strip():
        score += 0.05
    if str(finding.get("severity", "")).strip().lower() in {"high", "critical"}:
        score += 0.05
    return round(max(0.0, min(1.0, score)), 3)


def build_adversarial_prompt(finding: Dict, gate: str = "all") -> str:
    """Strict mode evaluates deterministically; prompt scaffolding is empty."""
    return ""


def build_chain_refutation_prompt(chain_findings: List[Dict]) -> str:
    return ""


class RefutationEngine:
    """F0.5 refutation engine — strict (confidence-gated) by default."""

    def __init__(self, target: str, *, strict: bool = True,
                 require_reproducible: bool = False,
                 project_root: Optional[str] = None):
        self.target = target
        self.strict = strict
        # Live-execution gate (Phase 3): when True, a finding is only
        # CONFIRMED if it carries a recorded request/response evidence block
        # (produced by tools/core/live_executor.py).  Legacy findings that
        # predate live execution still pass the confidence gate.
        self.require_reproducible = require_reproducible
        self.project_root = project_root
        # Root the refutation ledger at the same workspace as the learning
        # store so tests and installed bundles stay project-contained.
        self.refutation_dir = workspace_root(project_root) / "state" / "refutations"
        self.refutation_dir.mkdir(parents=True, exist_ok=True)

    # -- quarantine --------------------------------------------------------

    def _quarantine(self, finding: Dict, score: float,
                    reason: str) -> Dict[str, Any]:
        """Write a quarantined candidate to state/learning/<target>.jsonl.

        Reuses the platform's adaptive-learning store (append-only,
        target-isolated, redacted, candidate-by-default) so a low-confidence
        finding is preserved for operator review and never silently dropped.
        """
        try:
            from tools.adaptive_learning import AdaptiveMemory
        except ImportError:
            from adaptive_learning import AdaptiveMemory
        memory = AdaptiveMemory(self.target, root=self.project_root)
        evidence = finding.get("evidence") or finding.get("evidence_ids") or []
        if isinstance(evidence, (list, tuple)):
            evidence = [str(item) for item in evidence][:12]
        title = str(finding.get("title") or finding.get("bug_class")
                    or "unscored finding")[:120]
        return memory.ingest(
            kind="low-confidence-finding",
            title=title,
            summary=(f"F0.5 quarantined: confidence {score:.3f} below "
                     f"{STRICT_CONFIDENCE_THRESHOLD}; {reason}"),
            bug_classes=[str(finding.get("bug_class", ""))] if finding.get("bug_class") else (),
            source_refs=[],
            evidence_refs=evidence,
            journey="f0.5-quarantine",
        )

    # -- gates -------------------------------------------------------------

    def _strict_gates(self, finding: Dict, score: float) -> List[GateEvaluation]:
        """Deterministic gate evaluations from the finding's own evidence."""
        trigger = (finding.get("trigger_trace") or finding.get("reproduction")
                   or finding.get("trigger"))
        impact = finding.get("impact_trace") or finding.get("impact")
        evidence = finding.get("evidence") or finding.get("evidence_ids") or []
        has_trigger = bool(trigger and str(trigger).strip())
        has_impact = bool(impact and str(impact).strip())
        has_evidence = bool(evidence and len(evidence) > 0)
        reproducible = has_reproducible_evidence(finding)
        gates = [
            GateEvaluation(
                gate="reproducible",
                result=(GateResult.CLEARED if reproducible
                        else GateResult.UNCERTAIN),
                reasoning=("recorded request/response + replay key present "
                           "(live executor evidence)" if reproducible else
                           "no recorded request/response evidence block"),
                confidence=(score if reproducible else round(score * 0.5, 3)),
            ),
            GateEvaluation(
                gate="refutation",
                result=(GateResult.CLEARED if score >= STRICT_CONFIDENCE_THRESHOLD
                        else GateResult.DEMOTED),
                reasoning=(f"confidence {score:.3f} meets the F0.5 threshold "
                           if score >= STRICT_CONFIDENCE_THRESHOLD else
                           f"confidence {score:.3f} below the F0.5 threshold "
                           f"({STRICT_CONFIDENCE_THRESHOLD})"),
                confidence=score,
            ),
            GateEvaluation(
                gate="reachability",
                result=(GateResult.CLEARED if has_trigger else GateResult.UNCERTAIN),
                reasoning=("reproducible trigger trace present"
                           if has_trigger else "no trigger/reproduction trace"),
                confidence=(score if has_trigger else round(score * 0.5, 3)),
            ),
            GateEvaluation(
                gate="trigger",
                result=(GateResult.CLEARED if has_trigger else GateResult.UNCERTAIN),
                reasoning=("trigger trace recorded" if has_trigger
                           else "trigger trace missing"),
                confidence=(score if has_trigger else round(score * 0.5, 3)),
            ),
            GateEvaluation(
                gate="impact",
                result=(GateResult.CLEARED if has_impact and has_evidence
                        else GateResult.UNCERTAIN),
                reasoning=("impact trace + evidence refs present"
                           if has_impact and has_evidence else
                           "impact or evidence incomplete"),
                confidence=(score if has_impact and has_evidence
                            else round(score * 0.6, 3)),
            ),
        ]
        return gates

    # -- main entry --------------------------------------------------------

    def refute(self, finding: Dict, model: str = "uncensored",
               strict: Optional[bool] = None) -> RefutationRecord:
        """Refute one finding; strict (default) gates by confidence.

        Phase 0 C-3: ``strict=False`` is no longer accepted. The
        auto-confirm shortcut has been removed; all findings flow through
        the F0.5 gate. ``strict`` is preserved on the signature for
        backwards compatibility but is ignored if False.
        """
        if strict is False:
            strict = True  # Phase 0 C-3: --no-strict is gone; always strict.
        strict = True if strict is None else bool(strict)
        finding_id = finding.get("finding_id", hashlib.sha256(
            json.dumps(finding, sort_keys=True, default=str).encode()
        ).hexdigest()[:16])

        now = datetime.now(timezone.utc).isoformat()
        # F0.5 strict mode: score, gate, and quarantine below threshold.
        score = confidence_score(finding)
        gates = self._strict_gates(finding, score)
        # Phase 0 C-3.2: when --require-reproducible is set, a finding is
        # CONFIRMED only if it carries a recorded request/response evidence
        # block. Findings without it are DEMOTED regardless of score.
        if self.require_reproducible and not has_reproducible_evidence(finding):
            reproducible = False
        else:
            reproducible = (not self.require_reproducible
                            or has_reproducible_evidence(finding))
        eligible = score >= STRICT_CONFIDENCE_THRESHOLD and reproducible
        verdict = FindingVerdict.CONFIRMED if eligible else FindingVerdict.DEMOTED
        quarantined = False
        if not eligible:
            quarantined = True
            reason = ("evidence/trigger/impact insufficient for report "
                      "eligibility" if score < STRICT_CONFIDENCE_THRESHOLD
                      else "no recorded request/response evidence "
                           "(reproducible-evidence gate)")
            try:
                self._quarantine(finding, score, reason)
            except Exception:
                # Quarantine is advisory; the DEMOTED verdict still stands.
                quarantined = False
        passes = [
            RefutationPass(
                pass_number=1,
                model=model,
                started_at=now,
                completed_at=now,
                verdict=verdict,
                gate_results=gates,
                kill_argument=("" if eligible else
                               ("below F0.5 confidence threshold"
                                if score < STRICT_CONFIDENCE_THRESHOLD else
                                "no recorded request/response evidence")),
                survival_argument=("" if not eligible else
                                   "meets F0.5 confidence + reproducible "
                                   "evidence gates"),
            )
        ]
        return RefutationRecord(
            finding_id=finding_id,
            target=self.target,
            title=finding.get("title", ""),
            bug_class=finding.get("bug_class", ""),
            severity=finding.get("severity", "info"),
            endpoint=finding.get("endpoint", ""),
            passes=passes,
            final_verdict=verdict,
            total_passes=1,
            survived_passes=1 if eligible else 0,
            killed_passes=0 if eligible else 1,
            confidence=score,
            eligible_for_report=eligible,
            quarantined=quarantined,
        )

    def verify_reproducibility(self, finding: Dict, target: str, *,
                               transport=None) -> bool:
        """Deterministic replay check against a live target.

        Re-sends the finding's recorded request via
        ``tools/core/live_executor.verify_reproducibility`` and returns True
        when the reproduction matches the recorded response — the finding is
        deterministic, not a one-off.  Findings without a recorded evidence
        block return False (nothing to replay).  Never raises: a replay
        failure is a ``False`` verdict, advisory to the reporting gate.
        """
        try:
            from tools.core.live_executor import verify_reproducibility as _verify
        except ImportError:
            return False
        try:
            return _verify(finding, target, transport=transport)
        except Exception:
            return False

    def refute_chain(self, chain_findings: List[Dict],
                     strict: Optional[bool] = None) -> RefutationRecord:
        """Refute a chain; strict mode scores the joined finding set.

        Phase 0 C-3: ``strict=False`` is no longer accepted; the
        auto-confirm branch has been removed.
        """
        if strict is False:
            strict = True  # Phase 0 C-3: --no-strict is gone; always strict.
        strict = True if strict is None else bool(strict)
        joined: Dict[str, Any] = {}
        for item in chain_findings or []:
            if not isinstance(item, dict):
                continue
            for key in ("evidence", "evidence_ids", "trigger_trace",
                        "impact_trace", "title", "bug_class", "severity",
                        "endpoint", "confirmed_behavior", "reproduction", "impact"):
                value = item.get(key)
                if value and not joined.get(key):
                    joined[key] = value
        joined["title"] = str(joined.get("title", "chain finding"))
        return self.refute(joined, model="uncensored", strict=True)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Refutation Engine (F0.5 strict by default)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--finding-id")
    parser.add_argument("--finding-file")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--passes", type=int, default=1)
    parser.add_argument("--model", default="uncensored")
    parser.add_argument("--strict", dest="strict", action="store_true",
                        default=True,
                        help="F0.5 confidence gate (default): quarantine "
                             "low-confidence findings")
    parser.add_argument("--require-reproducible", action="store_true",
                        help="Live-execution gate: CONFIRMED requires a "
                             "recorded request/response evidence block")
    parser.add_argument("--project-root", default=None,
                        help="workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    engine = RefutationEngine(args.target, strict=args.strict,
                              require_reproducible=args.require_reproducible,
                              project_root=args.project_root)

    if args.finding_file:
        try:
            findings = [json.loads(l) for l in
                        Path(args.finding_file).read_text().splitlines()
                        if l.strip()]
        except Exception:
            print(json.dumps({"error": "invalid findings file"}))
            return 2
        results = [asdict(engine.refute(f, args.model)) for f in findings]
    else:
        finding = {"finding_id": args.finding_id or "unknown",
                   "title": "Auto-confirmed"}
        results = [asdict(engine.refute(finding, args.model))]

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        for r in results:
            if r.get("eligible_for_report"):
                print(f"[+] Confirmed: {r.get('finding_id')} — {r.get('final_verdict')}")
            else:
                print(f"[~] Quarantined: {r.get('finding_id')} — "
                      f"{r.get('final_verdict')} (confidence {r.get('confidence')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# Phase 1.4 governance shim — 7-Question Gate compatibility wrapper.
# ---------------------------------------------------------------------------

def with_question_gate(finding, *, gate=None):
    """Phase 1.4 shim — re-export the new 7-Question Gate.

    Returns a :class:`FindingVerdict` produced by
    :class:`bugwolf.governance.question_gate.QuestionGate.evaluate`.
    The gate NEVER raises; every error path yields REJECTED.
    """
    from bugwolf.governance.question_gate import QuestionGate
    g = gate or QuestionGate()
    return g.evaluate_verdict(finding or {})

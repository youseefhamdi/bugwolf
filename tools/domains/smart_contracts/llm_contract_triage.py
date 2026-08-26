#!/usr/bin/env python3
"""BugWolf LLM Contract Triage — exploitability ranking of static findings.

Turns smart-contract static candidates into ranked, adversarially-verifiable
triage verdicts (OpenAnt-style).  For each candidate + code slice:

  1. **Deterministic exploitability scoring** — weighted markers for the
     bug classes that dominate DeFi incidents (reentrancy, access control,
     unchecked arithmetic, oracle manipulation, flash-loan callbacks,
     upgradeability, input validation).
  2. **Constrained adversarial verification prompts** — a fixed set of
     questions that force a model (when invoked) to *refute or confirm* the
     candidate with a JSON verdict, never free-form prose.
  3. **Verdict merge & re-rank** — ``--verdicts file.jsonl`` blends model
     verdicts with the deterministic score (deterministic core decides order;
     the model only adjusts within a bounded band).

Offline and deterministic: no model is called by this tool.  Output lands at
``research/<target>/contracts/triage-verdicts.json`` (a ``research``
artifact).  Human review is preserved — every verdict carries
``human_review_required: true``.  Emits ``LLM_CANDIDATE`` for top-ranked
exploitable candidates.

Usage:
  python3 tools/domains/smart_contracts/llm_contract_triage.py \
      --target acme --candidates findings.json
  python3 tools/domains/smart_contracts/llm_contract_triage.py \
      --target acme --candidates findings.json --verdicts model-responses.jsonl --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current


_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn

SCHEMA = "bugwolf/llm-contract-triage/v1"

# ---------------------------------------------------------------------------
# Deterministic exploitability markers: (pattern, weight, cwe, label)
# ---------------------------------------------------------------------------

EXPLOIT_MARKERS: List[Dict[str, Any]] = [
    {"pattern": r"\.call\.value|\.call\{value|\.call\(|\.send\(",
     "weight": 4, "cwe": "CWE-667", "label": "low-level external call"},
    {"pattern": r"delegatecall", "weight": 5, "cwe": "CWE-829",
     "label": "delegatecall (storage/context confusion)"},
    {"pattern": r"tx\.origin", "weight": 5, "cwe": "CWE-477",
     "label": "tx.origin authorization"},
    {"pattern": r"block\.timestamp", "weight": 3, "cwe": "CWE-682",
     "label": "block.timestamp dependency"},
    {"pattern": r"oracle|chainlink|getPrice|spotPrice|TWAP|twap",
     "weight": 3, "cwe": "CWE-829", "label": "oracle/price dependency"},
    {"pattern": r"flashLoan|onFlashLoan|flashMint",
     "weight": 3, "cwe": "CWE-829", "label": "flash-loan callback surface"},
    {"pattern": r"transferOwnership|setOwner|upgradeTo|initialize\s*\(",
     "weight": 3, "cwe": "CWE-269", "label": "admin/upgradeable surface"},
    {"pattern": r"abi\.decode|msg\.data|array\.pop\(\)|unchecked",
     "weight": 2, "cwe": "CWE-20", "label": "input/array validation surface"},
    {"pattern": r"require\s*\([^)]*==\s*msg\.sender",
     "weight": 2, "cwe": "CWE-287", "label": "sender equality check (weak auth)"},
    {"pattern": r"balances\[[^]]+\]\s*[-+]=|-=|transfer\s*\(",
     "weight": 2, "cwe": "CWE-682", "label": "balance arithmetic"},
]

# Function names that are privileged (access-control expectations).
_PRIVILEGED_FN = re.compile(
    r"function\s+(withdraw|setOwner|transferOwnership|mint|burn|upgradeTo|"
    r"setPrice|updateOracle|pause|unpause|setFee|admin[A-Z]\w*)\s*\(",
    re.IGNORECASE)


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class VerificationPrompt:
    prompt_id: str
    candidate_id: str
    question: str
    instructions: str
    response_schema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageVerdict:
    candidate_id: str
    contract: str
    bug_class: str
    deterministic_score: float
    llm_verdict: str = ""          # "" | confirmed | refuted | inconclusive
    llm_confidence: float = 0.0
    final_score: float = 0.0
    exploitability: str = ""       # critical | high | medium | low
    markers: List[str] = field(default_factory=list)
    attack_path: str = ""
    human_review_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageReport:
    target: str
    generated_at: str
    verdicts: List[TriageVerdict] = field(default_factory=list)
    prompts: List[VerificationPrompt] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "verdict_count": len(self.verdicts),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "prompts": [p.to_dict() for p in self.prompts],
        }


def _detect_markers(code: str) -> List[str]:
    if not code:
        return []
    found: List[str] = []
    for marker in EXPLOIT_MARKERS:
        if re.search(marker["pattern"], code, re.IGNORECASE):
            found.append(marker["label"])
    return found


def _score_candidate(candidate: Dict[str, Any]) -> float:
    """Deterministic exploitability score (0-10) from markers + surface."""
    code = str(candidate.get("code_slice") or candidate.get("code") or "")
    score = 0.0
    for marker in EXPLOIT_MARKERS:
        if re.search(marker["pattern"], code, re.IGNORECASE):
            score += marker["weight"]
    if _PRIVILEGED_FN.search(code):
        score += 1
    # Caller-provided signals nudge within a bounded band.
    guess = str(candidate.get("severity_guess") or "").lower()
    if guess in ("critical", "high"):
        score += 1
    # Cap at 10.
    return min(10.0, round(score, 1))


def _exploitability_label(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _verification_prompts(candidate: Dict[str, Any]) -> List[VerificationPrompt]:
    """Constrained adversarial prompts for one candidate (deterministic)."""
    cid = str(candidate.get("candidate_id") or "unknown")
    schema = {
        "exploitable": "boolean",
        "confidence": "number 0..1",
        "attack_path": "string",
        "prerequisites": "array of strings",
        "cwe": "string",
    }
    return [
        VerificationPrompt(
            prompt_id=_id("vp", cid, "confirm"),
            candidate_id=cid,
            question=("Can an attacker exercise this candidate to cause loss "
                      "of funds, privilege escalation, or state corruption? "
                      "Construct the shortest concrete attack path or state "
                      "why it is not reachable."),
            instructions=("Answer with strict JSON matching the schema. If any "
                          "precondition is unsatisfiable in the shown code, "
                          "set exploitable=false."),
            response_schema=schema,
        ),
        VerificationPrompt(
            prompt_id=_id("vp", cid, "prereq"),
            candidate_id=cid,
            question=("What preconditions must hold (roles, token balances, "
                      "external contracts, time windows) for the attack to "
                      "succeed, and how likely are they in a typical "
                      "deployment?"),
            instructions=("Answer with strict JSON. Prerequisites that require "
                          "an admin action or an unlikely market state lower "
                          "confidence."),
            response_schema=schema,
        ),
        VerificationPrompt(
            prompt_id=_id("vp", cid, "refute"),
            candidate_id=cid,
            question=("Play devil's advocate: identify the strongest argument "
                      "that this candidate is NOT exploitable (existing "
                      "guards, arithmetic bounds, reentrancy locks, "
                      "access-control). Then decide."),
            instructions=("Answer with strict JSON. Confidence must reflect "
                          "how much the refutation depends on code not shown."),
            response_schema=schema,
        ),
    ]


def triage(target: str, candidates: List[Dict[str, Any]],
           verdicts: Optional[List[Dict[str, Any]]] = None) -> TriageReport:
    """Deterministically rank candidates; merge optional model verdicts."""
    report = TriageReport(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    verdict_map: Dict[str, Dict[str, Any]] = {}
    if verdicts:
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            cid = str(v.get("candidate_id") or v.get("id") or "")
            if cid:
                verdict_map[cid] = v

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        cid = str(candidate.get("candidate_id") or "unknown")
        code = str(candidate.get("code_slice") or candidate.get("code") or "")
        det = _score_candidate(candidate)
        markers = _detect_markers(code)
        verdict = TriageVerdict(
            candidate_id=cid,
            contract=str(candidate.get("contract") or candidate.get("name") or ""),
            bug_class=str(candidate.get("bug_class") or "unknown"),
            deterministic_score=det,
        )
        model = verdict_map.get(cid)
        if model:
            exploitable = bool(model.get("exploitable"))
            confidence = float(model.get("confidence") or 0.0)
            verdict.llm_verdict = "confirmed" if exploitable else "refuted"
            verdict.llm_confidence = confidence
            verdict.attack_path = str(model.get("attack_path") or "")
            # Blend: model can move the deterministic score within a band.
            if exploitable:
                verdict.final_score = round(min(10.0, det + 1.5 * confidence), 1)
            else:
                verdict.final_score = round(max(0.0, det - 2.0 * confidence), 1)
        else:
            verdict.final_score = det
        verdict.exploitability = _exploitability_label(verdict.final_score)
        verdict.markers = markers
        report.verdicts.append(verdict)
        report.prompts.extend(_verification_prompts(candidate))

    # Rank by final score descending; stable for determinism.
    report.verdicts.sort(key=lambda v: (-v.final_score, v.candidate_id))
    return report


def write_report(report: TriageReport, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/contracts/triage-verdicts.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(report.target)
    out_dir = root / "research" / target_dir / "contracts"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "triage-verdicts.json"
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-assisted contract triage")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--candidates", required=True,
                        help="path to candidates JSON (list or {candidates: [...]})")
    parser.add_argument("--verdicts", default=None,
                        help="path to model verdicts JSONL (candidate_id keyed)")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.candidates).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read candidates: {exc}"}))
        return 2
    candidates = raw.get("candidates") if isinstance(raw, dict) else raw
    if not isinstance(candidates, list):
        candidates = [raw]

    verdicts = None
    if args.verdicts:
        verdicts = []
        for line in Path(args.verdicts).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                verdicts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    report = triage(args.target, candidates, verdicts)
    out = write_report(report, project_root=args.project_root,
                       base_dir=args.base_dir)

    top = [v for v in report.verdicts
           if v.exploitability in ("critical", "high")]
    for v in top:
        publish_or_warn(args.target, "LLM_CANDIDATE",
                        source="llm_contract_triage",
                        payload={"candidate_id": v.candidate_id,
                                 "contract": v.contract,
                                 "score": v.final_score,
                                 "exploitability": v.exploitability},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(report.verdicts)} verdicts ranked "
              f"(top: {report.verdicts[0].candidate_id} "
              f"score={report.verdicts[0].final_score}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

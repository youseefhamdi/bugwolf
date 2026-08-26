#!/usr/bin/env python3
"""BugWolf Self-Evaluation Harness — AutoPenBench-style milestone scoring.

Scores a target's campaign against a **fixed task set** of deterministic
milestones (workflow stages complete, research checkpoints fresh, recon
artifacts present, deep-hunt evidence produced, event-driven reactions fired).
This is the "did the APT Commander actually force deep exploration" check:
the same task set runs identically on every target, so scores are comparable
across runs and campaigns.

Every task carries the three-question setting discipline from the plan:

  * **setting** — ``synthetic-lab`` (fixed fixtures, no live target) vs
    ``live-bounty`` (a real authorized target),
  * **handed_to_agent** — exactly what was given to the agent before the run
    (fixtures, endpoints, policy dumps, manifests),
  * **who_confirms** — who validates the milestone (``operator`` for anything
    touching a live target; ``deterministic`` for artifact/stage checks).

Milestones are pure artifact/state checks — no probes, no network, no model.
A milestone either holds (artifact present, stage complete, event fired) or
it does not; partial credit is never awarded.

Output lands at ``state/eval/milestones-<target>.json`` and emits
``EVAL_COMPLETE`` on the signal bus.  Uncensored: the harness scores depth and
methodology, never authorization.

Usage:
  python3 tools/validation/self_eval_harness.py --target acme
  python3 tools/validation/self_eval_harness.py --target acme --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


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
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus

SCHEMA = "bugwolf/self-eval-harness/v1"


def _nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


@dataclass
class Milestone:
    milestone_id: str
    label: str
    passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvalTask:
    task_id: str
    title: str
    setting: str            # synthetic-lab | live-bounty
    handed_to_agent: str
    who_confirms: str       # operator | deterministic
    milestones: List[Milestone] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.milestones) and all(
            m.passed for m in self.milestones)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "setting": self.setting,
            "handed_to_agent": self.handed_to_agent,
            "who_confirms": self.who_confirms,
            "milestone_count": len(self.milestones),
            "milestones_passed": sum(1 for m in self.milestones if m.passed),
            "passed": self.passed,
            "milestones": [m.to_dict() for m in self.milestones],
        }


@dataclass
class EvalReport:
    target: str
    generated_at: str
    tasks: List[EvalTask] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        passed = sum(1 for t in self.tasks if t.passed)
        total = len(self.tasks)
        milestones = [m for t in self.tasks for m in t.milestones]
        ms_passed = sum(1 for m in milestones if m.passed)
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "task_count": total,
            "tasks_passed": passed,
            "score_pct": round(100.0 * passed / total, 1) if total else 0.0,
            "milestone_pct": round(100.0 * ms_passed / len(milestones), 1)
                if milestones else 0.0,
            "tasks": [t.to_dict() for t in self.tasks],
        }


def evaluate(target: str, *, project_root: Optional[str] = None,
             base_dir: Optional[str] = None) -> EvalReport:
    """Deterministically score the fixed milestone task set for a target."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    slug = re.sub(r"[^\w.-]+", "_", target or "default") or "default"
    recon = root / "recon" / slug
    research = root / "research" / slug
    state = root / "state"
    # The stage controller persists workflows under .bugwolf/workflows/ (the
    # canonical location); state/workflows/ is the legacy location kept for
    # older workspaces. Prefer the canonical one when both exist.
    workflow = root / ".bugwolf" / "workflows" / f"{slug}.json"
    legacy_workflow = state / "workflows" / f"{slug}.json"

    def workflow_data() -> Dict[str, Any]:
        for candidate in (workflow, legacy_workflow):
            if _nonempty(candidate):
                try:
                    return json.loads(candidate.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
        return {}

    def stages_complete() -> List[str]:
        data = workflow_data()
        return [
            str(rec.get("name") or rec.get("stage"))
            for rec in data.get("stages", [])
            if rec.get("status") == "complete"
        ]

    def events() -> List[str]:
        events_file = state / "signals" / "events" / f"{slug}.jsonl"
        if not _nonempty(events_file):
            return []
        try:
            return [
                json.loads(line).get("event_type", "")
                for line in events_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (json.JSONDecodeError, OSError):
            return []

    report = EvalReport(
        target=slug,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    # ---- Task 1: strict 12-stage workflow ---------------------------------
    stages = ["setup", "environment-preflight", "authorization", "passive-recon",
              "asset-intelligence", "technology-fingerprint", "maps", "research",
              "coverage-plan", "validation", "triage", "report"]
    done = set(stages_complete())
    t1 = EvalTask(
        task_id="workflow-12-stage",
        title="Strict 12-stage workflow enforced to completion",
        setting="synthetic-lab",
        handed_to_agent="fresh workflow manifest; operator records each stage's "
                        "required artifact via --complete",
        who_confirms="deterministic",
        milestones=[
            Milestone(mid, f"stage '{mid}' complete", mid in done)
            for mid in stages
        ],
    )
    report.tasks.append(t1)

    # ---- Task 2: mandatory 7-checkpoint research --------------------------
    seq_path = research / "sequence.json"
    sequence: List[str] = []
    if _nonempty(seq_path):
        try:
            data = json.loads(seq_path.read_text(encoding="utf-8"))
            executions = data.get("executions", []) if isinstance(
                data.get("executions"), list) else []
            current = executions[-1] if executions else data
            sequence = list(current.get("sequence", []))
        except (json.JSONDecodeError, OSError):
            sequence = []
    mandatory = ["pre-hunt", "post-recon", "post-maps", "bypass",
                 "post-findings", "escalation", "pre-report"]
    it = iter(sequence)
    ordered = all(
        any(item == required for item in it) for required in mandatory)
    t2 = EvalTask(
        task_id="research-7-checkpoint",
        title="Mandatory 7-checkpoint research sequence completed in order",
        setting="synthetic-lab",
        handed_to_agent="offline research executor (bundled references, no "
                        "live search provider)",
        who_confirms="deterministic",
        milestones=[
            Milestone("seq-manifest", "research sequence.json exists",
                      _nonempty(seq_path)),
            Milestone("seq-ordered", "mandatory 7 present in order", ordered),
        ],
    )
    report.tasks.append(t2)

    # ---- Task 3: recon depth (surface + maps before threat modeling) ------
    t3 = EvalTask(
        task_id="recon-depth",
        title="Recon produced surface data and asset intelligence",
        setting="synthetic-lab",
        handed_to_agent="operator-supplied asset list + fingerprint + passive "
                        "DNS/CRT snapshots",
        who_confirms="deterministic",
        milestones=[
            Milestone("urls", "recon/<t>/urls.txt present",
                      _nonempty(recon / "urls.txt")),
            Milestone("fingerprint", "tech-fingerprint.json present",
                      _nonempty(recon / "tech-fingerprint.json")),
            Milestone("asset-delta", "asset-intel/delta.json present",
                      _nonempty(recon / "asset-intel" / "delta.json")),
        ],
    )
    report.tasks.append(t3)

    # ---- Task 4: deep-hunt evidence (the Week 1-6 suite) ------------------
    deep_evidence = [
        ("smuggling", recon / "discovery" / "smuggling-plan.jsonl"),
        ("graphql", recon / "discovery" / "graphql-plans.json"),
        ("bopla", recon / "discovery" / "bopla-matrix.json"),
        ("jwt", research / "auth" / "jwt-forgery-plans.json"),
        ("oauth", research / "auth" / "oauth-flow-plans.json"),
        ("ato", recon / "discovery" / "ato-chain-plans.json"),
        ("iam", state / "capability" / f"iam-privesc-{slug}.json"),
        ("deep-link", recon / "discovery" / "deep-link-plans.json"),
        ("mobile-policy", recon / "discovery" / "mobile-policy-check.json"),
        ("contract-triage", research / "contracts" / "triage-verdicts.json"),
        ("price-manip", research / "contracts"
                        / "price-manipulation-plans.json"),
        ("tool-auth", research / "llm" / "agentic-tool-auth-plans.json"),
        ("rag", research / "llm" / "rag-poisoning-plans.json"),
        ("seed", research / "advisor" / "seed-proposals.json"),
        ("lab", research / "verification" / "lab-plans.json"),
        ("chain-proposals", research / "chains" / "graph-ai-proposals.json"),
    ]
    present = sum(1 for _, p in deep_evidence if _nonempty(p))
    t4 = EvalTask(
        task_id="deep-hunt-evidence",
        title="Deep-hunt tool suite produced supplementary evidence",
        setting="synthetic-lab",
        handed_to_agent="policy dump, manifest/plist, OpenAPI spec, contract "
                        "source, passive-DNS snapshots, leads, failures",
        who_confirms="deterministic",
        milestones=[
            Milestone("evidence-any", "at least one deep-hunt artifact",
                      present > 0),
            Milestone("evidence-majority",
                      "at least 8 of 16 deep-hunt artifact families present",
                      present >= 8),
            Milestone("evidence-full",
                      "at least 12 of 16 deep-hunt artifact families present",
                      present >= 12),
        ],
    )
    report.tasks.append(t4)

    # ---- Task 5: event-driven reactions (the nervous system) --------------
    event_types = set(events())
    t5 = EvalTask(
        task_id="event-driven-reactions",
        title="Signal-bus events fired and were persisted",
        setting="synthetic-lab",
        handed_to_agent="campaign actions that publish events (thread "
                        "completion, WAF block, findings)",
        who_confirms="deterministic",
        milestones=[
            Milestone("bus-active", "events file exists with entries",
                      bool(event_types)),
            Milestone("finding-event", "FINDING_DISCOVERED fired",
                      "FINDING_DISCOVERED" in event_types),
            Milestone("candidate-events", "at least one *_CANDIDATE fired",
                      any(e.endswith("_CANDIDATE") for e in event_types)),
        ],
    )
    report.tasks.append(t5)

    # ---- Task 6: chain discovery (multi-hop, not surface scan) ------------
    chain = state / "chains" / slug / "orchestration.json"
    has_chain = _nonempty(chain)
    t6 = EvalTask(
        task_id="chain-discovery",
        title="Chain discovery produced a graph (no surface-scan stall)",
        setting="live-bounty",
        handed_to_agent="findings + leads from the campaign ledger",
        who_confirms="operator",
        milestones=[
            Milestone("chain-graph", "chain orchestration graph persisted",
                      has_chain),
        ],
    )
    report.tasks.append(t6)

    return report


def write_report(report: EvalReport, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to state/eval/milestones-<target>.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    out_dir = root / "state" / "eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"milestones-{report.target}.json"
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-evaluation harness")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    report = evaluate(args.target, project_root=args.project_root,
                      base_dir=args.base_dir)
    out = write_report(report, project_root=args.project_root,
                       base_dir=args.base_dir)

    try:
        bus = SignalBus(args.target,
                        project_root=args.project_root or args.base_dir)
        bus.publish("EVAL_COMPLETE", source="self_eval_harness",
                    payload={"score_pct": report.to_dict()["score_pct"],
                             "target": args.target})
    except Exception as exc:  # advisory, never a gate
        print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
              file=sys.stderr)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        d = report.to_dict()
        print(f"[+] {args.target}: {d['tasks_passed']}/{d['task_count']} "
              f"tasks ({d['score_pct']}%) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

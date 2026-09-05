#!/usr/bin/env python3
"""BugWolf Chain-Graph AI — missing-link chain proposals on the deep_chain graph.

Synthesizes multi-hop chain proposals between parked leads and findings on top
of ``tools.deep_chain``'s deterministic compatibility graph (``EDGES``).
Every proposal is a *missing link*: lead A's bug class can escalate toward
lead B's bug class (or toward an uncovered terminal class), with the
intermediate classes that are not yet present in the pool explicitly listed.

  * **Deterministic proposals** — computed from ``EDGES`` reachability (BFS):
    for every pair of pool entries, propose the chain when a directed path
    exists, and flag the classes along the path that are *missing* from the
    pool (those are the next discovery targets).
  * **LLM-merged proposals** — ``--verdicts`` JSONL may propose additional
    links ``{from_lead, to_lead, rationale}``; each is **validated through
    the deterministic edge-checker** and only accepted when a path actually
    exists in ``EDGES``.  The deterministic graph always decides.

Output lands at ``research/<target>/chains/graph-ai-proposals.json`` (a
``research`` artifact) and emits ``CHAIN_PROPOSAL`` for accepted proposals.

Offline and deterministic; uncensored; no model is called.

Usage:
  python3 tools/intelligence/chain_graph_ai.py --target acme --pool pool.json
  python3 tools/intelligence/chain_graph_ai.py --target acme --pool pool.json --verdicts model.jsonl --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
try:
    from tools.deep_chain import EDGES, TERMINAL
except ImportError:  # pragma: no cover
    from tools.deep_chain import EDGES, TERMINAL

SCHEMA = "bugwolf/chain-graph-ai/v1"
LOG = logging.getLogger(__name__)

MAX_HOPS = 4


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _shortest_path(start: str, end: str, max_hops: int = MAX_HOPS) -> List[str]:
    """BFS over EDGES; returns the class path start->...->end ([] if none)."""
    if start == end:
        return [start]
    queue: deque = deque([(start, [start])])
    seen: Set[str] = {start}
    while queue:
        node, path = queue.popleft()
        if len(path) - 1 >= max_hops:
            continue
        for nxt in EDGES.get(node, []):
            if nxt in seen:
                continue
            new_path = path + [nxt]
            if nxt == end:
                return new_path
            seen.add(nxt)
            queue.append((nxt, new_path))
    return []


def _canonical_class(value: str) -> str:
    return (value or "").strip().lower()


@dataclass
class ChainProposal:
    proposal_id: str
    from_lead: str
    to_lead: str
    from_class: str
    to_class: str
    path: List[str]
    terminal: bool
    missing_classes: List[str] = field(default_factory=list)
    rationale: str = ""
    source: str = "deterministic"   # deterministic | llm_validated

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChainProposalSet:
    target: str
    generated_at: str
    proposals: List[ChainProposal] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "proposal_count": len(self.proposals),
            "proposals": [p.to_dict() for p in self.proposals],
        }


def propose(target: str, pool: List[Dict[str, Any]],
            verdicts: Optional[List[Dict[str, Any]]] = None) -> ChainProposalSet:
    """Deterministically propose missing links; validate LLM proposals."""
    report = ChainProposalSet(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    entries: List[Dict[str, Any]] = []
    for entry in pool:
        if not isinstance(entry, dict):
            continue
        cls = _canonical_class(entry.get("bug_class") or entry.get("class"))
        lead_id = str(entry.get("lead_id") or entry.get("id")
                      or entry.get("finding_id") or "lead")
        if cls:
            entries.append({"lead_id": lead_id, "bug_class": cls,
                            "summary": str(entry.get("summary") or "")})

    classes_present: Set[str] = {e["bug_class"] for e in entries}
    seen: Set[Tuple[str, str]] = set()

    # 1. Deterministic pair proposals: a directed path exists between classes.
    for a in entries:
        for b in entries:
            if a["lead_id"] == b["lead_id"]:
                continue
            if a["bug_class"] == b["bug_class"]:
                continue
            path = _shortest_path(a["bug_class"], b["bug_class"])
            if not path:
                continue
            key = (a["lead_id"], b["lead_id"])
            if key in seen:
                continue
            seen.add(key)
            missing = [c for c in path[1:-1] if c not in classes_present]
            report.proposals.append(ChainProposal(
                proposal_id=_id("chain", a["lead_id"], b["lead_id"]),
                from_lead=a["lead_id"],
                to_lead=b["lead_id"],
                from_class=a["bug_class"],
                to_class=b["bug_class"],
                path=path,
                terminal=b["bug_class"] in TERMINAL,
                missing_classes=missing,
                rationale=(f"{a['bug_class']} can escalate to "
                           f"{b['bug_class']} via {' → '.join(path)}."
                           + (f" Intermediate class(es) not yet in the pool: "
                              f"{', '.join(missing)} — discovery targets."
                              if missing else "")),
            ))

    # 2. Terminal-gap proposals: classes in the pool that can reach a terminal
    # class not yet present.
    terminals_present = classes_present & TERMINAL
    for entry in entries:
        for terminal in sorted(TERMINAL):
            if terminal in terminals_present or terminal == entry["bug_class"]:
                continue
            path = _shortest_path(entry["bug_class"], terminal)
            if not path:
                continue
            key = (entry["lead_id"], "terminal:" + terminal)
            if key in seen:
                continue
            seen.add(key)
            missing = [c for c in path[1:] if c not in classes_present]
            report.proposals.append(ChainProposal(
                proposal_id=_id("chain", entry["lead_id"], "terminal",
                                terminal),
                from_lead=entry["lead_id"],
                to_lead="(terminal)",
                from_class=entry["bug_class"],
                to_class=terminal,
                path=path,
                terminal=True,
                missing_classes=missing,
                rationale=(f"{entry['bug_class']} can reach the terminal "
                           f"class {terminal} via {' → '.join(path)}"
                           + (f"; missing from the pool: {', '.join(missing)}"
                              if missing else "")),
            ))

    # 3. LLM-proposed links, validated through the deterministic edge-checker.
    if verdicts:
        by_lead = {e["lead_id"]: e["bug_class"] for e in entries}
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            from_lead = str(v.get("from_lead") or "")
            to_lead = str(v.get("to_lead") or "")
            from_cls = by_lead.get(from_lead)
            to_cls = by_lead.get(to_lead)
            if not from_cls or not to_cls:
                continue
            path = _shortest_path(from_cls, to_cls)
            if not path:
                continue  # rejected by the deterministic graph
            key = (from_lead, to_lead)
            rationale = str(v.get("rationale") or "LLM-proposed link, "
                            "validated against the compatibility graph.")
            # A passing LLM proposal enriches the deterministic link (or adds
            # it when the deterministic scan had not produced the pair).
            existing = next((p for p in report.proposals
                             if p.from_lead == from_lead
                             and p.to_lead == to_lead), None)
            if existing is not None:
                existing.rationale = rationale
                existing.source = "llm_validated"
                continue
            seen.add(key)
            missing = [c for c in path[1:-1] if c not in classes_present]
            report.proposals.append(ChainProposal(
                proposal_id=_id("chain-llm", from_lead, to_lead),
                from_lead=from_lead,
                to_lead=to_lead,
                from_class=from_cls,
                to_class=to_cls,
                path=path,
                terminal=to_cls in TERMINAL,
                missing_classes=missing,
                rationale=rationale,
                source="llm_validated",
            ))

    # Stable deterministic order.
    report.proposals.sort(key=lambda p: (p.from_lead, p.to_lead,
                                         p.from_class))
    return report


def write_proposal_set(report: ChainProposalSet, *,
                       project_root: Optional[str] = None,
                       base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/chains/graph-ai-proposals.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(report.target)
    out_dir = root / "research" / target_dir / "chains"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "graph-ai-proposals.json"
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Chain-graph missing-link proposals")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--pool", required=True,
                        help="path to lead/finding pool JSON (list or {pool: [...]})")
    parser.add_argument("--verdicts", default=None,
                        help="path to LLM link proposals JSONL (from_lead/to_lead/rationale)")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.pool).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read pool: {exc}"}))
        LOG.error("chain_graph_ai.read_pool_failed: %s", exc)
        return 2
    pool = raw.get("pool") if isinstance(raw, dict) else raw
    if not isinstance(pool, list):
        pool = [raw]

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

    report = propose(args.target, pool, verdicts)
    out = write_proposal_set(report, project_root=args.project_root,
                             base_dir=args.base_dir)

    for p in report.proposals[:8]:
        publish_or_warn(args.target, "CHAIN_PROPOSAL",
                        source="chain_graph_ai",
                        payload={"proposal_id": p.proposal_id,
                                 "from": p.from_lead,
                                 "to": p.to_lead,
                                 "path": p.path,
                                 "source": p.source},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        LOG.info("chain_graph_ai.report target=%s proposals=%d",
                 args.target, len(report.proposals))
    else:
        print(f"[+] {args.target}: {len(report.proposals)} chain proposals -> {out}")
        LOG.info("chain_graph_ai.summary target=%s proposals=%d out=%s",
                 args.target, len(report.proposals), out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

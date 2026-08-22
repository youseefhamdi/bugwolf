#!/usr/bin/env python3
"""BugWolf full-chain orchestrator.

The older chain helpers mostly answer "which classes can connect?" This module
answers the operational question that matters after an agent finds a link:
which steps are already evidenced, which links are missing, what is the next
highest-information validation task, and when must the chain stop for a gate?

It consumes redacted findings and open-lead snapshots, produces a bounded
chain graph, and persists a hash-linked orchestration history per target. It is
offline by default and never executes a request, creates an exploit, contacts a
third party, or treats a chain hypothesis as a confirmed finding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tools.deep_chain import EDGES, TERMINAL, SEV_RANK
    from tools.evidence import redact
    from tools.runtime_paths import workspace_root
    from tools.safety import safe_path, safe_target_name
except ImportError:  # direct script execution
    from deep_chain import EDGES, TERMINAL, SEV_RANK
    from evidence import redact
    from runtime_paths import workspace_root
    from safety import safe_path, safe_target_name


SCHEMA = "bugwolf-chain-orchestration/v1"
CHAIN_DIR_NAME = "state/chains"

# Names emitted by different agents for the same conceptual class.
CLASS_ALIASES = {
    "open_redirect": "open-redirect",
    "oauth_misconfig": "oauth-bypass",
    "information_disclosure": "info-disclosure",
    "graphql_idor": "idor",
    "privilege-escalation": "privilege-escalation-web",
    "privilege_escalation": "privilege-escalation-web",
    "account_takeover": "account-takeover",
    "mass_data_breach": "mass-data-breach",
    "funds_drain": "funds-drain",
    "command-injection": "rce",
    "remote-code-execution": "rce",
}

TERMINAL_IMPACT = {
    "rce": "remote code execution",
    "account-takeover": "account takeover / impersonation",
    "funds-drain": "funds or value drain",
    "mass-data-breach": "mass data breach",
}


@dataclass
class ChainNode:
    node_id: str
    kind: str
    bug_class: str
    title: str
    endpoint: str
    method: str
    severity: str
    evidence_state: str
    source_status: str
    map_path: str = ""


@dataclass
class ChainEdge:
    source: str
    target: str
    relation: str
    confidence: str
    evidence_needed: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_class(value: Any) -> str:
    raw = str(value or "").strip().lower().replace(" ", "-")
    return CLASS_ALIASES.get(raw, raw)


def _clean(value: Any, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _read_json_records(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            if isinstance(value.get("findings"), list):
                return [item for item in value["findings"] if isinstance(item, dict)]
            return [value]
    except json.JSONDecodeError:
        pass
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
        except json.JSONDecodeError:
            continue
    return records


def _latest_leads(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    for record in records:
        lead_id = str(record.get("lead_id", ""))
        if lead_id:
            latest[lead_id] = record
    return list(latest.values())


def _evidence_state(record: Dict[str, Any], kind: str) -> str:
    explicit = str(record.get("evidence_state", "")).lower()
    if explicit in {"fact", "observation", "hypothesis", "open_lead", "finding", "blocked", "refuted"}:
        return explicit
    if kind == "lead":
        if record.get("state") == "FINDING":
            return "finding"
        return "open_lead"
    status = str(record.get("status", "")).lower()
    observation = str(record.get("observation_state", "")).lower()
    if status in {"confirmed", "validated", "reported"} or observation == "signal":
        return "finding"
    if status in {"refuted", "killed", "resolved", "dup", "n/a"}:
        return "refuted"
    return "observation" if record.get("evidence") else "hypothesis"


def _node_from_record(record: Dict[str, Any], kind: str, index: int) -> Optional[ChainNode]:
    node_id = str(record.get("finding_id") or record.get("id") or record.get("lead_id") or f"{kind}-{index}")
    bug_class = _normalize_class(record.get("bug_class") or record.get("category") or record.get("title"))
    if not bug_class or (bug_class not in EDGES and bug_class not in TERMINAL):
        return None
    severity = str(record.get("severity", "low")).lower()
    if severity not in SEV_RANK:
        severity = "low"
    return ChainNode(
        node_id=node_id[:120],
        kind=kind,
        bug_class=bug_class,
        title=_clean(record.get("title") or record.get("name") or bug_class),
        endpoint=_clean(record.get("endpoint") or record.get("location")),
        method=_clean(record.get("method") or "GET", 30),
        severity=severity,
        evidence_state=_evidence_state(record, kind),
        source_status=_clean(record.get("status") or record.get("state") or "unreviewed", 80),
        map_path=_clean(record.get("map_path") or record.get("map") or ""),
    )


def _endpoint_root(endpoint: str) -> str:
    value = endpoint.split("?", 1)[0].rstrip("/")
    parts = value.split("/")
    while parts and (parts[-1].isdigit() or len(parts[-1]) > 24):
        parts.pop()
    return "/".join(parts)


def _build_nodes(findings: Iterable[Dict[str, Any]], leads: Iterable[Dict[str, Any]]) -> List[ChainNode]:
    nodes: List[ChainNode] = []
    seen: set[str] = set()
    for kind, records in (("finding", findings), ("lead", _latest_leads(leads))):
        for index, record in enumerate(records):
            node = _node_from_record(record, kind, index)
            if node and node.node_id not in seen and node.evidence_state != "refuted":
                seen.add(node.node_id)
                nodes.append(node)
    return nodes


def _edge_for(source: ChainNode, target: ChainNode) -> Optional[ChainEdge]:
    if target.bug_class in EDGES.get(source.bug_class, []):
        return ChainEdge(
            source.node_id, target.node_id, f"{source.bug_class} enables {target.bug_class}",
            "medium", "Verify the causal join without assuming the intermediate control is absent.",
        )
    same_root = _endpoint_root(source.endpoint) and _endpoint_root(source.endpoint) == _endpoint_root(target.endpoint)
    if same_root and source.bug_class == target.bug_class == "idor":
        return ChainEdge(
            source.node_id, target.node_id, "same object surface, different authorization action",
            "high", "Compare only owned disposable resources across two cooperating accounts.",
        )
    if same_root and source.bug_class != target.bug_class:
        return ChainEdge(
            source.node_id, target.node_id, "same surface root, cross-class composition",
            "low", "Prove the output of the first node is accepted by the second without side effects.",
        )
    return None


def _build_edges(nodes: Sequence[ChainNode]) -> List[ChainEdge]:
    edges: List[ChainEdge] = []
    for source in nodes:
        for target in nodes:
            if source.node_id == target.node_id:
                continue
            edge = _edge_for(source, target)
            if edge:
                edges.append(edge)
    return edges


def _conceptual_paths(start: str, max_hops: int) -> List[List[str]]:
    paths: List[List[str]] = []

    def walk(node: str, path: List[str]) -> None:
        if len(path) - 1 >= max_hops:
            return
        for nxt in EDGES.get(node, []):
            if nxt in path:
                continue
            candidate = path + [nxt]
            paths.append(candidate)
            walk(nxt, candidate)

    walk(start, [start])
    return paths


def _best_node(nodes: Sequence[ChainNode], bug_class: str, used: set[str]) -> Optional[ChainNode]:
    candidates = [node for node in nodes if node.bug_class == bug_class and node.node_id not in used]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (
        item.evidence_state == "finding", SEV_RANK.get(item.severity, 0), item.node_id,
    ), reverse=True)[0]


def _stage_status(node: Optional[ChainNode], bug_class: str) -> Dict[str, Any]:
    if node is None:
        return {
            "bug_class": bug_class,
            "node_id": None,
            "status": "missing_link",
            "evidence_state": "blocked",
            "next_action": f"Map and validate the {bug_class} link using an authorized, bounded baseline.",
        }
    return {
        "bug_class": bug_class,
        "node_id": node.node_id,
        "kind": node.kind,
        "title": node.title,
        "endpoint": node.endpoint,
        "method": node.method,
        "status": "evidenced" if node.evidence_state == "finding" else "needs_validation",
        "evidence_state": node.evidence_state,
        "next_action": "Reproduce the trigger and trace victim impact before using this link for escalation.",
    }


def _chain_score(stages: Sequence[Dict[str, Any]], terminal: str, source: ChainNode) -> float:
    resolved = sum(1 for stage in stages if stage["status"] != "missing_link")
    evidenced = sum(1 for stage in stages if stage.get("evidence_state") == "finding")
    missing = len(stages) - resolved
    score = float(SEV_RANK.get(source.severity, 0) * 8 + resolved * 12 + evidenced * 15 - missing * 10)
    if terminal in TERMINAL:
        score += 35
    return score


def _chain_id(stages: Sequence[Dict[str, Any]]) -> str:
    canonical = "|".join(f"{stage['bug_class']}:{stage.get('node_id') or 'missing'}" for stage in stages)
    return "chain-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _validation_queue(stages: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn adjacent chain links into ordered, non-executable work items."""
    queue: List[Dict[str, Any]] = []
    for sequence, (source, target) in enumerate(zip(stages, stages[1:]), 1):
        source_id = source.get("node_id")
        target_id = target.get("node_id")
        if source_id and target_id:
            relation = f"{source['bug_class']} enables {target['bug_class']}"
            status = "pending_gated_validation"
        else:
            relation = f"{source['bug_class']} -> {target['bug_class']}"
            status = "blocked_missing_link"
        queue.append({
            "sequence": sequence,
            "from_bug_class": source["bug_class"],
            "from_node": source_id,
            "to_bug_class": target["bug_class"],
            "to_node": target_id,
            "relation": relation,
            "status": status,
            "evidence_needed": (
                "Show the source output is accepted by the next control using an "
                "owned disposable fixture and a baseline/control comparison."
            ),
            "automatic_execution": False,
            "requires": ["explicit_scope", "active_confirmation", "human_review"],
        })
    return queue


def orchestrate(findings: Iterable[Dict[str, Any]], leads: Iterable[Dict[str, Any]], *,
                max_hops: int = 4, max_chains: int = 32) -> Dict[str, Any]:
    """Build complete bounded chain plans from current evidence and open leads."""
    nodes = _build_nodes(findings, leads)
    edges = _build_edges(nodes)
    chains: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for source in sorted(nodes, key=lambda item: (
            SEV_RANK.get(item.severity, 0), item.evidence_state == "finding", item.node_id), reverse=True):
        conceptual = _conceptual_paths(source.bug_class, max_hops)
        for path in conceptual:
            if path[-1] not in TERMINAL and len(path) < 3:
                continue
            used: set[str] = set()
            stages = []
            for bug_class in path:
                node = _best_node(nodes, bug_class, used)
                if node:
                    used.add(node.node_id)
                stages.append(_stage_status(node, bug_class))
            chain_id = _chain_id(stages)
            if chain_id in seen:
                continue
            seen.add(chain_id)
            missing = [stage["bug_class"] for stage in stages if stage["status"] == "missing_link"]
            complete = not missing
            terminal = path[-1]
            score = _chain_score(stages, terminal, source)
            validation_queue = _validation_queue(stages)
            chains.append({
                "chain_id": chain_id,
                "path": path,
                "source_node": source.node_id,
                "stages": stages,
                "terminal": terminal in TERMINAL,
                "impact": TERMINAL_IMPACT.get(terminal, ""),
                "score": score,
                "state": "ready_for_gated_validation" if complete else "blocked_missing_link",
                "missing_links": missing,
                "evidence_gaps": [stage["bug_class"] for stage in stages
                                  if stage.get("evidence_state") != "finding"],
                "validation_queue": validation_queue,
                "next_action": (
                    stages[next(index for index, item in enumerate(stages)
                                if item["status"] == "missing_link")]["next_action"]
                    if missing else
                    "Validate the chain edges in order with one bounded experiment per edge, then trace impact."
                ),
                "gates": {
                    "offline_plan": True,
                    "explicit_scope_required": True,
                    "active_confirmation_required": True,
                    "state_change_confirmation_required": True,
                    "human_review_required": True,
                    "automatic_execution": False,
                },
            })
            if len(chains) >= max_chains * 4:
                break
        if len(chains) >= max_chains * 4:
            break

    chains.sort(key=lambda item: (item["score"], item["terminal"], -len(item["missing_links"])), reverse=True)
    chains = chains[:max_chains]
    complete = sum(1 for chain in chains if chain["state"] == "ready_for_gated_validation")
    resume = None
    if chains:
        top = chains[0]
        resume = {
            "chain_id": top["chain_id"],
            "state": top["state"],
            "path": top["path"],
            "next_action": top["next_action"],
            "next_queue_item": next((item for item in top["validation_queue"]
                                      if item["status"] != "complete"), None),
        }
    return {
        "schema": SCHEMA,
        "offline": True,
        "nodes": [asdict(node) for node in nodes],
        "edges": [asdict(edge) for edge in edges],
        "chains": chains,
        "resume": resume,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "chains": len(chains),
            "complete_chains": complete,
            "blocked_chains": len(chains) - complete,
        },
        "policy": "A chain is a hypothesis until every edge has evidence; never execute automatically.",
    }


def _default_input(project: Path, target: str, filename: str) -> Path:
    safe = safe_target_name(target).replace(":", "_")
    return project / "state" / "sessions" / safe / filename


def refresh_target(project: str | Path, target: str, *,
                   max_hops: int = 4, max_chains: int = 32) -> Dict[str, Any]:
    """Refresh the target-local chain graph from the current state stores.

    This is the integration boundary used by hunt/research entry points. It
    reads only the target's own findings and lead snapshots, writes a redacted
    graph plus hash-linked history, and never executes a validation task.
    """
    if max_hops < 2 or max_hops > 8:
        raise ValueError("max_hops must be 2..8")
    if max_chains < 1 or max_chains > 256:
        raise ValueError("max_chains must be 1..256")
    root = Path(project).expanduser().resolve()
    safe_target_name(target)  # fail closed before constructing state paths
    findings_path = _default_input(root, target, "findings.jsonl")
    leads_path = _default_input(root, target, "leads.jsonl")
    result = orchestrate(
        _read_json_records(findings_path),
        _read_json_records(leads_path),
        max_hops=max_hops,
        max_chains=max_chains,
    )
    result["persistence"] = _persist(root, target, result)
    return result


def _persist(project: Path, target: str, result: Dict[str, Any]) -> Dict[str, str]:
    safe = safe_target_name(target).replace(":", "_")
    directory = project / CHAIN_DIR_NAME / safe
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / "orchestration.json"
    history = directory / "orchestration.jsonl"
    snapshot = dict(result)
    snapshot["target"] = target
    snapshot["generated_at"] = _now()
    snapshot["input_sha256"] = hashlib.sha256(
        json.dumps(result.get("nodes", []), sort_keys=True).encode("utf-8")
    ).hexdigest()
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(redact(snapshot), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    previous = ""
    if history.is_file():
        lines = [line for line in history.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                previous = json.loads(lines[-1]).get("record_hash", "")
            except json.JSONDecodeError:
                previous = ""
    record = {
        "sequence": len(history.read_text(encoding="utf-8").splitlines()) + 1 if history.exists() else 1,
        "previous_hash": previous,
        "target": target,
        "generated_at": snapshot["generated_at"],
        "input_sha256": snapshot["input_sha256"],
        "stats": snapshot["stats"],
    }
    record["record_hash"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    with history.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return {"orchestration": str(output), "history": str(history)}


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf full-chain offline orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-root", help="Project workspace (default: cwd)")
    parser.add_argument("--findings-file")
    parser.add_argument("--leads-file")
    parser.add_argument("--max-hops", type=int, default=4)
    parser.add_argument("--max-chains", type=int, default=32)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.max_hops < 2 or args.max_hops > 8 or args.max_chains < 1 or args.max_chains > 256:
        parser.error("--max-hops must be 2..8 and --max-chains must be 1..256")
    project = workspace_root(args.project_root)
    findings_path = safe_path(args.findings_file, project) if args.findings_file else _default_input(project, args.target, "findings.jsonl")
    leads_path = safe_path(args.leads_file, project) if args.leads_file else _default_input(project, args.target, "leads.jsonl")
    if not args.findings_file and not args.leads_file:
        result = refresh_target(project, args.target,
                                max_hops=args.max_hops, max_chains=args.max_chains)
        paths = result["persistence"]
    else:
        result = orchestrate(_read_json_records(findings_path), _read_json_records(leads_path),
                             max_hops=args.max_hops, max_chains=args.max_chains)
        paths = _persist(project, args.target, result)
        result["persistence"] = paths
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        stats = result["stats"]
        print(f"[*] Chain orchestration: {stats['chains']} bounded chain(s); "
              f"{stats['complete_chains']} ready for gated validation; "
              f"{stats['blocked_chains']} missing link(s)")
        print(f"[*] Saved: {paths['orchestration']}")
        for chain in result["chains"][:5]:
            print(f"  [{chain['state']}] {chain['chain_id']}: "
                  f"{' -> '.join(chain['path'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

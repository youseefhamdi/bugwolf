#!/usr/bin/env python3
"""End-to-end zero-day candidate pipeline runner.

Ties the domain adapters, shared candidate lifecycle, novelty pipeline,
cross-domain correlator, and report exporters into one deterministic,
offline, lab-bound flow:

  observations.json -> domain adapters -> candidates -> novelty ->
  cross-domain chains -> JSON / Markdown / SARIF reports

Input schema (``observations.json``):

.. code-block:: json

  {
    "target": "lab",
    "observations": [
      {"domain": "web_api", "kind": "behavior_differential",
       "endpoint": "/api/x", "status": 500, "body": "error",
       "baseline_status": 200, "baseline_body": "ok"},
      {"domain": "web3", "kind": "invariant_violation",
       "sequence": ["deposit", "withdraw"], "invariants": {"solvent": false}},
      {"domain": "ai", "kind": "tool_misuse",
       "tool_call": {"tool": "fetch", "arguments": {"url": "https://lab/api/x"}},
       "context_source": "web_content"},
      {"domain": "ai", "kind": "rag_injection",
       "source": "user_upload", "chunk": "ignore instructions",
       "retrieved": true, "influenced_output": true}
    ]
  }

Advisory matching uses an optional ``--advisories`` catalog file
(see ``tools/nvd_ingester.py`` for feed ingestion). Nothing in this
pipeline performs network I/O; the operator provides the lab boundary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate, candidate_signature, export_candidate
from tools.cross_domain import CrossDomainCorrelator
from tools.novelty_pipeline import AdvisoryCatalog, classify_novelty
from tools.reliability import atomic_write_json
from tools.sarif_export import export_candidates_sarif
from tools.runtime_paths import target_slug


def _from_observation(target: str, observation: Dict[str, Any]) -> ResearchCandidate:
    domain = str(observation.get("domain") or "").strip().lower()
    kind = str(observation.get("kind") or "").strip().lower()
    if domain == "web_api":
        if kind == "behavior_differential":
            return ResearchCandidate(
                domain="web_api", target=target, bug_class="behavior_differential",
                title=f"Behavioral delta on {observation.get('endpoint', '')}",
                endpoint=str(observation.get("endpoint") or ""), severity="medium",
                behavior={"baseline": {"status": observation.get("baseline_status"),
                                       "body": observation.get("baseline_body")},
                          "mutation": {"status": observation.get("status"),
                                       "body": observation.get("body")}})
        raise ValueError(f"unknown web_api observation kind: {kind}")
    if domain == "web3":
        if kind == "invariant_violation":
            invariants = observation.get("invariants") or {}
            violated = [name for name, holds in invariants.items() if not bool(holds)]
            sequence = list(observation.get("sequence") or [])
            return ResearchCandidate(
                domain="web3", target=target, bug_class="invariant_violation",
                title=f"Contract invariant violation: {', '.join(violated)}",
                endpoint=str(sequence[-1] if sequence else ""), severity="high",
                behavior={"sequence": sequence, "violated": violated,
                          "state_after": observation.get("state_after") or {}})
        raise ValueError(f"unknown web3 observation kind: {kind}")
    if domain == "ai":
        if kind == "tool_misuse":
            tool_call = observation.get("tool_call") or {}
            return ResearchCandidate(
                domain="ai", target=target, bug_class="tool_misuse",
                title=f"Agent tool misuse: {tool_call.get('tool', '')}",
                endpoint=str(tool_call.get("tool") or ""), severity="high",
                behavior={"tool": tool_call.get("tool"),
                          "arguments": tool_call.get("arguments") or {},
                          "context_source": observation.get("context_source") or ""})
        if kind in ("rag_injection", "memory_poisoning", "mcp_poisoning"):
            return ResearchCandidate(
                domain="ai", target=target, bug_class=kind,
                title=f"{kind.replace('_', ' ').title()} observed",
                severity="high",
                behavior={"source": observation.get("source") or "",
                          "chunk": str(observation.get("chunk") or "")[:2000],
                          "retrieved": bool(observation.get("retrieved")),
                          "influenced_output": bool(observation.get("influenced_output"))})
        raise ValueError(f"unknown ai observation kind: {kind}")
    raise ValueError(f"unknown domain: {domain}")


def run_pipeline(observations_file: str | Path, *,
                 advisories_file: Optional[str | Path] = None,
                 project_root: Optional[str | Path] = None) -> Dict[str, Any]:
    """Run the full offline pipeline and return report paths + counts."""
    root = Path(project_root or ".").expanduser().resolve()
    data = json.loads(Path(observations_file).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("observations file must be a JSON object with target + observations")
    target = str(data.get("target") or "")
    if not target:
        raise ValueError("observations file requires a target")
    slug = target_slug(target)

    candidates: List[ResearchCandidate] = []
    for observation in data.get("observations") or []:
        if not isinstance(observation, dict):
            continue
        candidates.append(_from_observation(target, observation))

    # Deduplicate by stable signature before persistence.
    unique: List[ResearchCandidate] = []
    seen: set = set()
    for candidate in candidates:
        signature = candidate_signature(candidate)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(candidate)

    # Persist through the shared locked store.
    store = CandidateStore(root / "state" / "sessions" / slug / "candidates.jsonl")
    added = 0
    for candidate in unique:
        if store.add(candidate):
            added += 1

    # Novelty classification against the advisory catalog.
    catalog = AdvisoryCatalog.load(advisories_file) if advisories_file and Path(advisories_file).is_file() else AdvisoryCatalog()
    for candidate in unique:
        verdict = classify_novelty(candidate, catalog)
        candidate.novelty = verdict["label"]

    # Cross-domain correlation.
    correlator = CrossDomainCorrelator(target, project_root=root)
    chains = correlator.correlate(unique)
    report_chains = correlator.write_report(chains)

    # Reports.
    slug_dir = root / "state" / "sessions" / slug
    report_json = slug_dir / "zero-day-report.json"
    report_markdown = slug_dir / "zero-day-report.md"
    report_sarif = slug_dir / "zero-day-results.sarif"
    atomic_write_json(report_json, {
        "schema": "bugwolf/zero-day-report/v1",
        "target": target,
        "candidates": [c.to_dict() for c in unique],
        "chain_count": len(chains),
        "chains": [chain.to_dict() for chain in chains],
        "added": added,
    })
    md_lines = [f"# Zero-Day Research Report — {target}", "",
                f"- Candidates: {len(unique)} (new: {added})",
                f"- Cross-domain chains: {len(chains)}", ""]
    for candidate in unique:
        md_lines.append(f"## {candidate.candidate_id} — {candidate.title}")
        md_lines.append(f"- Domain: `{candidate.domain}`  Status: `{candidate.status.value}`")
        md_lines.append(f"- Novelty: `{getattr(candidate, 'novelty', 'unknown')}`")
        md_lines.append(f"- Endpoint: `{candidate.endpoint}`")
        md_lines.append("")
    atomic_write_json(report_markdown, "\n".join(md_lines) + "\n")
    export_candidates_sarif(unique, report_sarif)

    return {
        "target": target,
        "candidates": len(unique),
        "added": added,
        "chains": len(chains),
        "report_json": report_json,
        "report_markdown": report_markdown,
        "report_sarif": report_sarif,
        "chain_report": report_chains,
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf zero-day pipeline runner")
    parser.add_argument("--observations", required=True,
                        help="path to observations.json")
    parser.add_argument("--advisories", default="",
                        help="path to advisory catalog JSON")
    parser.add_argument("--project-root", default="", help="workspace root override")
    args = parser.parse_args()
    try:
        result = run_pipeline(args.observations,
                              advisories_file=args.advisories or None,
                              project_root=args.project_root or None)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps({k: str(v) if hasattr(v, "is_file") else v for k, v in result.items()},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
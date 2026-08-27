#!/usr/bin/env python3
"""Candidate query CLI — list, filter, and export research candidates."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate
from tools.reliability import read_jsonl
from tools.sarif_export import export_candidates_sarif


def query_candidates(store_path: str | Path, *, domain: str = "",
                     status: str = "", bug_class: str = "",
                     severity: str = "", target: str = "",
                     limit: int = 100) -> Dict[str, Any]:
    """Filter stored candidates by domain/status/bug class/severity/target."""
    records, errors = read_jsonl(store_path)
    candidates: List[ResearchCandidate] = []
    for record in records:
        try:
            candidate = ResearchCandidate.from_dict(record)
        except (TypeError, ValueError):
            continue
        if domain and candidate.domain != domain:
            continue
        if status and candidate.status.value != status:
            continue
        if bug_class and bug_class not in candidate.bug_class:
            continue
        if severity and candidate.severity != severity:
            continue
        if target and candidate.target != target:
            continue
        candidates.append(candidate)
    candidates.sort(key=lambda c: c.created_at)
    return {
        "schema": "bugwolf/candidate-query/v1",
        "count": len(candidates),
        "total": sum(1 for _ in records),
        "corrupt_lines": len(errors),
        "candidates": [c.to_dict() for c in candidates[:max(1, limit)]],
    }


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf candidate query CLI")
    parser.add_argument("--store", default="state/sessions/default/candidates.jsonl",
                        help="path to candidates.jsonl")
    parser.add_argument("--domain", default="")
    parser.add_argument("--status", default="")
    parser.add_argument("--bug-class", default="")
    parser.add_argument("--severity", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--export-sarif", default="", help="write SARIF to this path")
    args = parser.parse_args(list(argv) if argv is not None else None)

    result = query_candidates(args.store, domain=args.domain, status=args.status,
                              bug_class=args.bug_class, severity=args.severity,
                              target=args.target, limit=args.limit)
    if args.export_sarif:
        candidates = [ResearchCandidate.from_dict(c) for c in result["candidates"]]
        export_candidates_sarif(candidates, args.export_sarif)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
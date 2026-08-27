#!/usr/bin/env python3
"""Operator dashboard — read-only summary of candidate and chain state.

Scans ``state/sessions/*/candidates.jsonl`` and ``state/chains/*/cross-domain.json``
and produces a deterministic summary for operators: counts by domain, status,
severity, novelty notes, active vs terminal candidates, chain coverage, and
corrupt-line reporting. This module never mutates state and never executes
anything against targets.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.candidate_lifecycle import CandidateStatus, ResearchCandidate
from tools.reliability import read_jsonl

_TERMINAL_STATUSES = {
    CandidateStatus.CONFIRMED.value,
    CandidateStatus.REJECTED.value,
    CandidateStatus.DUPLICATE.value,
    CandidateStatus.EXPECTED.value,
}


def _scan_candidates(root: Path) -> Dict[str, Any]:
    sessions = root / "state" / "sessions"
    targets: List[str] = []
    by_domain: Counter = Counter()
    by_status: Counter = Counter()
    by_severity: Counter = Counter()
    by_notes: Counter = Counter()
    corrupt_lines = 0
    active = 0
    terminal = 0
    total = 0
    if sessions.is_dir():
        for session_dir in sorted(sessions.iterdir()):
            if not session_dir.is_dir():
                continue
            store_path = session_dir / "candidates.jsonl"
            if not store_path.is_file():
                continue
            targets.append(session_dir.name)
            records, errors = read_jsonl(store_path)
            corrupt_lines += len(errors)
            for record in records:
                try:
                    candidate = ResearchCandidate.from_dict(record)
                except (TypeError, ValueError):
                    corrupt_lines += 1
                    continue
                total += 1
                by_domain[candidate.domain] += 1
                by_status[candidate.status.value] += 1
                by_severity[candidate.severity] += 1
                if candidate.status.value in _TERMINAL_STATUSES:
                    terminal += 1
                else:
                    active += 1
                for note in candidate.notes:
                    raw = str(note).strip()
                    if raw.lower().startswith("novelty:"):
                        key = raw.split(":", 1)[1].strip().lower()
                    else:
                        key = raw.split(":")[0].strip().lower()
                    by_notes[key] += 1
    return {
        "targets": sorted(targets),
        "candidate_count": total,
        "active_count": active,
        "terminal_count": terminal,
        "by_domain": dict(sorted(by_domain.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_notes": dict(sorted(by_notes.items())),
        "corrupt_lines": corrupt_lines,
    }


def _scan_chains(root: Path) -> Dict[str, Any]:
    chains_dir = root / "state" / "chains"
    chain_count = 0
    by_domain: Counter = Counter()
    by_severity: Counter = Counter()
    if chains_dir.is_dir():
        for target_dir in sorted(chains_dir.iterdir()):
            report_path = target_dir / "cross-domain.json"
            if not report_path.is_file():
                continue
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            for chain in report.get("chains") or []:
                chain_count += 1
                for domain in chain.get("domains") or []:
                    by_domain[domain] += 1
                by_severity[chain.get("severity") or "info"] += 1
    return {
        "chain_count": chain_count,
        "chains_by_domain": dict(sorted(by_domain.items())),
        "chains_by_severity": dict(sorted(by_severity.items())),
    }


def dashboard_summary(project_root: str | Path = ".") -> Dict[str, Any]:
    """Return a deterministic operator summary for the state under root."""
    root = Path(project_root).expanduser().resolve()
    candidates = _scan_candidates(root)
    chains = _scan_chains(root)
    return {
        "schema": "bugwolf/operator-dashboard/v1",
        "project_root": str(root),
        **candidates,
        **chains,
    }


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf operator dashboard")
    parser.add_argument("--root", default=".", help="project root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="pretty-print JSON summary")
    args = parser.parse_args(list(argv) if argv is not None else None)
    summary = dashboard_summary(args.root)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"Targets:           {len(summary['targets'])}")
        print(f"Candidates:       {summary['candidate_count']} "
              f"(active={summary['active_count']}, terminal={summary['terminal_count']})")
        print(f"By domain:        {summary['by_domain']}")
        print(f"By status:        {summary['by_status']}")
        print(f"By severity:      {summary['by_severity']}")
        print(f"Cross-domain chains: {summary['chain_count']} "
              f"({summary['chains_by_domain']})")
        print(f"Corrupt lines:    {summary['corrupt_lines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
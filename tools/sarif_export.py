#!/usr/bin/env python3
"""SARIF 2.1.0 exporter for shared research candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

from tools.candidate_lifecycle import ResearchCandidate
from tools.reliability import atomic_write_json

_LEVEL_RANK = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def export_candidates_sarif(candidates: Iterable[ResearchCandidate],
                            path: str | Path) -> Path:
    candidates = list(candidates)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for candidate in candidates:
        rule_id = candidate.bug_class or "candidate"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": candidate.title or rule_id},
            "properties": {"tags": [candidate.domain], "severity": candidate.severity},
        })
        locations = []
        if candidate.endpoint:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": candidate.endpoint},
                },
                "logicalLocations": [{"name": candidate.endpoint}],
            })
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL_RANK.get(str(candidate.severity).lower(), "note"),
            "message": {"text": candidate.title or rule_id},
            "locations": locations,
            "partialFingerprints": {"primaryLocationLineHash": candidate.signature},
            "properties": {
                "candidate_id": candidate.candidate_id,
                "domain": candidate.domain,
                "status": candidate.status.value,
                "behavior": candidate.behavior,
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "BugWolf", "version": "1", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return atomic_write_json(path, sarif)
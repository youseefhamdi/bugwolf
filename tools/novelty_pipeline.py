#!/usr/bin/env python3
"""Phase 1 novelty pipeline and reproducibility infrastructure.

Deterministic advisory correlation, novelty classification, candidate
ranking, and reproducibility manifests. Offline and bounded: no network
access, no authorization gates, no model calls.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import ResearchCandidate, candidate_signature
from tools.reliability import atomic_write_json

_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def _tokens(*values: Any) -> set:
    out: set = set()
    for value in values:
        if isinstance(value, str):
            out.update(_TOKEN_RE.findall(value.lower()))
        elif isinstance(value, dict):
            out.update(_tokens(list(value.values())))
        elif isinstance(value, (list, tuple)):
            for item in value:
                out.update(_tokens(item))
    return out


def _candidate_text(candidate: ResearchCandidate) -> str:
    parts = [candidate.title, candidate.bug_class, candidate.endpoint,
             candidate.severity]
    parts.extend(str(v) for v in (candidate.behavior or {}).values())
    return " ".join(parts)


@dataclass
class AdvisoryRecord:
    cve_id: str
    keywords: List[str] = field(default_factory=list)
    description: str = ""
    severity: str = "info"
    source: str = "local"
    published: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdvisoryRecord":
        return cls(**data)


class AdvisoryCatalog:
    """Deterministic local advisory corpus with token matching."""

    def __init__(self, records: Iterable[Dict[str, Any]] = ()):
        self.records: List[AdvisoryRecord] = []
        for record in records:
            if isinstance(record, AdvisoryRecord):
                self.records.append(record)
            elif isinstance(record, dict):
                self.records.append(AdvisoryRecord.from_dict(record))
        self._index: Dict[str, List[AdvisoryRecord]] = {}
        for record in self.records:
            for token in _tokens(record.cve_id) | _tokens(record.keywords) | _tokens(record.description):
                self._index.setdefault(token, []).append(record)

    def match(self, candidate: ResearchCandidate) -> List[AdvisoryRecord]:
        tokens = _tokens(_candidate_text(candidate))
        scored: Dict[str, int] = {}
        for token in tokens:
            for record in self._index.get(token, []):
                scored[record.cve_id] = scored.get(record.cve_id, 0) + 1
        matches = [record for record in self.records if scored.get(record.cve_id, 0) >= 2]
        matches.sort(key=lambda r: (-scored[r.cve_id], r.cve_id))
        return matches

    def write(self, path: str | Path) -> None:
        atomic_write_json(path, {
            "schema": "bugwolf/advisory-catalog/v1",
            "records": [r.to_dict() for r in self.records],
        })

    @classmethod
    def load(cls, path: str | Path) -> "AdvisoryCatalog":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        records = data.get("records", []) if isinstance(data, dict) else data
        return cls(records)


def classify_novelty(candidate: ResearchCandidate,
                     catalog: Optional[AdvisoryCatalog] = None,
                     known_candidates: Iterable[ResearchCandidate] = ()) -> Dict[str, Any]:
    """Return a deterministic novelty verdict for one candidate."""
    matches = catalog.match(candidate) if catalog else []
    known_ids = {other.candidate_id for other in known_candidates}
    duplicate = candidate.candidate_id in known_ids
    if matches:
        return {
            "label": "known",
            "known": True,
            "duplicate": duplicate,
            "matches": [{"cve_id": r.cve_id, "severity": r.severity,
                         "description": r.description[:200]} for r in matches],
            "reasons": [f"advisory match: {matches[0].cve_id}"],
        }
    if duplicate:
        return {
            "label": "duplicate",
            "known": False,
            "duplicate": True,
            "matches": [],
            "reasons": ["already present in the local candidate store"],
        }
    return {
        "label": "potentially_novel",
        "known": False,
        "duplicate": False,
        "matches": [],
        "reasons": ["no local advisory or duplicate match found"],
    }


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_NOVELTY_RANK = {"potentially_novel": 0, "known": 1, "duplicate": 2}


def rank_candidates(candidates: Iterable[ResearchCandidate]) -> List[ResearchCandidate]:
    """Rank candidates: novel + severe + high-confidence first."""
    return sorted(
        candidates,
        key=lambda c: (
            _NOVELTY_RANK.get(str(getattr(c, "novelty", "")), 3),
            _SEVERITY_RANK.get(str(c.severity).lower(), 4),
            -float(getattr(c, "confidence", 0.0) or 0.0),
            c.candidate_id,
        ),
    )


def _similarity(a: ResearchCandidate, b: ResearchCandidate) -> float:
    """Token Jaccard similarity over candidate text."""
    tokens_a = _tokens(_candidate_text(a))
    tokens_b = _tokens(_candidate_text(b))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def cluster_near_duplicates(candidates: Iterable[ResearchCandidate], *,
                            threshold: float = 0.6) -> List[List[str]]:
    """Group near-duplicate candidate IDs by token similarity.

    Deterministic single-linkage clustering over the shared candidate text.
    Returns clusters of candidate IDs (sorted), each of size >= 1.
    """
    candidates = list(candidates)
    parent = {c.candidate_id: c.candidate_id for c in candidates}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            if _similarity(candidates[i], candidates[j]) >= threshold:
                union(candidates[i].candidate_id, candidates[j].candidate_id)

    groups: Dict[str, List[str]] = {}
    for candidate in candidates:
        groups.setdefault(find(candidate.candidate_id), []).append(candidate.candidate_id)
    return [sorted(ids) for ids in groups.values()]


def build_reproducibility_manifest(*, target: str, candidate_id: str,
                                   fixture_digest: str = "",
                                   tool_versions: Optional[Dict[str, str]] = None,
                                   action_sequence: Optional[List[str]] = None,
                                   initial_state: Optional[Dict[str, Any]] = None,
                                   seeds: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a deterministic reproducibility manifest for one candidate."""
    return {
        "schema": "bugwolf/reproducibility-manifest/v1",
        "target": target,
        "candidate_id": candidate_id,
        "fixture_digest": fixture_digest,
        "tool_versions": dict(tool_versions or {}),
        "action_sequence": list(action_sequence or []),
        "initial_state": dict(initial_state or {}),
        "seeds": dict(seeds or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
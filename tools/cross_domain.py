#!/usr/bin/env python3
"""Phase 5 cross-domain correlation.

Links shared-schema candidates from the AI, Web/API, and Web3 domains into
bounded evidence chains using stable, deterministic evidence tokens. Chains
are advisory research hypotheses — never claims of confirmed zero-days.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStatus, ResearchCandidate, candidate_signature
from tools.reliability import atomic_write_json

_URL_PATH_RE = re.compile(r"https?://[^/\s\"']+([^\s\"']*)")
_TOKEN_RE = re.compile(r"[a-z0-9_]{3,}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text_tokens(text: str) -> set:
    return set(_TOKEN_RE.findall(str(text).lower()))


def _url_paths(text: str) -> set:
    paths = set()
    for match in _URL_PATH_RE.finditer(str(text)):
        raw = match.group(1) or "/"
        paths.add(raw)
        for segment in raw.split("/"):
            if len(segment) >= 3:
                paths.add("/" + segment)
    return paths


def _candidate_tokens(candidate: ResearchCandidate) -> set:
    tokens: set = set()
    tokens.update(_text_tokens(candidate.endpoint))
    tokens.update(_url_paths(candidate.endpoint))
    chunks = [candidate.title, candidate.bug_class]
    for value in (candidate.behavior or {}).values():
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, (list, dict)):
            chunks.append(json.dumps(value, sort_keys=True, default=str))
    for chunk in chunks:
        tokens.update(_text_tokens(chunk))
        tokens.update(_url_paths(chunk))
    return tokens


@dataclass
class CrossDomainChain:
    chain_id: str
    target: str
    candidate_ids: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    shared_tokens: List[str] = field(default_factory=list)
    severity: str = "info"
    schema: str = "bugwolf/cross-domain-chain/v1"
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now()
        if not self.chain_id:
            raw = "|".join(sorted(self.candidate_ids))
            self.chain_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CrossDomainCorrelator:
    """Deterministically link candidates from different domains."""

    def __init__(self, target: str, *, project_root: Optional[str] = None,
                 max_chain_depth: int = 8):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.report_dir = root / "state" / "chains" / target_slug(target)
        self.max_chain_depth = max(1, max_chain_depth)

    def correlate(self, candidates: Iterable[ResearchCandidate]) -> List[CrossDomainChain]:
        candidates = [c for c in candidates if c.domain != ""]
        if len(candidates) < 2:
            return []
        # Build a bounded adjacency list from stable shared tokens.
        token_index: Dict[str, set] = {}
        for candidate in candidates:
            for token in _candidate_tokens(candidate):
                token_index.setdefault(token, set()).add(candidate.candidate_id)
        edges: Dict[str, set] = {c.candidate_id: set() for c in candidates}
        for candidate in candidates:
            for token in _candidate_tokens(candidate):
                for other_id in token_index.get(token, set()):
                    if other_id != candidate.candidate_id:
                        edges[candidate.candidate_id].add(other_id)
        # Deterministic BFS over each candidate (stable order), bounded depth.
        by_id = {c.candidate_id: c for c in candidates}
        visited: set = set()
        chains: List[List[str]] = []
        for start in sorted(by_id):
            if start in visited:
                continue
            frontier = [start]
            component: List[str] = []
            while frontier and len(component) < self.max_chain_depth:
                next_frontier = []
                for node in sorted(frontier):
                    if node in visited or node in component or len(component) >= self.max_chain_depth:
                        continue
                    visited.add(node)
                    component.append(node)
                    for neighbor in sorted(edges.get(node, set())):
                        if neighbor not in visited and neighbor not in component:
                            next_frontier.append(neighbor)
                frontier = next_frontier
            if len(component) >= 2:
                chains.append(sorted(component))
        result: List[CrossDomainChain] = []
        for component in chains:
            members = [by_id[c] for c in component]
            domains = sorted({m.domain for m in members})
            if len(domains) < 2:
                continue
            shared = sorted(set.intersection(
                *(_candidate_tokens(m) for m in members)))
            severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            severity = min(members, key=lambda m: severity_rank.get(m.severity, 4)).severity
            result.append(CrossDomainChain(
                chain_id="",
                target=self.target,
                candidate_ids=component,
                domains=domains,
                shared_tokens=shared[:16],
                severity=severity,
            ))
        result.sort(key=lambda chain: (len(chain.candidate_ids), chain.chain_id))
        return result

    def write_report(self, chains: Iterable[CrossDomainChain]) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / "cross-domain.json"
        atomic_write_json(path, {
            "schema": "bugwolf/cross-domain-report/v1",
            "target": self.target,
            "chain_count": len(list(chains)),
            "chains": [chain.to_dict() for chain in chains],
            "generated_at": _now(),
        })
        return path
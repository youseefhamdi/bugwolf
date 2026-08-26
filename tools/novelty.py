#!/usr/bin/env python3
"""Novelty assessment for potentially undisclosed vulnerability candidates.

This module does not claim a candidate is a zero-day. It records exact and
near matches, preserves research sources, and emits a reviewable novelty label.
External search is injected by callers so the core remains deterministic and
testable offline.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

try:
    from tools.research_model import (
        CandidateStatus, NoveltyLabel, ResearchCandidate,
    )
except ImportError:
    from research_model import CandidateStatus, NoveltyLabel, ResearchCandidate

try:
    from tools.runtime_paths import target_slug
except ImportError:
    from runtime_paths import target_slug

try:
    from tools.art_selector import payload_tokens
except ImportError:  # pragma: no cover - direct script execution
    from art_selector import payload_tokens  # type: ignore

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

ROOT = workspace_root()
RESEARCH_ROOT = ROOT / "state" / "research"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _normalise(value: str) -> str:
    return " ".join(_TOKEN_RE.findall(str(value).lower()))


def candidate_payload(candidate: ResearchCandidate) -> Optional[str]:
    """The SQLi/trigger payload carried by a candidate, if any.

    Payload-bearing candidates (from mutation/differential flows) store the
    concrete value in metadata. Payload token identity is a much stronger
    duplicate signal than hypothesis wording, so novelty assessment uses it
    when present.
    """
    for key in ("payload", "mutated"):
        value = candidate.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def candidate_fingerprint(candidate: ResearchCandidate) -> str:
    """Create a stable, location-aware fingerprint for local deduplication.

    When the candidate carries a concrete payload value, its ART4SQLi token
    decomposition joins the fingerprint so identical triggers deduplicate even
    when hypothesis wording differs.
    """
    parts = [
        candidate.surface.value,
        _normalise(candidate.bug_class),
        _normalise(candidate.location),
        _normalise(candidate.hypothesis),
    ]
    payload = candidate_payload(candidate)
    if payload:
        parts.append("|".join(payload_tokens(payload)))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


@dataclass
class NoveltyAssessment:
    label: NoveltyLabel
    score: float
    exact_match: bool = False
    matches: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


class CandidateIndex:
    """Append-only local index of candidates and their novelty decisions."""

    def __init__(self, target: str):
        self.target = target
        self.path = RESEARCH_ROOT / target_slug(target) / "candidates.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, candidate: ResearchCandidate) -> None:
        record = candidate.to_dict()
        record["fingerprint"] = candidate_fingerprint(candidate)
        with open(self.path, "a") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def all(self) -> List[ResearchCandidate]:
        if not self.path.exists():
            return []
        candidates = []
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                candidates.append(ResearchCandidate.from_dict(json.loads(line)))
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                continue
        return candidates


class NoveltyEngine:
    """Compare candidates with local history and injected research results."""

    def __init__(self, target: str, *, similarity_threshold: float = 0.82):
        self.target = target
        self.index = CandidateIndex(target)
        self.similarity_threshold = similarity_threshold

    def assess(self, candidate: ResearchCandidate,
               known: Optional[Iterable[ResearchCandidate]] = None) -> NoveltyAssessment:
        known_candidates = list(known) if known is not None else self.index.all()
        fingerprint = candidate_fingerprint(candidate)
        matches = []
        best = 0.0
        exact = False
        payload_exact = False
        for other in known_candidates:
            if other.candidate_id == candidate.candidate_id:
                continue
            other_fp = candidate_fingerprint(other)
            if other_fp == fingerprint:
                score = 1.0
                exact = True
            else:
                hypothesis_similarity = SequenceMatcher(
                    None,
                    _normalise(candidate.hypothesis),
                    _normalise(other.hypothesis),
                ).ratio()
                same_bug_class = (
                    _normalise(candidate.bug_class) == _normalise(other.bug_class)
                )
                same_location = (
                    _normalise(candidate.location) == _normalise(other.location)
                )
                # Location and bug class are stronger duplicate signals than
                # title wording. Weight them explicitly to catch variants that
                # rename an identifier without merging unrelated endpoints.
                context_score = (int(same_bug_class) + int(same_location)) / 2.0
                score = 0.75 * hypothesis_similarity + 0.25 * context_score
                # Payload token identity (ART4SQLi grammar-token cosine over
                # the two payloads) is a stronger duplicate signal than prose:
                # two candidates that ship the same trigger are the same bug
                # even when their hypotheses are worded differently. Raw
                # term-frequency cosine is used (not TF-IDF) because a
                # two-document corpus zeroes IDF for shared tokens.
                my_payload = candidate_payload(candidate)
                other_payload = candidate_payload(other)
                if my_payload and other_payload:
                    my_counts = Counter(payload_tokens(my_payload))
                    other_counts = Counter(payload_tokens(other_payload))
                    if my_counts and other_counts:
                        dot = sum(count * other_counts[token]
                                  for token, count in my_counts.items())
                        norm = (math.sqrt(sum(c * c for c in my_counts.values()))
                                * math.sqrt(sum(c * c for c in other_counts.values())))
                        cosine = dot / norm if norm else 0.0
                        if cosine >= 1.0 - 1e-9:
                            payload_exact = True
                        score = max(score, max(0.0, cosine))
            if score >= self.similarity_threshold:
                matches.append({
                    "candidate_id": other.candidate_id,
                    "score": round(score, 4),
                    "status": other.status.value,
                    "source": other.metadata.get("source", "local"),
                })
            best = max(best, score)

        if exact or payload_exact:
            label = NoveltyLabel.EXACT_DUPLICATE
            reasons = (["stable fingerprint matches a local candidate"]
                       if exact else [])
            if payload_exact:
                reasons.append("identical payload token signature")
        elif best >= self.similarity_threshold:
            label = NoveltyLabel.LIKELY_VARIANT
            reasons = [f"near-match similarity {best:.3f} exceeds threshold"]
        else:
            label = NoveltyLabel.POTENTIALLY_NOVEL
            reasons = ["no local exact or near match found"]

        return NoveltyAssessment(
            label=label,
            score=round(1.0 - best if best else 1.0, 4),
            exact_match=exact,
            matches=matches,
            reasons=reasons,
        )

    def apply(self, candidate: ResearchCandidate,
              assessment: NoveltyAssessment) -> ResearchCandidate:
        candidate.novelty = assessment.label
        candidate.novelty_score = assessment.score
        candidate.known_matches = assessment.matches
        candidate.metadata["novelty_reasons"] = assessment.reasons
        if candidate.status == CandidateStatus.IMPACT_BOUNDED:
            candidate.transition(CandidateStatus.NOVELTY_PENDING,
                                 reason="deterministic novelty assessment completed")
        self.index.add(candidate)
        return candidate

    def research_sequential(
        self,
        candidate: ResearchCandidate,
        researchers: Dict[str, Callable[[ResearchCandidate], Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Run research adapters one at a time in stable source order."""
        results: List[Dict[str, Any]] = []
        for name in sorted(researchers):
            try:
                results.append({"source": name, "ok": True,
                                "result": researchers[name](candidate)})
            except Exception as exc:
                results.append({"source": name, "ok": False,
                                "error": str(exc)[:500]})
        candidate.metadata["sequential_research"] = results
        # Compatibility alias for consumers written before sequencing became
        # mandatory; the values are still produced serially.
        candidate.metadata["parallel_research"] = results
        return results

    def research_parallel(
        self,
        candidate: ResearchCandidate,
        researchers: Dict[str, Callable[[ResearchCandidate], Dict[str, Any]]],
        *,
        max_workers: int = 4,
    ) -> List[Dict[str, Any]]:
        """Run independent local/public research adapters in parallel.

        Adapters must return structured metadata and are responsible for their
        own network authorization. Exceptions become recorded research errors,
        never silent evidence of novelty.
        """
        results: List[Dict[str, Any]] = []
        if not researchers:
            return results
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(researchers)))) as pool:
            futures = {
                pool.submit(worker, candidate): name
                for name, worker in researchers.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results.append({"source": name, "ok": True, "result": result})
                except Exception as exc:
                    results.append({"source": name, "ok": False,
                                    "error": str(exc)[:500]})
        results.sort(key=lambda item: item["source"])
        candidate.metadata["parallel_research"] = results
        return results

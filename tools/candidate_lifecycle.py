#!/usr/bin/env python3
"""Shared candidate lifecycle and novelty primitives.

This module is intentionally dependency-free and deterministic. Domain
adapters may add richer evidence, but only this lifecycle owns candidate state
transitions. It does not authorize or scope execution.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from tools.reliability import append_jsonl, read_jsonl, atomic_write_json

SCHEMA = "bugwolf/research-candidate/v1"


class CandidateStatus(str, Enum):
    DISCOVERED = "discovered"
    NORMALIZED = "normalized"
    DEDUPLICATED = "deduplicated"
    TRIAGED = "triaged"
    REPRODUCTION_PENDING = "reproduction_pending"
    REPRODUCED = "reproduced"
    NOVELTY_PENDING = "novelty_pending"
    IMPACT_VALIDATION = "impact_validation"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    EXPECTED = "expected"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


_TERMINAL = {
    CandidateStatus.CONFIRMED,
    CandidateStatus.REJECTED,
    CandidateStatus.DUPLICATE,
    CandidateStatus.EXPECTED,
}
_DOMAINS = {"web3", "web_api", "ai"}

# The forward path is explicit; terminal outcomes may be reached from any
# active state when evidence supports the decision.
_FORWARD = {
    CandidateStatus.DISCOVERED: {CandidateStatus.NORMALIZED, CandidateStatus.BLOCKED},
    CandidateStatus.NORMALIZED: {CandidateStatus.DEDUPLICATED, CandidateStatus.BLOCKED},
    CandidateStatus.DEDUPLICATED: {CandidateStatus.TRIAGED, CandidateStatus.DUPLICATE, CandidateStatus.BLOCKED},
    CandidateStatus.TRIAGED: {CandidateStatus.REPRODUCTION_PENDING, CandidateStatus.REJECTED, CandidateStatus.BLOCKED},
    CandidateStatus.REPRODUCTION_PENDING: {CandidateStatus.REPRODUCED, CandidateStatus.INCONCLUSIVE, CandidateStatus.BLOCKED},
    CandidateStatus.REPRODUCED: {CandidateStatus.NOVELTY_PENDING, CandidateStatus.IMPACT_VALIDATION, CandidateStatus.BLOCKED},
    CandidateStatus.NOVELTY_PENDING: {CandidateStatus.IMPACT_VALIDATION, CandidateStatus.DUPLICATE, CandidateStatus.EXPECTED, CandidateStatus.BLOCKED},
    CandidateStatus.IMPACT_VALIDATION: {CandidateStatus.CONFIRMED, CandidateStatus.REJECTED, CandidateStatus.INCONCLUSIVE, CandidateStatus.BLOCKED},
    CandidateStatus.BLOCKED: {CandidateStatus.REPRODUCTION_PENDING, CandidateStatus.REJECTED, CandidateStatus.INCONCLUSIVE},
    CandidateStatus.INCONCLUSIVE: {CandidateStatus.REPRODUCTION_PENDING, CandidateStatus.REJECTED, CandidateStatus.BLOCKED},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


@dataclass
class ResearchCandidate:
    domain: str
    title: str = ""
    candidate_id: str = ""
    status: CandidateStatus = CandidateStatus.DISCOVERED
    target: str = ""
    bug_class: str = ""
    severity: str = "info"
    endpoint: str = ""
    behavior: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    payload_lineage: List[Dict[str, Any]] = field(default_factory=list)
    operation_ids: List[str] = field(default_factory=list)
    parent_candidate_ids: List[str] = field(default_factory=list)
    signature: str = ""
    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)
    schema: str = SCHEMA
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.domain = str(self.domain).strip().lower()
        if self.domain not in _DOMAINS:
            raise ValueError(f"domain must be one of {sorted(_DOMAINS)}")
        if not isinstance(self.status, CandidateStatus):
            try:
                self.status = CandidateStatus(str(self.status))
            except ValueError as exc:
                raise ValueError(f"unknown candidate status: {self.status}") from exc
        if not self.candidate_id:
            self.candidate_id = _uuid()
        if not self.created_at:
            self.created_at = _now()
        if not self.updated_at:
            self.updated_at = self.created_at
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if self.schema != SCHEMA:
            raise ValueError(f"unsupported candidate schema: {self.schema}")
        if not self.signature:
            self.signature = candidate_signature(self)

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResearchCandidate":
        data = dict(value)
        data.setdefault("schema", SCHEMA)
        data.setdefault("behavior", {})
        data.setdefault("evidence_refs", [])
        data.setdefault("payload_lineage", [])
        data.setdefault("operation_ids", [])
        data.setdefault("parent_candidate_ids", [])
        data.setdefault("notes", [])
        return cls(**{key: data[key] for key in cls.__dataclass_fields__ if key in data})

    def transition(self, status: CandidateStatus | str, *, note: str = "") -> "ResearchCandidate":
        next_status = status if isinstance(status, CandidateStatus) else CandidateStatus(str(status))
        if self.status in _TERMINAL:
            raise ValueError(f"terminal candidate cannot transition: {self.status.value}")
        allowed = _FORWARD.get(self.status, set())
        if next_status not in allowed:
            raise ValueError(f"invalid candidate transition: {self.status.value} -> {next_status.value}")
        self.status = next_status
        if note:
            self.notes.append(str(note))
        self.updated_at = _now()
        return self


def candidate_signature(candidate: ResearchCandidate | Mapping[str, Any]) -> str:
    """Return a stable behavioral identity excluding volatile fields."""
    data = candidate.to_dict() if isinstance(candidate, ResearchCandidate) else dict(candidate)
    identity = {
        "domain": data.get("domain", ""),
        "target": data.get("target", ""),
        "bug_class": data.get("bug_class", ""),
        "endpoint": data.get("endpoint", ""),
        "behavior": data.get("behavior", {}),
        "payload_lineage": data.get("payload_lineage", []),
    }
    return hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()


def migrate_candidate(value: Mapping[str, Any]) -> ResearchCandidate:
    """Convert legacy finding/exploit records to the shared candidate schema."""
    data = dict(value)
    behavior = dict(data.get("behavior") or {})
    for key in ("confirmed_behavior", "demonstrated_impact", "impact", "response", "evidence"):
        if key in data and key not in behavior:
            behavior[key] = data[key]
    domain = data.get("domain")
    if not domain:
        bug_class = str(data.get("bug_class") or "").lower()
        domain = "web3" if any(x in bug_class for x in ("contract", "defi", "solidity", "oracle", "bridge")) else "ai" if any(x in bug_class for x in ("prompt", "llm", "agent", "rag", "mcp")) else "web_api"
    candidate_id = str(data.get("candidate_id") or data.get("finding_id") or data.get("id") or "")
    return ResearchCandidate(
        domain=domain,
        candidate_id=candidate_id,
        title=str(data.get("title") or data.get("objective") or data.get("bug_class") or "Legacy candidate"),
        target=str(data.get("target") or ""),
        bug_class=str(data.get("bug_class") or ""),
        severity=str(data.get("severity") or "info"),
        endpoint=str(data.get("endpoint") or ""),
        behavior=behavior,
        evidence_refs=list(data.get("evidence_refs") or []),
        operation_ids=list(data.get("operation_ids") or []),
        created_at=str(data.get("created_at") or data.get("found_at") or ""),
    )


class CandidateStore:
    """Locked append-only candidate store with signature deduplication."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def add(self, candidate: ResearchCandidate) -> bool:
        existing = self.load()
        signatures = {item.signature for item in existing}
        if candidate.signature in signatures:
            return False
        append_jsonl(self.path, candidate.to_dict())
        return True

    def load(self) -> List[ResearchCandidate]:
        records, _ = read_jsonl(self.path)
        latest: Dict[str, ResearchCandidate] = {}
        for record in records:
            try:
                candidate = ResearchCandidate.from_dict(record)
            except (TypeError, ValueError):
                continue
            latest[candidate.candidate_id] = candidate
        return list(latest.values())

    def migrate_legacy(self, records: Iterable[Mapping[str, Any]]) -> int:
        added = 0
        for record in records:
            if self.add(migrate_candidate(record)):
                added += 1
        return added

    def migrate_file(self, source: str | Path) -> int:
        """Import legacy JSONL records, tolerating malformed lines."""
        records, _ = read_jsonl(source)
        return self.migrate_legacy(records)


def export_candidate(candidate: ResearchCandidate, directory: str | Path) -> Dict[str, Path]:
    """Write a candidate's machine-readable and researcher-readable reports."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / f"{candidate.candidate_id}.json"
    markdown_path = root / f"{candidate.candidate_id}.md"
    atomic_write_json(json_path, candidate.to_dict())
    lines = [
        f"# Research Candidate {candidate.candidate_id}", "",
        f"- Domain: `{candidate.domain}`",
        f"- Status: `{candidate.status.value}`",
        f"- Bug class: `{candidate.bug_class or 'unspecified'}`",
        f"- Severity: `{candidate.severity}`",
        f"- Signature: `{candidate.signature}`", "",
        "## Title", "", candidate.title, "",
        "## Behavioral evidence", "",
        "```json", _canonical(candidate.behavior), "```", "",
        "## Evidence references", "",
    ]
    lines.extend(f"- `{ref}`" for ref in candidate.evidence_refs) or lines.append("- None")
    from tools.reliability import atomic_write_text
    atomic_write_text(markdown_path, "\n".join(lines) + "\n")
    return {"json": json_path, "markdown": markdown_path}

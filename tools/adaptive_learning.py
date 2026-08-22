#!/usr/bin/env python3
"""BugWolf adaptive learning memory.

This module learns *records*, not executable code. New techniques discovered in
research or a journey are quarantined as candidates. Only an explicit review
with evidence can approve a record for reuse on later journeys. The store is
append-only JSONL, target-isolated, redacted, and deterministic to inspect.

No network, subprocess, payload execution, or source-code mutation occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


SCHEMA = "bugwolf-adaptive-learning/v1"
STATUSES = {"candidate", "approved", "rejected"}
MAX_TEXT = 320
MAX_TERMS = 16
SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: Any, limit: int = MAX_TEXT) -> str:
    text = str(value or "")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda match: match.group(0)[:4] + "[…]", text)
    text = re.sub(r"(?i)(cookie|authorization)\s*[:=]\s*[^\s]+", r"\1: […]", text)
    return " ".join(text.split())[:limit]


def _term_candidates(value: Any) -> List[str]:
    """Extract conservative reusable labels, never raw payload fragments."""
    stop = {"2026", "2025", "latest", "technique", "techniques", "security",
            "vulnerability", "disclosed", "report", "bypass", "filter"}
    return [token.lower() for token in re.findall(
        r"[A-Za-z][A-Za-z0-9._:/-]{2,}", str(value or ""))
        if token.lower() not in stop][:MAX_TERMS]


def _safe_terms(values: Iterable[Any]) -> List[str]:
    terms: List[str] = []
    for value in values:
        term = _redact(value, 80).strip()
        if not term or len(term) > 80:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,79}", term):
            continue
        if term.lower() in {item.lower() for item in terms}:
            continue
        terms.append(term)
        if len(terms) >= MAX_TERMS:
            break
    return terms


def _source_refs(values: Iterable[Any]) -> List[str]:
    refs: List[str] = []
    for value in values:
        ref = _redact(value, 400).strip()
        if not (ref.startswith("https://") or ref.startswith("bundle://")):
            continue
        if ref not in refs:
            refs.append(ref)
        if len(refs) >= 12:
            break
    return refs


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._:-]+", "_", str(value or "")).strip("._")[:160] or "default"


def _canonical(value: str) -> str:
    return re.sub(r"\s+", " ", _redact(value).lower()).strip()


def _technique_id(kind: str, title: str, summary: str, bug_classes: Iterable[str]) -> str:
    raw = "|".join([
        _canonical(kind), _canonical(title), _canonical(summary),
        ",".join(sorted(_canonical(item) for item in bug_classes if item)),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _memory_root(explicit: Optional[str | Path] = None) -> Path:
    return workspace_root(explicit) / "state" / "learning"


class AdaptiveMemory:
    """Append-only, target-isolated technique memory."""

    def __init__(self, target: str, root: Optional[str | Path] = None):
        self.target = target or "default"
        self.directory = _memory_root(root)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / f"{_slug(self.target)}.jsonl"

    def _read_latest(self) -> Dict[str, Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        if not self.path.exists():
            return latest
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return latest
        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and record.get("technique_id"):
                latest[str(record["technique_id"])] = record
        return latest

    def _append(self, record: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            if fcntl:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            if fcntl:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def all(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        records = list(self._read_latest().values())
        if status:
            records = [record for record in records if record.get("status") == status]
        records.sort(key=lambda record: (
            record.get("status") != "approved",
            -int(record.get("seen_count", 0)),
            record.get("technique_id", ""),
        ))
        return records

    def approved(self, limit: int = 32) -> List[Dict[str, Any]]:
        """Return only explicitly reviewed techniques safe for reuse."""
        return self.all("approved")[:max(0, limit)]

    def ingest(self, *, kind: str, title: str, summary: str = "",
               bug_classes: Iterable[str] = (), defenses: Iterable[str] = (),
               source_refs: Iterable[str] = (), evidence_refs: Iterable[str] = (),
               terms: Iterable[str] = (), journey: str = "") -> Dict[str, Any]:
        """Record a quarantined candidate or merge it into an existing record."""
        title = _redact(title)
        summary = _redact(summary)
        bug_classes = [_redact(item, 80) for item in bug_classes if _redact(item, 80)]
        defenses = [_redact(item, 100) for item in defenses if _redact(item, 100)]
        technique_id = _technique_id(kind, title, summary, bug_classes)
        now = _now()
        latest = self._read_latest().get(technique_id)
        if latest:
            merged = dict(latest)
            merged["last_seen"] = now
            merged["seen_count"] = int(latest.get("seen_count", 1)) + 1
            for field in ("bug_classes", "defenses", "source_refs", "evidence_refs", "terms", "journeys"):
                values = list(latest.get(field, []))
                incoming = {
                    "bug_classes": bug_classes,
                    "defenses": defenses,
                    "source_refs": _source_refs(source_refs),
                    "evidence_refs": _source_refs(evidence_refs),
                    "terms": _safe_terms(terms),
                    "journeys": [_redact(journey, 120)] if journey else [],
                }[field]
                for value in incoming:
                    if value and value not in values:
                        values.append(value)
                merged[field] = values[:32]
            # A review decision is never downgraded by later ingestion.
            self._append(merged)
            return merged

        record = {
            "schema": SCHEMA,
            "technique_id": technique_id,
            "target": _redact(self.target, 160),
            "kind": _redact(kind, 80),
            "title": title,
            "summary": summary,
            "bug_classes": sorted(set(bug_classes))[:16],
            "defenses": sorted(set(defenses))[:16],
            "source_refs": _source_refs(source_refs),
            "evidence_refs": _source_refs(evidence_refs),
            "terms": _safe_terms(terms),
            "journeys": [_redact(journey, 120)] if journey else [],
            "status": "candidate",
            "confidence": "unreviewed",
            "seen_count": 1,
            "first_seen": now,
            "last_seen": now,
            "review": None,
        }
        self._append(record)
        return record

    def review(self, technique_id: str, decision: str, reviewer: str,
               evidence: str) -> Dict[str, Any]:
        """Approve/reject a candidate with an explicit evidence-bearing review."""
        if decision not in {"approve", "reject"}:
            raise ValueError("decision must be approve or reject")
        if not reviewer.strip() or not evidence.strip():
            raise ValueError("reviewer and evidence are required")
        records = self._read_latest()
        record = records.get(technique_id)
        if not record:
            raise KeyError(f"unknown technique: {technique_id}")
        updated = dict(record)
        updated["status"] = "approved" if decision == "approve" else "rejected"
        updated["confidence"] = "reviewed"
        updated["review"] = {
            "decision": decision,
            "reviewer": _redact(reviewer, 120),
            "evidence": _redact(evidence, MAX_TEXT),
            "reviewed_at": _now(),
        }
        self._append(updated)
        return updated

    def mark_used(self, technique_ids: Iterable[str], journey: str = "") -> int:
        """Record approved technique reuse without changing its approval state."""
        records = self._read_latest()
        changed = 0
        for technique_id in technique_ids:
            record = records.get(str(technique_id))
            if not record or record.get("status") != "approved":
                continue
            updated = dict(record)
            updated["used_count"] = int(record.get("used_count", 0)) + 1
            updated["last_used"] = _now()
            if journey:
                journeys = list(updated.get("used_in", []))
                if journey not in journeys:
                    journeys.append(_redact(journey, 120))
                updated["used_in"] = journeys[-32:]
            self._append(updated)
            changed += 1
        return changed


def _walk_research(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("task_type") == "search":
            yield value
        for child in value.values():
            yield from _walk_research(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_research(child)


def _classify(text: str, checkpoint: str = "") -> str:
    lowered = f"{checkpoint} {text}".lower()
    for name, words in (
        ("bypass", ("bypass", "evasion", "waf", "filter")),
        ("cve", ("cve", "advisory", "vulnerability")),
        ("authorization", ("idor", "authorization", "access control", "tenant")),
        ("injection", ("injection", "sqli", "xss", "ssti", "command")),
        ("chain", ("chain", "escalat", "account takeover", "rce")),
    ):
        if any(word in lowered for word in words):
            return name
    return "research"


def learn_from_journey(target: str, journey: Dict[str, Any], *,
                       journey_type: str, root: Optional[str | Path] = None,
                       max_records: int = 100) -> Dict[str, Any]:
    """Extract bounded candidate knowledge from a completed journey."""
    memory = AdaptiveMemory(target, root=root)
    records: List[Dict[str, Any]] = []
    seen: set[str] = set()

    def add(kind: str, title: str, summary: str = "", *,
            bug_classes: Iterable[str] = (), defenses: Iterable[str] = (),
            refs: Iterable[str] = (), evidence: Iterable[str] = (),
            terms: Iterable[str] = ()) -> None:
        if len(records) >= max_records:
            return
        candidate = memory.ingest(
            kind=kind, title=title, summary=summary,
            bug_classes=bug_classes, defenses=defenses,
            source_refs=refs, evidence_refs=evidence,
            terms=terms, journey=journey_type)
        if candidate["technique_id"] not in seen:
            seen.add(candidate["technique_id"])
            records.append(candidate)

    # Research result titles/queries become quarantined learning candidates.
    for search in _walk_research(journey.get("research", journey)):
        query = _redact(search.get("query", ""))
        checkpoint = _redact(search.get("checkpoint", ""), 80)
        for result in search.get("results", [])[:8]:
            if not isinstance(result, dict):
                continue
            title = _redact(result.get("title", ""))
            if not title:
                continue
            url = result.get("url", "")
            category = _classify(f"{query} {title}", checkpoint)
            add(
                "researched-technique",
                title,
                f"{category} research candidate from query: {query}",
                bug_classes=[category], refs=[url],
                terms=_term_candidates(title) + _term_candidates(query),
            )


    # Explicit journey observations contribute patterns, never raw bodies/tokens.
    for item in journey.get("results", journey.get("candidates", [])):
        if not isinstance(item, dict):
            continue
        notes = _redact(item.get("notes") or item.get("title") or item.get("summary"), MAX_TEXT)
        if not notes:
            continue
        bug_class = _redact(item.get("bug_class") or "", 80)
        status = _redact(item.get("observation_state") or item.get("status") or "", 40)
        if status in {"signal", "validated", "approved"} or item.get("idor_signal"):
            add(
                "observed-pattern",
                f"{bug_class or 'observed'}: {notes[:120]}",
                f"Observed during {journey_type}; validation state: {status or 'signal'}.",
                bug_classes=[bug_class] if bug_class else (),
                evidence=[item.get("observation_id", "")],
            )
        elif any(word in notes.lower() for word in ("blocked", "403", "406", "429")):
            add(
                "blocker-pattern",
                f"Blocker: {notes[:120]}",
                f"A blocker was observed during {journey_type}; bypass research remains required.",
                bug_classes=[bug_class] if bug_class else (),
                defenses=[notes],
            )

    approved = memory.approved()
    return {
        "schema": SCHEMA,
        "target": target,
        "journey_type": journey_type,
        "candidate_count": len(records),
        "candidate_ids": [record["technique_id"] for record in records],
        "approved_reusable_count": len(approved),
        "approved_reusable_ids": [record["technique_id"] for record in approved],
        "store": str(memory.path),
        "status": "candidates_quarantined",
        "network": "not performed",
    }


def load_json_file(path: str) -> Dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("journey file must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf adaptive technique memory")
    parser.add_argument("--target", required=True)
    parser.add_argument("--journey-type", default="manual")
    parser.add_argument("--journey-file", action="append", default=[])
    parser.add_argument("--research-dir", help="read persisted research results.json files")
    parser.add_argument("--root", help="workspace root for the learning store")
    parser.add_argument("--list", action="store_true", help="list stored techniques")
    parser.add_argument("--status", choices=sorted(STATUSES), help="filter --list")
    parser.add_argument("--review-id")
    parser.add_argument("--decision", choices=["approve", "reject"])
    parser.add_argument("--reviewer")
    parser.add_argument("--evidence")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    memory = AdaptiveMemory(args.target, root=args.root)
    try:
        if args.list:
            result: Dict[str, Any] = {
                "schema": SCHEMA,
                "target": args.target,
                "techniques": memory.all(args.status),
                "network": "not performed",
            }
        elif args.review_id:
            if not args.decision or not args.reviewer or not args.evidence:
                raise ValueError("--review-id requires --decision, --reviewer, and --evidence")
            result = memory.review(args.review_id, args.decision,
                                   args.reviewer, args.evidence)
        else:
            journey: Dict[str, Any] = {"research": []}
            for path in args.journey_file:
                journey.setdefault("journeys", []).append(load_json_file(path))
            if args.research_dir:
                research_path = Path(args.research_dir)
                for path in sorted(research_path.rglob("results.json")):
                    try:
                        journey.setdefault("research", []).append(load_json_file(str(path)))
                    except (OSError, ValueError, json.JSONDecodeError):
                        continue
            result = learn_from_journey(
                args.target, journey, journey_type=args.journey_type, root=args.root)
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "target": args.target,
                  "status": "error", "error": str(exc),
                  "network": "not performed"}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if args.list:
            print(f"{len(result['techniques'])} stored technique(s)")
        elif args.review_id:
            print(f"Technique {result['technique_id']}: {result['status']}")
        else:
            print(f"Learned {result['candidate_count']} candidate technique(s); "
                  f"{result['approved_reusable_count']} approved for reuse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

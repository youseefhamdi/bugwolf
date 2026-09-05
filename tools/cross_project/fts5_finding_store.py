#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter fts5_store.py:1-680 (1.5.l)
## Source: BugWolf ledger.py (Phase 0 in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

3-layer FTS5-equivalent finding store.

BugWolf's persistence story uses three layers:

  * in-memory dict (fast access for the orchestrator)
  * JSONL append-only log (durable, replay-friendly)
  * scope-isolated namespace (one store per ``scope_id``)

This module is a pure-stdlib re-implementation.  We do NOT use SQLite
FTS5 (matching BugWolf's existing JSONL-only pattern; the
``fts5``-equivalent term here is "full-text-search over JSONL" via
simple token matching).  For larger stores swap the JSONL backend for
sqlite3 + FTS5; the interface is the same.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fts5-store/v1"

_WORD = re.compile(r"[A-Za-z0-9_]+")


@dataclass(frozen=True)
class Finding:
    """A single finding record stored by :class:`FindingStore`."""

    id: str
    scope_id: str
    bug_class: str
    severity: str
    endpoint: str
    method: str
    evidence: str
    reproducer: str = ""
    confidence: str = "tentative"
    tags: Tuple[str, ...] = field(default_factory=tuple)
    created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "id": self.id,
            "scope_id": self.scope_id,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "reproducer": self.reproducer,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "created_at_ms": self.created_at_ms,
            "extra": dict(self.extra),
        }


class FindingStore:
    """3-layer finding store.

    Layers:
      1. in-memory  : a dict keyed by ``scope_id`` -> ``id`` -> :class:`Finding`
      2. JSONL log  : append-only file at ``path`` (``*.jsonl``)
      3. scope isolation: a finding is keyed by ``(scope_id, id)``; searches
         filter by ``scope_id`` first.

    The store is process-local.  Persistence is opt-in via :meth:`use_disk`.
    """

    SCHEMA = SCHEMA

    def __init__(self, *, path: Optional[Path] = None) -> None:
        self._mem: Dict[str, Dict[str, Finding]] = {}
        self._path: Optional[Path] = Path(path) if path else None
        self._loaded_from_disk = False

    # -- persistence -----------------------------------------------------

    def use_disk(self, path: Path) -> None:
        """Enable JSONL persistence at ``path``.

        Existing records on disk are NOT auto-loaded — call
        :meth:`load_disk` separately.
        """
        self._path = Path(path)
        self._loaded_from_disk = False

    def load_disk(self) -> int:
        """Load all records from the JSONL file into memory.  Returns count.

        The store is set to a LOADING state during this operation so
        :meth:`add` does NOT append back to disk (which would create
        an infinite loop).
        """
        if self._path is None or not self._path.is_file():
            return 0
        count = 0
        self._loading = True
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(obj, Mapping):
                        continue
                    try:
                        self.add(Finding(
                            id=str(obj["id"]),
                            scope_id=str(obj["scope_id"]),
                            bug_class=str(obj.get("bug_class") or ""),
                            severity=str(obj.get("severity") or ""),
                            endpoint=str(obj.get("endpoint") or ""),
                            method=str(obj.get("method") or ""),
                            evidence=str(obj.get("evidence") or ""),
                            reproducer=str(obj.get("reproducer") or ""),
                            confidence=str(obj.get("confidence") or "tentative"),
                            tags=tuple(obj.get("tags") or ()),
                            created_at_ms=int(obj.get("created_at_ms") or 0),
                            extra=dict(obj.get("extra") or {}),
                        ))
                        count += 1
                    except Exception:  # noqa: BLE001
                        continue
        finally:
            self._loading = False
        self._loaded_from_disk = True
        return count

    # -- write API -------------------------------------------------------

    def add(self, finding: Finding) -> None:
        """Add ``finding`` to memory + optionally to disk."""
        bucket = self._mem.setdefault(finding.scope_id, {})
        bucket[finding.id] = finding
        if self._path is not None and not getattr(self, "_loading", False):
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(finding.to_dict()) + "\n")

    # -- read API --------------------------------------------------------

    def get(self, scope_id: str, finding_id: str) -> Optional[Finding]:
        return self._mem.get(scope_id, {}).get(finding_id)

    def iter(self, scope_id: str) -> List[Finding]:
        return list(self._mem.get(scope_id, {}).values())

    def count(self, scope_id: Optional[str] = None) -> int:
        if scope_id is None:
            return sum(len(b) for b in self._mem.values())
        return len(self._mem.get(scope_id, {}))

    def scopes(self) -> List[str]:
        return sorted(self._mem.keys())

    def search(self, query: str, *, scope_id: str,
               limit: int = 100) -> List[Finding]:
        """Return findings in ``scope_id`` that match ``query``.

        The match is a token-level intersection: every whitespace-separated
        token in ``query`` must appear (as a substring) in at least one
        searchable field of the finding.
        """
        tokens = _tokenise(query)
        bucket = self._mem.get(scope_id, {})
        if not tokens:
            return list(bucket.values())[:limit]
        results: List[Finding] = []
        for f in bucket.values():
            blob = _searchable_text(f)
            if all(t in blob for t in tokens):
                results.append(f)
                if len(results) >= limit:
                    break
        return results

    def search_any(self, query: str, *, scope_id: str,
                   limit: int = 100) -> List[Finding]:
        """Token-level UNION search (any token matches)."""
        tokens = _tokenise(query)
        bucket = self._mem.get(scope_id, {})
        if not tokens:
            return list(bucket.values())[:limit]
        results: List[Finding] = []
        for f in bucket.values():
            blob = _searchable_text(f)
            if any(t in blob for t in tokens):
                results.append(f)
                if len(results) >= limit:
                    break
        return results

    # -- bulk -----------------------------------------------------------

    def bulk_add(self, findings: Iterable[Finding]) -> int:
        n = 0
        for f in findings:
            self.add(f); n += 1
        return n

    def fingerprint(self, scope_id: str) -> str:
        """Return a deterministic sha256 over the scope's findings."""
        rows = sorted(self.iter(scope_id), key=lambda f: f.id)
        h = hashlib.sha256()
        for f in rows:
            h.update(f.id.encode("utf-8"))
            h.update(b"|")
            h.update(f.bug_class.encode("utf-8"))
            h.update(b"|")
            h.update(f.severity.encode("utf-8"))
            h.update(b"|")
            h.update(f.endpoint.encode("utf-8"))
        return h.hexdigest()


def _tokenise(query: str) -> List[str]:
    return [t.lower() for t in _WORD.findall(query or "")]


def _searchable_text(f: Finding) -> str:
    parts = [
        f.bug_class, f.severity, f.endpoint, f.method,
        f.evidence, f.reproducer, f.confidence, " ".join(f.tags),
    ]
    parts.extend(f.extra.get("bug_class_alt") or [] if isinstance(
        f.extra, Mapping) else [])
    return " ".join(parts).lower()


__all__ = ["SCHEMA", "Finding", "FindingStore"]
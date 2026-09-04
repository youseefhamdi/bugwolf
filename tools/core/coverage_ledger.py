#!/usr/bin/env python3
"""BugWolf Coverage Ledger — endpoint x canonical-checklist verdicts.

The mission-level answer to "which checklist IDs did we actually close on
this endpoint?" Every verdict cites evidence IDs; `n-a` demands a reason;
`attest` items stay pending until the operator clears them. The report
wave refuses to finish while **closeable** P0/P1 IDs remain open — the
no-silent-skip gate, now per-checklist-item instead of per-endpoint only.

State lives at ``<mission>/coverage.json`` in this shape::

    {
      "schema": "bugwolf.coverage/1.0",
      "entries": {
        "https://api.target.com/v2/orders::GET::A": {
          "ACC-01": {"verdict": "not-vuln", "evidence": ["EVID-0001"]},
          "ACC-02": {"verdict": "confirmed", "evidence": ["EVID-0007"],
                      "reason": ""},
          "ACC-05": {"verdict": "n-a",
                      "reason": "no export feature on surface",
                      "evidence": []}
        }
      }
    }

Verdicts: ``untested | confirmed | suspected | not-vuln | blocked-waf |
n-a``. Untested + no reason = a coverage hole, and holes gate reporting.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.core import checklists

SCHEMA = "bugwolf.coverage/1.0"

VERDICTS = ("untested", "confirmed", "suspected", "not-vuln",
            "blocked-waf", "n-a")


def evidence_key(evidence: Optional[List[str]]) -> str:
    """Stable string for verdict gate tests (deduped, sorted)."""
    return ",".join(sorted({str(e) for e in (evidence or [])}))


class CoverageError(ValueError):
    """Raised on invalid verdict writes."""


class CoverageLedger:
    """Endpoint x checklist verdict ledger with integrity + gate helpers."""

    def __init__(self, mission_dir: Path) -> None:
        self._dir = Path(mission_dir)
        self.path = self._dir / "coverage.json"
        self._data: Dict[str, Any] = {"schema": SCHEMA, "entries": {}}
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("schema") != SCHEMA:
                raise CoverageError(
                    f"coverage schema mismatch: {raw.get('schema')!r}")
            self._data = raw

    def save(self) -> None:
        """Atomic write (tmp+fsync+rename), consistent with team state."""
        self._dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._data, indent=2, sort_keys=True)
        fd = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(self._dir), delete=False)
        try:
            fd.write(payload)
            fd.flush()
            import os
            os.fsync(fd.fileno())
        finally:
            fd.close()
        Path(fd.name).replace(self.path)

    # -- keys and entries ----------------------------------------------------

    @staticmethod
    def key(endpoint: str, method: str, auth: str) -> str:
        return f"{endpoint}::{str(method or 'GET').upper()}::{auth or 'anon'}"

    def _entry(self, key: str) -> Dict[str, Any]:
        return self._data["entries"].setdefault(key, {})

    # -- verdict writes --------------------------------------------------------

    def set_verdict(self, endpoint: str, method: str, auth: str,
                    item_id: str, verdict: str,
                    evidence: Optional[List[str]] = None,
                    reason: str = "") -> Dict[str, Any]:
        """Write one verdict. Enforces evidence/reason invariants."""
        item = checklists.get(item_id)  # raises ChecklistError if unknown
        if verdict not in VERDICTS:
            raise CoverageError(f"invalid verdict {verdict!r}")
        if verdict in ("confirmed", "suspected", "not-vuln") and not evidence:
            raise CoverageError(f"{item_id}: verdict {verdict!r} requires "
                                "at least one evidence id")
        if verdict == "n-a" and not str(reason or "").strip():
            raise CoverageError(f"{item_id}: n-a requires a reason "
                                "(no silent skips)")
        attest = not item.canary_safe
        if attest and verdict in ("confirmed", "suspected"):
            raise CoverageError(
                f"{item_id}: attest-gated item — write 'n-a' with an "
                "operator-clearance reason or leave untested")
        rec = {"verdict": verdict, "evidence": list(evidence or []),
               "reason": str(reason or "")}
        self._entry(self.key(endpoint, method, auth))[item_id] = rec
        return dict(rec)

    def get_verdict(self, endpoint: str, method: str, auth: str,
                    item_id: str) -> Dict[str, Any]:
        return dict(self._entry(self.key(endpoint, method, auth))
                    .get(item_id) or
                    {"verdict": "untested", "evidence": [], "reason": ""})

    # -- gate helpers ----------------------------------------------------------

    def holes(self, required_ids: List[str], endpoint: str,
              method: str, auth: str) -> List[str]:
        """IDs that are neither closed nor explained for this endpoint.

        An ID is a hole if: verdict is untested (and the item is closeable,
        i.e. not attest-gated), or the record is internally inconsistent
        (verdicts needing evidence without any).
        """
        holes: List[str] = []
        for item_id in required_ids:
            try:
                item = checklists.get(item_id)
            except checklists.ChecklistError:
                continue
            rec = self.get_verdict(endpoint, method, auth, item_id)
            verdict = rec.get("verdict", "untested")
            if verdict == "untested" and item.canary_safe:
                holes.append(item_id)
            elif verdict in ("confirmed", "suspected", "not-vuln") \
                    and not rec.get("evidence"):
                holes.append(item_id)  # inconsistent record
        return holes

    def summary(self, bug_classes: List[str],
                keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fleet-level coverage: per-ID verdict counts across endpoints."""
        ids = checklists.slice_for_bug_classes(bug_classes or [])
        keys = keys if keys is not None else list(self._data["entries"])
        counts: Dict[str, Dict[str, int]] = {
            i: {v: 0 for v in VERDICTS} for i in ids}
        for key in keys:
            entry = self._data["entries"].get(key, {})
            for item_id in ids:
                rec = entry.get(item_id)
                verdict = rec.get("verdict") if rec else None
                if verdict in counts[item_id]:
                    counts[item_id][verdict] += 1
                else:
                    counts[item_id]["untested"] += 1  # never recorded
        return {
            "schema": SCHEMA,
            "bug_classes": list(bug_classes or []),
            "endpoints": len(keys),
            "items": {i: dict(c) for i, c in counts.items()},
            "open_closeable": sum(
                c["untested"] for c in counts.values()),
        }

    # -- integrity --------------------------------------------------------------

    def digest(self) -> str:
        payload = json.dumps(self._data, sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    def attest_pending(self, required_ids: List[str]) -> List[str]:
        """Attest-gated IDs that were never cleared by the operator."""
        return [i for i in required_ids if i in checklists.attest_ids()]

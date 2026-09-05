"""Append-only JSONL tracer (Phase 1.4 — Governance Core).

Every plan-step emission is recorded as one line in
``state/governance/traces/<mission_id>.jsonl``.  Each line carries::

    {
      "ts":            ISO-8601 UTC,
      "plan_hash":     <sha256 over the plan body>,
      "entry_sha256":  <sha256 over the canonical line>,
      "prev_sha256":   <sha256 of the previous line, "" for genesis>,
      "event":         short event name,
      "actor":         emitting component,
      "detail_sha256": <sha256 over the detail payload>,
    }

The chain link (``prev_sha256`` -> ``entry_sha256``) is verified by
:meth:`Tracer.verify_chain`.  The tracer is fail-closed: the file is
opened in append mode and ``fsync``'d after every line so a process
crash loses at most one line.

No external deps; stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ._canonical import SCHEMA as _SCHEMA, canonical_bytes

SCHEMA = "bugwolf-governance-v1"


class Tracer:
    """Append-only JSONL plan-hash tracer."""

    schema = _SCHEMA

    def __init__(self, mission_id: str, *, root: Optional[Path] = None) -> None:
        if not mission_id:
            raise ValueError("Tracer requires mission_id")
        self._mission_id = str(mission_id)
        self._path = self._trace_path(root)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    @property
    def mission_id(self) -> str:
        return self._mission_id

    @property
    def path(self) -> Path:
        return self._path

    def record(
        self,
        *,
        plan_hash: str,
        event: str,
        actor: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append one entry.  Returns the entry dict that was written."""
        if not plan_hash:
            raise ValueError("plan_hash is required")
        if not event:
            raise ValueError("event is required")
        if not actor:
            raise ValueError("actor is required")
        with self._lock:
            prev_sha256 = self._tip_sha256_locked()
            detail = dict(detail or {})
            entry = {
                "ts": _utc_iso(),
                "plan_hash": str(plan_hash),
                "event": str(event),
                "actor": str(actor),
                "detail_sha256": _sha256(canonical_bytes(detail)),
                "prev_sha256": prev_sha256,
            }
            # entry_sha256 covers EVERYTHING including itself? No — it's
            # the SHA-256 over the canonical form with entry_sha256
            # stripped, so the field can be re-derived on verification.
            entry["entry_sha256"] = _sha256(canonical_bytes(entry))
            self._append_locked(entry)
            return entry

    def entries(self) -> List[Dict[str, Any]]:
        """Read all entries (oldest first)."""
        if not self._path.is_file():
            return []
        out: List[Dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                out.append(payload)
        return out

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the hash chain in this tracer's file.

        Returns a dict with::

            {
              "is_valid": bool,
              "verified": int,
              "errors":   List[str],
              "schema":   str,
            }
        """
        result = {
            "is_valid": True,
            "verified": 0,
            "errors": [],
            "schema": self.schema,
        }
        prev_sha = ""
        for index, entry in enumerate(self.entries()):
            declared_prev = entry.get("prev_sha256", "")
            if declared_prev != prev_sha:
                result["is_valid"] = False
                result["errors"].append(
                    f"entry {index}: prev_sha256 mismatch "
                    f"(expected {prev_sha!r}, got {declared_prev!r})")
            declared_hash = entry.get("entry_sha256", "")
            unsigned = {k: v for k, v in entry.items() if k != "entry_sha256"}
            expected_hash = _sha256(canonical_bytes(unsigned))
            if declared_hash != expected_hash:
                result["is_valid"] = False
                result["errors"].append(
                    f"entry {index}: entry_sha256 mismatch "
                    f"(expected {expected_hash}, got {declared_hash})")
            prev_sha = str(declared_hash or "")
            result["verified"] += 1
        return result

    # -- internals ----------------------------------------------------------

    def _trace_path(self, root: Optional[Path]) -> Path:
        base = Path(root) if root else Path(
            os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
        return base / "state" / "governance" / "traces" / (
            f"{self._mission_id}.jsonl")

    def _tip_sha256_locked(self) -> str:
        """Return the entry_sha256 of the last line, or "" if file empty."""
        if not self._path.is_file():
            return ""
        try:
            with self._path.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    if size == 0:
                        return ""
                    # Walk back over one line (cheap for tracer files).
                    offset = size - 1
                    chunk = 4096
                    buf = b""
                    while offset > 0 and b"\n" not in buf:
                        read_size = min(chunk, offset)
                        offset -= read_size
                        stream.seek(offset)
                        buf = stream.read(read_size) + buf
                    lines = buf.splitlines()
                    if not lines:
                        return ""
                    last = lines[-1]
                    if not last:
                        return ""
                    payload = json.loads(last)
                    if isinstance(payload, dict):
                        return str(payload.get("entry_sha256") or "")
        except (OSError, json.JSONDecodeError):
            return ""
        return ""

    def _append_locked(self, entry: Dict[str, Any]) -> None:
        line = json.dumps(entry, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["SCHEMA", "Tracer"]
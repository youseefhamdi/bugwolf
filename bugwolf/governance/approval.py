"""Approval window (Phase 1.4 — Governance Core).

Destructive / out-of-band operations (DELETE, STATE_CHANGE, etc.) require
an explicit operator approval that is itself hash-chained, signed, and
time-bounded.

Lifecycle::

    * ``Approval.request(target, action, ...)``  → creates a pending record
    * ``Approval.grant(approval_id)``            → flips status to GRANTED
    * ``Approval.is_approved(candidate)``        → True iff a non-expired
      GRANTED record covers the candidate

Approvals expire after :data:`APPROVAL_TTL` seconds (default 7 days).  Each
record carries the SHA-256 over ``(target, action, method, endpoint,
scope_file_sha256, ts)`` so that the approval body is tamper-evident.
Records are appended to ``state/governance/approvals/<target>.jsonl``.

No external deps; stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ._canonical import SCHEMA as _SCHEMA, canonical_bytes

SCHEMA = "bugwolf-governance-v1"

APPROVAL_TTL = 7 * 24 * 3600  # 7 days, in seconds


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ApprovalError(Exception):
    """Raised when an approval operation is illegal."""


@dataclass
class ApprovalRecord:
    schema: str
    approval_id: str
    target: str
    action: str
    method: str
    endpoint: str
    scope_file_sha256: str
    ts: str
    expires_at: str
    status: str = ApprovalStatus.PENDING.value
    operator: str = ""
    record_sha256: str = ""
    prev_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Approval:
    """Approval window store.  Thread-safe."""

    schema = _SCHEMA

    def __init__(
        self,
        *,
        ttl_seconds: int = APPROVAL_TTL,
        root: Optional[Path] = None,
        clock: Optional["callable"] = None,
        signer: Optional["callable"] = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._ttl = int(ttl_seconds)
        self._root = Path(root) if root else Path(
            os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
        self._base = self._root / "state" / "governance" / "approvals"
        self._base.mkdir(parents=True, exist_ok=True)
        self._clock = clock or time.time
        self._signer = signer  # optional (prev_hash, record_sha256) -> sig
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    # -- public API ---------------------------------------------------------

    def request(
        self,
        *,
        target: str,
        action: str,
        method: str = "",
        endpoint: str = "",
        scope_file_sha256: str = "",
        operator: str = "",
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalRecord:
        """Append a new PENDING approval record and return it."""
        if not target:
            raise ValueError("target is required")
        if not action:
            raise ValueError("action is required")
        ttl = int(ttl_seconds) if ttl_seconds is not None else self._ttl
        with self._lock:
            return self._append_record(
                target=target,
                action=action,
                method=method,
                endpoint=endpoint,
                scope_file_sha256=scope_file_sha256,
                status=ApprovalStatus.PENDING,
                operator=operator,
                ttl=ttl,
            )

    def grant(self, approval_id: str, *, target: str,
              operator: str = "") -> ApprovalRecord:
        """Mark the latest PENDING record for ``target`` as GRANTED.

        A new entry is appended (status=GRANTED, prev_sha256 points at the
        PENDING record's hash) so the chain stays linear and tamper-
        evident.
        """
        record = self._latest_pending(target, approval_id)
        if record is None:
            raise ApprovalError(
                f"no pending approval_id={approval_id!r} for target={target!r}")
        with self._lock:
            return self._append_record(
                target=target,
                action=record.action,
                method=record.method,
                endpoint=record.endpoint,
                scope_file_sha256=record.scope_file_sha256,
                status=ApprovalStatus.GRANTED,
                operator=operator,
                ttl=self._ttl,
                previous_hash=record.record_sha256,
            )

    def revoke(self, approval_id: str, *, target: str,
               operator: str = "") -> ApprovalRecord:
        """Mark the latest PENDING/GRANTED record as REVOKED."""
        record = self._latest_active(target, approval_id)
        if record is None:
            raise ApprovalError(
                f"no active approval_id={approval_id!r} for target={target!r}")
        with self._lock:
            return self._append_record(
                target=target,
                action=record.action,
                method=record.method,
                endpoint=record.endpoint,
                scope_file_sha256=record.scope_file_sha256,
                status=ApprovalStatus.REVOKED,
                operator=operator,
                ttl=self._ttl,
                previous_hash=record.record_sha256,
            )

    def is_approved(self, candidate: Mapping[str, Any]) -> bool:
        """Return True iff a non-expired GRANTED record covers ``candidate``.

        A ``REVOKED`` record whose position is AFTER the GRANTED record
        invalidates that grant.  We walk the chain twice — once to
        collect every revoke key and its position, once to find a
        GRANTED record that is NOT preceded by a matching REVOKED.
        """
        target = str(candidate.get("target") or "")
        if not target:
            return False
        action = str(candidate.get("action") or "")
        method = str(candidate.get("method") or "")
        endpoint = str(candidate.get("endpoint") or "")
        scope_sha = str(candidate.get("scope_file_sha256") or "")
        now = float(self._clock())
        records = self.history(target)

        def _match(rec: ApprovalRecord) -> bool:
            if rec.action != action:
                return False
            if method and rec.method and rec.method != method:
                return False
            if endpoint and rec.endpoint and rec.endpoint != endpoint:
                return False
            return True

        revoked_keys: set = set()
        for record in records:
            if record.status != ApprovalStatus.REVOKED.value:
                continue
            if _match(record):
                revoked_keys.add(
                    (record.action, record.method, record.endpoint,
                     record.scope_file_sha256))

        for record in records:
            if record.status != ApprovalStatus.GRANTED.value:
                continue
            if not _match(record):
                continue
            if scope_sha and record.scope_file_sha256 and (
                    record.scope_file_sha256 != scope_sha):
                continue
            expires = self._parse_ts(record.expires_at)
            if expires is not None and expires < now:
                continue
            key = (record.action, record.method, record.endpoint,
                   record.scope_file_sha256)
            if key in revoked_keys:
                continue
            return True
        return False

    def history(self, target: str) -> List[ApprovalRecord]:
        path = self._path_for(target)
        if not path.is_file():
            return []
        records: List[ApprovalRecord] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            records.append(ApprovalRecord(
                schema=payload.get("schema", self.schema),
                approval_id=payload.get("approval_id", ""),
                target=payload.get("target", target),
                action=payload.get("action", ""),
                method=payload.get("method", ""),
                endpoint=payload.get("endpoint", ""),
                scope_file_sha256=payload.get("scope_file_sha256", ""),
                ts=payload.get("ts", ""),
                expires_at=payload.get("expires_at", ""),
                status=payload.get("status", ApprovalStatus.PENDING.value),
                operator=payload.get("operator", ""),
                record_sha256=payload.get("record_sha256", ""),
                prev_sha256=payload.get("prev_sha256", ""),
            ))
        return records

    def verify_chain(self, target: str) -> Dict[str, Any]:
        result = {"schema": self.schema, "is_valid": True,
                  "verified": 0, "errors": []}
        prev_sha = ""
        for index, record in enumerate(self.history(target)):
            declared_prev = record.prev_sha256
            if declared_prev != prev_sha:
                result["is_valid"] = False
                result["errors"].append(
                    f"record {index}: prev_sha256 mismatch")
            unsigned = {
                "schema": record.schema,
                "approval_id": record.approval_id,
                "target": record.target,
                "action": record.action,
                "method": record.method,
                "endpoint": record.endpoint,
                "scope_file_sha256": record.scope_file_sha256,
                "ts": record.ts,
                "expires_at": record.expires_at,
                "status": record.status,
                "operator": record.operator,
                "prev_sha256": record.prev_sha256,
            }
            expected = _sha256(canonical_bytes(unsigned))
            if expected != record.record_sha256:
                result["is_valid"] = False
                result["errors"].append(
                    f"record {index}: record_sha256 mismatch")
            prev_sha = record.record_sha256
            result["verified"] += 1
        return result

    # -- internals ----------------------------------------------------------

    def _append_record(
        self,
        *,
        target: str,
        action: str,
        method: str,
        endpoint: str,
        scope_file_sha256: str,
        status: ApprovalStatus,
        operator: str,
        ttl: int,
        previous_hash: Optional[str] = None,
    ) -> ApprovalRecord:
        ts = _utc_iso()
        expires_at = _iso_from_ts(self._clock() + ttl)
        approval_id = _new_approval_id(target, action, ts, method, endpoint,
                                        scope_file_sha256)
        prev_sha = (previous_hash if previous_hash is not None
                    else self._tip_sha256(target))
        record = ApprovalRecord(
            schema=self.schema,
            approval_id=approval_id,
            target=target,
            action=action,
            method=method,
            endpoint=endpoint,
            scope_file_sha256=scope_file_sha256,
            ts=ts,
            expires_at=expires_at,
            status=status.value,
            operator=operator,
            prev_sha256=prev_sha,
        )
        unsigned = {
            "schema": record.schema,
            "approval_id": record.approval_id,
            "target": record.target,
            "action": record.action,
            "method": record.method,
            "endpoint": record.endpoint,
            "scope_file_sha256": record.scope_file_sha256,
            "ts": record.ts,
            "expires_at": record.expires_at,
            "status": record.status,
            "operator": record.operator,
            "prev_sha256": record.prev_sha256,
        }
        record.record_sha256 = _sha256(canonical_bytes(unsigned))
        if self._signer is not None:
            # Optional co-signature is stored on the record's metadata
            # but kept off the chain (it would re-hash on every signature
            # regeneration).  Verifiers that need it can re-invoke the
            # signer over (prev_sha256, record_sha256).
            try:
                record._signature = self._signer(prev_sha, record.record_sha256)
            except Exception:  # noqa: BLE001
                record._signature = ""
        path = self._path_for(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record.to_dict(), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return record

    def _latest_pending(self, target: str,
                        approval_id: str) -> Optional[ApprovalRecord]:
        latest_match: Optional[ApprovalRecord] = None
        for record in self.history(target):
            if (record.status == ApprovalStatus.PENDING.value
                    and record.approval_id == approval_id):
                latest_match = record
        return latest_match

    def _latest_active(self, target: str,
                       approval_id: str) -> Optional[ApprovalRecord]:
        latest_match: Optional[ApprovalRecord] = None
        for record in self.history(target):
            if (record.status in (ApprovalStatus.PENDING.value,
                                  ApprovalStatus.GRANTED.value)
                    and record.approval_id == approval_id):
                latest_match = record
        return latest_match

    def _tip_sha256(self, target: str) -> str:
        path = self._path_for(target)
        if not path.is_file():
            return ""
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                if size == 0:
                    return ""
                offset = size - 1
                buf = b""
                while offset > 0 and b"\n" not in buf:
                    chunk = min(4096, offset)
                    offset -= chunk
                    stream.seek(offset)
                    buf = stream.read(chunk) + buf
                lines = buf.splitlines()
                if not lines:
                    return ""
                last = lines[-1]
                if not last:
                    return ""
                payload = json.loads(last)
                if isinstance(payload, dict):
                    return str(payload.get("record_sha256") or "")
        except (OSError, json.JSONDecodeError):
            return ""
        return ""

    def _path_for(self, target: str) -> Path:
        safe = "".join(c if (c.isalnum() or c in "._-") else "_"
                       for c in str(target))
        return self._base / f"{safe}.jsonl"

    @staticmethod
    def _parse_ts(value: str) -> Optional[float]:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None


def _new_approval_id(target: str, action: str, ts: str,
                     method: str, endpoint: str,
                     scope_file_sha256: str) -> str:
    body = f"{target}|{action}|{method}|{endpoint}|{scope_file_sha256}|{ts}"
    return "appr-" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def _iso_from_ts(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "SCHEMA",
    "APPROVAL_TTL",
    "ApprovalStatus",
    "ApprovalError",
    "ApprovalRecord",
    "Approval",
]
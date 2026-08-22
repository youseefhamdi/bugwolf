#!/usr/bin/env python3
"""Redacted evidence and deterministic replay artifacts.

Raw credentials are never persisted by this module. Callers should provide
responses/traces as structured data; sensitive fields are recursively masked
before they are written to the repository state directory.

Redaction is best-effort: it masks known credential shapes and key names, but
it is a risk-reduction heuristic, not a confidentiality boundary. Treat any
payload this module processes as potentially sensitive until a human has
reviewed the exact values that survive.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    from tools.safety import safe_target_name
except ImportError:
    from safety import safe_target_name

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

ROOT = workspace_root()
RESEARCH_ROOT = ROOT / "state" / "research"

_SECRET_KEY_RE = re.compile(
    r"(authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|"
    r"secret|token|password|passwd|private[-_]?key|client[-_]?secret|"
    r"session(?:[-_]?id)?|\bsid\b|jwt)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(bearer\s+)[A-Za-z0-9._~+/-]+|"
    r"(ghp_|github_pat_|sk_live_|AKIA)[A-Za-z0-9_./+-]+|"
    r"([?&](?:token|access_token|refresh_token|api[-_]?key|secret|password|"
    r"session(?:[-_]?id)?|sid|jwt)=)[^&\s]+|"
    r"(\b(?:token|secret|password|api[-_]?key)\s*[=:]\s*)[^\s,;]+|"
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
    re.IGNORECASE,
)


def redact_text(value: str) -> str:
    """Mask common credential formats while preserving useful structure."""
    value = _SECRET_VALUE_RE.sub(lambda match: "[REDACTED]", str(value))
    return value


def redact(value: Any, *, key: str = "") -> Any:
    """Recursively redact sensitive mapping keys and string values."""
    if isinstance(value, dict):
        return {
            str(k): ("[REDACTED]" if _SECRET_KEY_RE.search(str(k))
                    else redact(v, key=str(k)))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, key=key) for item in value]
    if isinstance(value, str):
        if _SECRET_KEY_RE.search(key):
            return "[REDACTED]"
        return redact_text(value)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


@dataclass
class EvidenceRecord:
    evidence_id: str
    kind: str
    sha256: str
    path: str
    previous_hash: str
    created_at: str
    metadata: Dict[str, Any]
    record_hash: str = ""


class EvidenceStore:
    """Append-only, redacted evidence store for one authorized target."""

    def __init__(self, target: str):
        self.target = target
        safe = safe_target_name(target).replace(":", "_")
        self.root = RESEARCH_ROOT / safe / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest = self.root / "manifest.jsonl"

    def _tip(self) -> str:
        if not self.manifest.exists():
            return ""
        lines = [line for line in self.manifest.read_text().splitlines() if line.strip()]
        if not lines:
            return ""
        try:
            record = json.loads(lines[-1])
            return record.get("record_hash") or record.get("sha256", "")
        except json.JSONDecodeError:
            return ""

    @staticmethod
    def _record_hash(record: Dict[str, Any]) -> str:
        unsigned = dict(record)
        unsigned.pop("record_hash", None)
        return hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()

    def add(self, kind: str, payload: Any,
            metadata: Optional[Dict[str, Any]] = None) -> EvidenceRecord:
        """Redact, persist, and hash one evidence object."""
        safe_payload = redact(payload)
        body = canonical_json(safe_payload).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        evidence_id = digest[:16]
        path = self.root / f"{evidence_id}.json"
        if not path.exists():
            path.write_bytes(body)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            kind=kind,
            sha256=digest,
            path=str(path.relative_to(ROOT)),
            previous_hash=self._tip(),
            created_at=datetime.now(timezone.utc).isoformat(),
            metadata=redact(metadata or {}),
        )
        record_dict = record.__dict__.copy()
        record.record_hash = self._record_hash(record_dict)
        line = json.dumps(record.__dict__, sort_keys=True)
        with open(self.manifest, "a") as stream:
            if fcntl:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            if fcntl:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return record

    def add_replay_fixture(self, request: Dict[str, Any], response: Dict[str, Any],
                           *, action: str = "read",
                           metadata: Optional[Dict[str, Any]] = None) -> EvidenceRecord:
        """Store a replayable candidate/control fixture without credentials."""
        return self.add(
            "replay_fixture",
            {
                "schema": "bugwolf-replay-v1",
                "action": action,
                "request": request,
                "response": response,
            },
            metadata=metadata,
        )

    def verify(self) -> Dict[str, Any]:
        """Verify evidence hashes and manifest linkage."""
        result = {"valid": True, "entries": 0, "errors": []}
        if not self.manifest.exists():
            return result
        previous = ""
        for line_number, line in enumerate(self.manifest.read_text().splitlines(), 1):
            if not line.strip():
                continue
            result["entries"] += 1
            try:
                record = json.loads(line)
                body_path = (ROOT / record["path"]).resolve()
                try:
                    body_path.relative_to(self.root)
                except ValueError as exc:
                    raise ValueError("evidence path escapes target store") from exc
                actual = hashlib.sha256(body_path.read_bytes()).hexdigest()
                if actual != record["sha256"]:
                    result["valid"] = False
                    result["errors"].append(f"entry {line_number}: evidence hash mismatch")
                if record.get("previous_hash", "") != previous:
                    result["valid"] = False
                    result["errors"].append(f"entry {line_number}: manifest chain mismatch")
                stored_record_hash = record.get("record_hash", "")
                if stored_record_hash and stored_record_hash != self._record_hash(record):
                    result["valid"] = False
                    result["errors"].append(f"entry {line_number}: manifest entry hash mismatch")
                previous = stored_record_hash or record["sha256"]
            except (OSError, KeyError, json.JSONDecodeError) as exc:
                result["valid"] = False
                result["errors"].append(f"entry {line_number}: {exc}")
        return result

"""Entry types and canonical JSON helpers."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-types-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import Any, Dict, Optional

SCHEMA = "bugwolf-unifiedstate-types-v1"

_LOG = logging.getLogger("bugwolf.unified_state.types")


class EntryKind(Enum):
    """Kinds of journal entries recorded by bugwolf."""

    INIT = "init"
    SCOPE = "scope"
    SCAN = "scan"
    FUZZ = "fuzz"
    TAINT = "taint"
    SEMANTIC = "semantic"
    REGRESSION = "regression"
    CHAIN = "chain"
    FINDING = "finding"
    GATE = "gate"
    SUBMISSION = "submission"
    COMPLETE = "complete"
    MIGRATION = "migration"
    AUDIT = "audit"


@dataclass
class Entry:
    """A single journal entry.

    Fields:
        id: unique identifier (UUID4 hex).
        seq: monotonically increasing per-journal sequence number.
        timestamp: POSIX timestamp (float seconds).
        kind: the entry kind.
        mission_id: the engagement or mission identifier this entry belongs to.
        actor: principal that produced the entry (user, agent, component).
        payload: arbitrary structured data; must be JSON-serializable.
        prev_hash: hex digest of the previous entry (64 chars). Genesis uses
            the all-zero hash.
        hash: hex digest of (prev_hash || canonical_json(entry-without-hash)).
        signature: optional hex signature (out-of-band) — never required.
    """

    id: str
    seq: int
    timestamp: float
    kind: EntryKind
    mission_id: str
    actor: str
    payload: dict
    prev_hash: str
    hash: str
    signature: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.id:
            self.id = uuid.uuid4().hex
        if isinstance(self.kind, str):
            try:
                self.kind = EntryKind(self.kind)
            except ValueError:
                _LOG.warning("unknown entry kind string: %r; coercing to AUDIT", self.kind)
                self.kind = EntryKind.AUDIT


def canonical_json(d: Dict[str, Any]) -> str:
    """Return the canonical JSON serialization of a dict.

    Uses sorted keys, no whitespace, and ``ensure_ascii=False`` so the
    representation is identical across runs, platforms, and locales.
    """

    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def to_dict(e: Entry) -> dict:
    """Convert an Entry to a JSON-serializable dict."""

    d = asdict(e)
    d["kind"] = e.kind.value if isinstance(e.kind, EntryKind) else str(e.kind)
    return d


def from_dict(d: Dict[str, Any]) -> Entry:
    """Best-effort reconstruction of an Entry from a dict.

    STUB-SAFE: missing required fields are filled with sensible defaults
    rather than raising. Unknown EntryKind strings become ``AUDIT``.
    """

    if not isinstance(d, dict):
        d = {}

    kind_raw = d.get("kind", EntryKind.AUDIT.value)
    try:
        kind = kind_raw if isinstance(kind_raw, EntryKind) else EntryKind(kind_raw)
    except (ValueError, TypeError):
        _LOG.warning("unknown kind %r, coercing to AUDIT", kind_raw)
        kind = EntryKind.AUDIT

    valid_fields = {f_.name for f_ in fields(Entry)}
    payload_raw = d.get("payload", {})
    payload = payload_raw if isinstance(payload_raw, dict) else {"value": payload_raw}

    return Entry(
        id=str(d.get("id") or uuid.uuid4().hex),
        seq=int(d.get("seq", 0) or 0),
        timestamp=float(d.get("timestamp", 0.0) or 0.0),
        kind=kind,
        mission_id=str(d.get("mission_id", "default")),
        actor=str(d.get("actor", "bugwolf")),
        payload=payload,
        prev_hash=str(d.get("prev_hash", "0" * 64)),
        hash=str(d.get("hash", "0" * 64)),
        signature=(d.get("signature") if "signature" in d else None),
    )


def make_blank_entry_dict() -> Dict[str, Any]:
    """Return a minimal entry dict useful for tests and shims."""

    return {
        "id": "",
        "seq": 0,
        "timestamp": 0.0,
        "kind": EntryKind.INIT.value,
        "mission_id": "",
        "actor": "",
        "payload": {},
        "prev_hash": "0" * 64,
        "hash": "0" * 64,
        "signature": None,
    }
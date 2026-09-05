"""Hash chain primitives and integrity verification."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-chain-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

from bugwolf.unified_state.types import (
    Entry,
    EntryKind,
    canonical_json,
    from_dict,
    to_dict,
)

SCHEMA = "bugwolf-unifiedstate-chain-v1"

_LOG = logging.getLogger("bugwolf.unified_state.chain")

GENESIS_HASH = "0" * 64


def compute_hash(prev_hash: str, entry_canonical: str) -> str:
    """Compute the SHA-256 hash of ``prev_hash || entry_canonical``."""

    if not isinstance(prev_hash, str):
        prev_hash = str(prev_hash or "")
    if not isinstance(entry_canonical, str):
        entry_canonical = str(entry_canonical or "")
    return hashlib.sha256((prev_hash + entry_canonical).encode("utf-8")).hexdigest()


def _entry_signing_dict(e: Entry) -> dict:
    """Return the dict that was actually signed (everything except ``hash`` and
    ``signature``). Used both for hashing and for verification."""

    d = to_dict(e)
    d.pop("hash", None)
    d.pop("signature", None)
    return d


def entry_hash(e: Entry) -> str:
    """Compute the hash of an Entry given its ``prev_hash`` field."""

    return compute_hash(e.prev_hash, canonical_json(_entry_signing_dict(e)))


def verify_chain(entries: List[Any]) -> Dict[str, Any]:
    """Verify a list of Entry-like objects or dicts.

    Walks the list in order and recomputes each hash. The first entry must
    have ``prev_hash == GENESIS_HASH`` unless the list is empty.

    STUB-SAFE: never raises. Malformed entries produce an error record in
    the returned dict instead of crashing the verification.
    """

    result: Dict[str, Any] = {
        "ok": True,
        "broken_at": None,
        "total": 0,
        "errors": [],
    }

    if not entries:
        return result

    prev_hash = GENESIS_HASH

    for idx, raw in enumerate(entries):
        seq: Optional[int] = None
        try:
            if isinstance(raw, Entry):
                e = raw
            elif isinstance(raw, dict):
                e = from_dict(raw)
            else:
                raise TypeError(f"unsupported entry type: {type(raw).__name__}")

            seq = e.seq

            if idx == 0 and e.prev_hash != GENESIS_HASH:
                result["ok"] = False
                if result["broken_at"] is None:
                    result["broken_at"] = 0
                result["errors"].append({
                    "seq": seq,
                    "expected": GENESIS_HASH,
                    "actual": e.prev_hash,
                    "reason": "genesis_prev_hash_mismatch",
                })
                # Continue — we still try to verify subsequent entries against
                # this one's hash (which is itself bogus).

            expected = entry_hash(e)
            if expected != e.hash:
                result["ok"] = False
                if result["broken_at"] is None:
                    result["broken_at"] = idx
                result["errors"].append({
                    "seq": seq,
                    "expected": expected,
                    "actual": e.hash,
                    "reason": "hash_mismatch",
                })

            if idx > 0:
                if prev_hash != e.prev_hash:
                    result["ok"] = False
                    if result["broken_at"] is None:
                        result["broken_at"] = idx
                    result["errors"].append({
                        "seq": seq,
                        "expected": prev_hash,
                        "actual": e.prev_hash,
                        "reason": "prev_hash_mismatch",
                    })

            prev_hash = e.hash
        except Exception as exc:  # STUB-SAFE
            result["ok"] = False
            if result["broken_at"] is None:
                result["broken_at"] = idx
            result["errors"].append({
                "seq": seq if seq is not None else -1,
                "expected": "",
                "actual": "",
                "reason": f"malformed_entry: {type(exc).__name__}: {exc}",
            })

    result["total"] = len(entries)
    return result


def seal_entry(prev_hash: str, e: Entry) -> Entry:
    """Mutate ``e`` to set ``prev_hash`` (if zero) and compute ``hash``."""

    if not e.prev_hash or e.prev_hash == "0" * 64:
        e.prev_hash = prev_hash if prev_hash else GENESIS_HASH
    e.hash = entry_hash(e)
    return e
"""Conflict-free merge for journals produced by concurrent workers."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-merge-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from bugwolf.unified_state.types import Entry, from_dict, to_dict

SCHEMA = "bugwolf-unifiedstate-merge-v1"

_LOG = logging.getLogger("bugwolf.unified_state.merge")


def _key(e: Entry) -> tuple:
    return (e.seq, e.hash)


def _read_jsonl(path: str) -> List[Entry]:
    out: List[Entry] = []
    p = Path(path)
    if not p.exists() or not p.is_file():
        return out
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    _LOG.warning("merge: skipping corrupt line in %s", path)
                    continue
                try:
                    out.append(from_dict(d))
                except Exception as exc:  # STUB-SAFE
                    _LOG.warning("merge: skipping bad entry: %s", exc)
                    continue
    except OSError as exc:
        _LOG.warning("merge: cannot read %s: %s", path, exc)
    return out


def merge_journals(
    ours: List[Entry],
    theirs: List[Entry],
) -> Dict[str, Any]:
    """Combine two journal lists deterministically.

    Strategy: dedup by ``(seq, hash)``. If both sides have the same ``seq``
    but different hashes, record a conflict (keep ours, flag theirs).

    Returns ``{merged: list, conflicts: list}``. The merged list is sorted
    by ``seq`` ascending.
    """

    ours_map: Dict[tuple, Entry] = {_key(e): e for e in ours}
    theirs_map: Dict[tuple, Entry] = {_key(e): e for e in theirs}

    by_seq: Dict[int, List[Entry]] = {}
    for e in ours:
        by_seq.setdefault(e.seq, []).append(e)
    for e in theirs:
        by_seq.setdefault(e.seq, []).append(e)

    merged: List[Entry] = []
    conflicts: List[Dict[str, Any]] = []

    for seq in sorted(by_seq.keys()):
        bucket = by_seq[seq]
        seen_keys: Dict[tuple, int] = {}
        for e in bucket:
            k = _key(e)
            if k not in seen_keys:
                seen_keys[k] = 0
            seen_keys[k] += 1

        unique_entries = list({_key(e): e for e in bucket}.values())
        unique_entries.sort(key=lambda e: e.timestamp)

        if len(unique_entries) == 1:
            merged.append(unique_entries[0])
            continue

        # Multiple distinct (seq, hash) values for the same seq → conflict.
        ours_entries = [e for e in ours if e.seq == seq]
        theirs_entries = [e for e in theirs if e.seq == seq]
        ours_keys = {_key(e) for e in ours_entries}
        theirs_keys = {_key(e) for e in theirs_entries}

        if ours_entries and theirs_entries and ours_keys != theirs_keys:
            keep = ours_entries[0] if ours_entries else unique_entries[0]
            merged.append(keep)
            conflicts.append({
                "seq": seq,
                "kept": to_dict(keep),
                "ours_hashes": sorted(ours_keys, key=lambda k: k[1]),
                "theirs_hashes": sorted(theirs_keys, key=lambda k: k[1]),
                "resolution": "kept_ours",
            })
        else:
            # Same hash appears on both sides, no conflict.
            for e in unique_entries:
                merged.append(e)

    # Final sort + dedup by id (just in case).
    seen_ids = set()
    deduped: List[Entry] = []
    for e in sorted(merged, key=lambda e: e.seq):
        if e.id in seen_ids:
            continue
        seen_ids.add(e.id)
        deduped.append(e)

    return {"merged": deduped, "conflicts": conflicts}


def merge_files(
    ours_path: str,
    theirs_path: str,
    output_path: str,
) -> Dict[str, Any]:
    """Read two journals, merge, and write JSONL to ``output_path``.

    STUB-SAFE: missing files are logged and treated as empty.
    """

    ours = _read_jsonl(ours_path)
    theirs = _read_jsonl(theirs_path)

    if not ours and not theirs:
        _LOG.warning("merge_files: both inputs empty (%s, %s)", ours_path, theirs_path)

    result = merge_journals(ours, theirs)
    merged = result.get("merged", [])

    p = Path(output_path)
    try:
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            for e in merged:
                d = to_dict(e)
                fh.write(json.dumps(d, ensure_ascii=False, separators=(",", ":")))
                fh.write("\n")
    except OSError as exc:
        _LOG.warning("merge_files: cannot write %s: %s", output_path, exc)

    return {
        "merged_count": len(merged),
        "ours_count": len(ours),
        "theirs_count": len(theirs),
        "conflicts": result.get("conflicts", []),
        "output_path": output_path,
    }
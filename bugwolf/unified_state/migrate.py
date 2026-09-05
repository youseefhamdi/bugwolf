"""Migration shim from legacy state formats to the unified journal."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-migrate-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from bugwolf.unified_state.state import State
from bugwolf.unified_state.types import Entry, EntryKind, from_dict

SCHEMA = "bugwolf-unifiedstate-migrate-v1"

_LOG = logging.getLogger("bugwolf.unified_state.migrate")


def detect_legacy_format(path: str) -> Optional[str]:
    """Best-effort detection of an old bugwolf state file format.

    Returns one of ``"tools_state"``, ``"chain_state"``, or ``None``.
    """

    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(4096)
    except OSError as exc:
        _LOG.warning("cannot read %s: %s", path, exc)
        return None

    text_stripped = text.strip()
    if not text_stripped:
        return None

    # JSON-based detection first.
    if text_stripped.startswith("{"):
        try:
            data = json.loads(text_stripped)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            keys = set(data.keys())
            tools_state_markers = {"engagement_id", "targets", "phases"}
            chain_state_markers = {"chains", "links"}
            if tools_state_markers.issubset(keys):
                return "tools_state"
            if chain_state_markers.issubset(keys):
                return "chain_state"
            if "phases" in keys and "targets" in keys:
                return "tools_state"
            if "chains" in keys or "links" in keys:
                return "chain_state"
            return None

    # YAML-based chain detection.
    if "links:" in text or "- type:" in text or "chain_id:" in text:
        return "chain_state"

    # JSONL detection: multiple JSON objects, each with chain-like keys.
    if text_stripped.startswith("{"):
        return None

    return None


def _tools_state_to_records(d: Dict[str, Any], source_label: str) -> List[Dict[str, Any]]:
    """Convert a tools/state.py style dict into per-record dicts."""

    engagement_id = str(d.get("engagement_id") or d.get("mission_id") or "default")
    out: List[Dict[str, Any]] = []

    scope = {
        "engagement_id": engagement_id,
        "targets": d.get("targets", []),
        "in_scope": d.get("in_scope", []),
        "out_of_scope": d.get("out_of_scope", []),
    }
    out.append({
        "kind": EntryKind.SCOPE.value,
        "mission_id": engagement_id,
        "actor": str(d.get("actor", "tools.state")),
        "payload": scope,
        "source": source_label,
    })

    for ph in d.get("phases") or []:
        if not isinstance(ph, dict):
            continue
        out.append({
            "kind": EntryKind.AUDIT.value,
            "mission_id": engagement_id,
            "actor": str(d.get("actor", "tools.state")),
            "payload": {
                "from": str(ph.get("from", "")),
                "to": str(ph.get("to", "")),
                "reason": str(ph.get("reason", "legacy")),
                "legacy": True,
            },
            "source": source_label,
        })

    for f in d.get("findings") or []:
        if not isinstance(f, dict):
            continue
        out.append({
            "kind": EntryKind.FINDING.value,
            "mission_id": engagement_id,
            "actor": str(d.get("actor", "tools.state")),
            "payload": dict(f),
            "source": source_label,
        })

    for ep in d.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        out.append({
            "kind": EntryKind.SCAN.value,
            "mission_id": engagement_id,
            "actor": str(d.get("actor", "tools.state")),
            "payload": dict(ep),
            "source": source_label,
        })

    return out


def _chain_state_to_records(d: Dict[str, Any], source_label: str) -> List[Dict[str, Any]]:
    """Convert a chain/... style record into per-record dicts."""

    mission_id = str(d.get("mission_id") or d.get("chain_id") or "default")
    out: List[Dict[str, Any]] = []
    for ch in d.get("chains") or []:
        if not isinstance(ch, dict):
            continue
        out.append({
            "kind": EntryKind.CHAIN.value,
            "mission_id": mission_id,
            "actor": str(d.get("actor", "chain")),
            "payload": dict(ch),
            "source": source_label,
        })
    for link in d.get("links") or []:
        if not isinstance(link, dict):
            continue
        out.append({
            "kind": EntryKind.CHAIN.value,
            "mission_id": mission_id,
            "actor": str(d.get("actor", "chain")),
            "payload": dict(link),
            "source": source_label,
        })
    if not out:
        out.append({
            "kind": EntryKind.MIGRATION.value,
            "mission_id": mission_id,
            "actor": "migrate",
            "payload": {"raw": d},
            "source": source_label,
        })
    return out


def migrate_legacy(
    path: str,
    output: State,
    *,
    source_label: str = "legacy",
) -> int:
    """Read ``path`` and append converted records to ``output``.

    Returns the number of records appended. STUB-SAFE: parse errors log a
    warning and return 0.
    """

    p = Path(path)
    if not p.exists() or not p.is_file():
        _LOG.warning("migrate_legacy: missing file %s", path)
        return 0

    fmt = detect_legacy_format(path)
    if fmt is None:
        _LOG.warning("migrate_legacy: unknown format for %s", path)
        return 0

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        _LOG.warning("migrate_legacy: read failed for %s: %s", path, exc)
        return 0

    if fmt == "tools_state":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            _LOG.warning("migrate_legacy: tools_state JSON parse error: %s", exc)
            return 0
        if not isinstance(data, dict):
            _LOG.warning("migrate_legacy: tools_state root not a dict")
            return 0
        records = _tools_state_to_records(data, source_label)
    elif fmt == "chain_state":
        # Try JSON first; fall back to a raw migration record.
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                records = _chain_state_to_records(data, source_label)
            else:
                records = [{
                    "kind": EntryKind.MIGRATION.value,
                    "mission_id": "default",
                    "actor": "migrate",
                    "payload": {"raw_text": text[:8192]},
                    "source": source_label,
                }]
        except json.JSONDecodeError:
            records = [{
                "kind": EntryKind.MIGRATION.value,
                "mission_id": "default",
                "actor": "migrate",
                "payload": {"raw_text": text[:8192]},
                "source": source_label,
            }]
    else:
        return 0

    count = 0
    for r in records:
        try:
            kind = EntryKind(r["kind"])
        except (ValueError, KeyError):
            kind = EntryKind.MIGRATION
        output.append(
            kind,
            {
                "migration": True,
                "source": source_label,
                **r.get("payload", {}),
            },
            mission_id=r.get("mission_id"),
            actor=r.get("actor"),
        )
        count += 1
    return count


def migrate_legacy_dict(
    d: Dict[str, Any],
    output: State,
    *,
    source_label: str = "legacy",
) -> int:
    """Same as :func:`migrate_legacy` but takes an already-parsed dict."""

    if not isinstance(d, dict):
        _LOG.warning("migrate_legacy_dict: input is not a dict")
        return 0

    keys = set(d.keys())
    if {"engagement_id", "targets", "phases"}.issubset(keys) or (
        "targets" in keys and "phases" in keys
    ):
        records = _tools_state_to_records(d, source_label)
    elif "chains" in keys or "links" in keys:
        records = _chain_state_to_records(d, source_label)
    else:
        _LOG.warning("migrate_legacy_dict: unknown shape")
        return 0

    count = 0
    for r in records:
        try:
            kind = EntryKind(r["kind"])
        except (ValueError, KeyError):
            kind = EntryKind.MIGRATION
        output.append(
            kind,
            {
                "migration": True,
                "source": source_label,
                **r.get("payload", {}),
            },
            mission_id=r.get("mission_id"),
            actor=r.get("actor"),
        )
        count += 1
    return count
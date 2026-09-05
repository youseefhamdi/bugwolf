"""Append-only JSONL state with cross-process locking."""

# bugwolf/unified_state — single append-only journal across all capabilities
# SCHEMA: bugwolf-unifiedstate-state-v1
# ## Source: original work for Phase 5.3
# ## License: BugWolf internal
# ## Capability tier: C0 (state management) — append-only, hash-chained

from __future__ import annotations

import fcntl
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from bugwolf.unified_state.chain import GENESIS_HASH, entry_hash, seal_entry, verify_chain
from bugwolf.unified_state.types import Entry, EntryKind, from_dict

SCHEMA = "bugwolf-unifiedstate-state-v1"

_LOG = logging.getLogger("bugwolf.unified_state.state")

try:
    _fcntl = fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None


class State:
    """Append-only hash-chained journal stored as JSONL."""

    def __init__(
        self,
        path: str,
        *,
        mission_id: str = "default",
        actor: str = "bugwolf",
        auto_flush: bool = True,
    ) -> None:
        self.path = str(path)
        self._mission_id = str(mission_id)
        self._actor = str(actor)
        self._auto_flush = bool(auto_flush)
        self._cached_seq = 0
        self._cached_last_hash = GENESIS_HASH
        self._loaded = False

        # Eagerly load so append() always knows the correct sequence number.
        self._load_cache()

    # ------------------------------------------------------------------
    # Construction / open
    # ------------------------------------------------------------------

    @classmethod
    def open(cls, path: str, **kwargs: Any) -> "State":
        """Open or create a journal at ``path``.

        STUB-SAFE: missing file → creates new; corrupt JSONL → creates new
        and logs a warning.
        """

        p = Path(path)
        instance = cls.__new__(cls)
        instance.path = str(path)
        instance._mission_id = str(kwargs.get("mission_id", "default"))
        instance._actor = str(kwargs.get("actor", "bugwolf"))
        instance._auto_flush = bool(kwargs.get("auto_flush", True))
        instance._cached_seq = 0
        instance._cached_last_hash = GENESIS_HASH
        instance._loaded = False
        instance._load_cache()
        return instance

    # ------------------------------------------------------------------
    # Cache loading
    # ------------------------------------------------------------------

    def _load_cache(self) -> None:
        p = Path(self.path)
        if not p.exists():
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.touch()
            except OSError as exc:
                _LOG.warning("cannot create journal %s: %s", self.path, exc)
            self._loaded = True
            return

        try:
            entries = self._read_all_unsafe()
        except Exception as exc:  # STUB-SAFE
            _LOG.warning("corrupt journal at %s: %s — starting fresh", self.path, exc)
            entries = []

        if entries:
            self._cached_seq = max(e.seq for e in entries)
            self._cached_last_hash = entries[-1].hash or GENESIS_HASH
        self._loaded = True

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def read_all(self) -> List[Entry]:
        """Read all entries from the journal. STUB-SAFE on corruption."""

        try:
            return self._read_all_unsafe()
        except Exception as exc:  # STUB-SAFE
            _LOG.warning("read_all failed for %s: %s", self.path, exc)
            return []

    def _read_all_unsafe(self) -> List[Entry]:
        entries: List[Entry] = []
        p = Path(self.path)
        if not p.exists():
            return entries
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    _LOG.warning("skipping corrupt JSONL line in %s", self.path)
                    continue
                try:
                    entries.append(from_dict(d))
                except Exception as exc:  # STUB-SAFE
                    _LOG.warning("skipping unparseable entry: %s", exc)
                    continue
        return entries

    # ------------------------------------------------------------------
    # Write (append only)
    # ------------------------------------------------------------------

    def append(
        self,
        kind: EntryKind,
        payload: Dict[str, Any],
        *,
        mission_id: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> Entry:
        """Append a new entry to the journal."""

        if not isinstance(kind, EntryKind):
            try:
                kind = EntryKind(kind)
            except (ValueError, TypeError):
                _LOG.warning("unknown kind %r, coercing to AUDIT", kind)
                kind = EntryKind.AUDIT

        payload_dict = payload if isinstance(payload, dict) else {"value": payload}

        entry = Entry(
            id=uuid.uuid4().hex,
            seq=self._cached_seq + 1,
            timestamp=time.time(),
            kind=kind,
            mission_id=str(mission_id if mission_id is not None else self._mission_id),
            actor=str(actor if actor is not None else self._actor),
            payload=dict(payload_dict),
            prev_hash=self._cached_last_hash,
            hash="",
        )
        entry.hash = entry_hash(entry)

        self._write_locked(entry)
        self._cached_seq = entry.seq
        self._cached_last_hash = entry.hash
        return entry

    def _write_locked(self, entry: Entry) -> None:
        d = {
            "id": entry.id,
            "seq": entry.seq,
            "timestamp": entry.timestamp,
            "kind": entry.kind.value if isinstance(entry.kind, EntryKind) else str(entry.kind),
            "mission_id": entry.mission_id,
            "actor": entry.actor,
            "payload": entry.payload,
            "prev_hash": entry.prev_hash,
            "hash": entry.hash,
            "signature": entry.signature,
        }
        line = json.dumps(d, ensure_ascii=False, separators=(",", ":"))

        p = Path(self.path)
        parent = p.parent
        try:
            if parent and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _LOG.warning("mkdir failed for %s: %s", parent, exc)

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        try:
            fd = os.open(str(p), flags, 0o644)
        except OSError as exc:
            _LOG.warning("open(O_APPEND) failed for %s: %s", self.path, exc)
            return

        try:
            if _fcntl is not None:
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX)
                except OSError as exc:
                    _LOG.debug("flock failed: %s", exc)
            payload = (line + "\n").encode("utf-8")
            try:
                os.write(fd, payload)
                if self._auto_flush:
                    try:
                        os.fsync(fd)
                    except OSError:
                        pass
            except OSError as exc:
                _LOG.warning("write failed for %s: %s", self.path, exc)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def verify(self) -> Dict[str, Any]:
        """Verify the chain integrity of this journal."""

        return verify_chain(self.read_all())

    def entries_by_kind(self, kind: EntryKind) -> List[Entry]:
        if not isinstance(kind, EntryKind):
            try:
                kind = EntryKind(kind)
            except (ValueError, TypeError):
                return []
        return [e for e in self.read_all() if e.kind == kind]

    def entries_by_mission(self, mission_id: str) -> List[Entry]:
        return [e for e in self.read_all() if e.mission_id == mission_id]

    def latest(self, kind: Optional[EntryKind] = None) -> Optional[Entry]:
        entries = self.read_all()
        if kind is not None:
            entries = [e for e in entries if e.kind == kind]
        if not entries:
            return None
        return entries[-1]

    def stats(self) -> Dict[str, Any]:
        entries = self.read_all()
        by_kind: Dict[str, int] = {}
        missions = set()
        first_ts = None
        last_ts = None
        last_hash = GENESIS_HASH
        for e in entries:
            kind_name = e.kind.value if isinstance(e.kind, EntryKind) else str(e.kind)
            by_kind[kind_name] = by_kind.get(kind_name, 0) + 1
            missions.add(e.mission_id)
            if first_ts is None or e.timestamp < first_ts:
                first_ts = e.timestamp
            if last_ts is None or e.timestamp > last_ts:
                last_ts = e.timestamp
            last_hash = e.hash
        return {
            "total": len(entries),
            "by_kind": by_kind,
            "missions": sorted(missions),
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "last_hash": last_hash,
        }


# Convenience alias matching the spec. Note: do NOT assign to a name
# named `open` because that would shadow the built-in `open()` used
# internally by this module.
_state_open = State.open
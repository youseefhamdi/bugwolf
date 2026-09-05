## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL corpus culling approach (afl-cmin) — minimisation concept
## License: bugwolf-MIT
## Schema: bugwolf-fuzz-v1

"""Seed corpus CRUD for the BugWolf fuzzing substrate.

:class:`CorpusManager` is a thin filesystem layer over a directory of
seed files.  It supports:

  * :meth:`add` — copy/append new seeds with deterministic names
  * :meth:`minimize` — drop duplicates (sha256) and shrink to a cap
  * :meth:`merge` — merge several corpus directories
  * :meth:`cull` — prune low-utility seeds (random sample when no
    coverage is provided)
  * :meth:`list` — return a snapshot of seeds with metadata

All methods are stub-safe: if the corpus directory does not exist
they create it lazily.  No network, no third-party deps.
"""
from __future__ import annotations

import hashlib
import os
import random
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fuzz-corpus-v1"


@dataclass(frozen=True)
class CorpusEntry:
    """One seed file in the corpus."""

    path: str
    sha256: str
    size_bytes: int


@dataclass
class CorpusManager:
    """Filesystem-backed seed corpus manager.

    Parameters
    ----------
    root:
        Root directory for the corpus.  Created lazily.
    max_entries:
        Soft cap on corpus size used by :meth:`minimize`.
    """

    root: Path
    max_entries: int = 1024
    _rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        try:
            Path(self.root).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ----------------------------------------------------------------- API

    def add(self, data: bytes, *, name: Optional[str] = None) -> CorpusEntry:
        """Append ``data`` to the corpus and return its entry."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(data).hexdigest()[:16]
            stem = name or f"seed_{digest}"
            target = self._unique_target(stem)
            target.write_bytes(data)
            return CorpusEntry(path=str(target), sha256=digest, size_bytes=len(data))
        except Exception as exc:
            return CorpusEntry(path=str(self.root), sha256="", size_bytes=0)

    def add_path(self, source: Path, *, name: Optional[str] = None) -> CorpusEntry:
        """Copy a file into the corpus."""
        try:
            data = Path(source).read_bytes()
        except Exception:
            return CorpusEntry(path=str(source), sha256="", size_bytes=0)
        return self.add(data, name=name or Path(source).name)

    def minimize(self) -> List[CorpusEntry]:
        """Drop duplicates and shrink the corpus to ``max_entries``."""
        try:
            entries = self.list()
            seen: dict = {}
            for entry in entries:
                try:
                    p = Path(entry.path)
                    if not p.exists():
                        continue
                    if entry.sha256 in seen:
                        try:
                            p.unlink()
                        except Exception:
                            pass
                        continue
                    seen[entry.sha256] = p
                except Exception:
                    continue
            kept = list(seen.values())
            if len(kept) > self.max_entries:
                random.shuffle(kept)
                for victim in kept[self.max_entries :]:
                    try:
                        Path(victim).unlink()
                    except Exception:
                        pass
            return self.list()
        except Exception:
            return []

    def merge(self, others: Sequence[Path]) -> List[CorpusEntry]:
        """Copy seeds from ``others`` into this corpus."""
        try:
            added = 0
            for other in others:
                src = Path(other)
                if not src.exists() or not src.is_dir():
                    continue
                for entry in src.rglob("*"):
                    if not entry.is_file():
                        continue
                    try:
                        data = entry.read_bytes()
                    except Exception:
                        continue
                    self.add(data, name=entry.name)
                    added += 1
            return self.list()
        except Exception:
            return self.list()

    def cull(self, coverage: Optional[dict] = None, *, keep_ratio: float = 0.5) -> List[CorpusEntry]:
        """Prune low-utility seeds.

        Without a coverage map the manager falls back to random
        sampling at ``keep_ratio``.  Never raises.
        """
        try:
            entries = self.list()
            if not entries:
                return entries
            keep = max(1, int(len(entries) * max(0.0, min(1.0, keep_ratio))))
            if coverage:
                scored = sorted(
                    entries,
                    key=lambda e: float(coverage.get(e.sha256, self._rng.random())),
                    reverse=True,
                )
                keep_paths = {e.path for e in scored[:keep]}
            else:
                keep_paths = {e.path for e in self._rng.sample(entries, keep)}
            for entry in entries:
                if entry.path not in keep_paths:
                    try:
                        Path(entry.path).unlink()
                    except Exception:
                        pass
            return self.list()
        except Exception:
            return []

    def list(self) -> List[CorpusEntry]:
        """Return a snapshot of the corpus."""
        out: List[CorpusEntry] = []
        try:
            for f in sorted(Path(self.root).iterdir()):
                if not f.is_file():
                    continue
                try:
                    data = f.read_bytes()
                    sha = hashlib.sha256(data).hexdigest()[:16]
                except Exception:
                    sha = ""
                out.append(CorpusEntry(path=str(f), sha256=sha, size_bytes=f.stat().st_size))
        except Exception:
            pass
        return out

    def clear(self) -> int:
        """Remove every file under :py:attr:`root`.  Returns count removed."""
        count = 0
        try:
            for f in Path(self.root).iterdir():
                if not f.is_file():
                    continue
                try:
                    f.unlink()
                    count += 1
                except Exception:
                    pass
        except Exception:
            pass
        return count

    # ------------------------------------------------------------ internals

    def _unique_target(self, stem: str) -> Path:
        """Return a path under :py:attr:`root` that does not yet exist."""
        safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in stem)
        if not safe:
            safe = "seed"
        base = self.root / safe
        if not base.exists():
            return base
        i = 1
        while True:
            candidate = self.root / f"{safe}.{i}"
            if not candidate.exists():
                return candidate
            i += 1
            if i > 9999:
                # Last-ditch: fall back to a deterministic suffix.
                return self.root / f"{safe}.{hash(os.urandom(4)).hexdigest()[:6]}"


__all__ = [
    "CorpusManager",
    "CorpusEntry",
]

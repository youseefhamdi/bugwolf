"""Semantic pattern matching using TF-IDF + cosine similarity.

Phase 3.3 of BugWolf: given a structured finding (or a free-text snippet),
find the closest entries in a local corpus of known-good bug patterns.  The
corpus is just a directory of JSON / Markdown / TXT files; we index them
on the fly with stdlib only (``collections.Counter`` for term counts,
``math`` for the cosine product).

This is intentionally simpler than an embedding model: the goal is to give
the operator a deterministic, STUB-SAFE "show me the closest known-good
finding" lookup that works offline, on tiny corpora, and without
third-party deps.

STUB-SAFE: if ``corpus_dir`` is empty / missing, ``find_similar()``
returns ``[]`` rather than raising.

## Source:  bugwolf/semantic/semantic_search.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stopwords + tokenisation (stdlib only, deterministic, language-agnostic)
# ---------------------------------------------------------------------------

# Compact English stopword set.  The point is to suppress ubiquitous tokens
# that don't carry semantic signal; we don't need a full IR stopword list
# because the corpora are small bug-pattern files.
_STOPWORDS: frozenset = frozenset(
    s.lower() for s in (
        "a an the and or of in to for on with at by from is are be as "
        "it this that these those but if not no so do does did has have "
        "had will would should could can may might must i you we he she "
        "they them their our your my me us he her him its was were been "
        "being also any all some such only own same than too very"
    ).split()
)

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_\-]{1,}")


def _tokenize(text: str) -> List[str]:
    """Lower-case + tokenise, drop stopwords + very short tokens."""
    if not text:
        return []
    out: List[str] = []
    for tok in _TOKEN_RE.findall(text.lower()):
        if len(tok) < 2:
            continue
        if tok in _STOPWORDS:
            continue
        out.append(tok)
    return out


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SemanticMatch:
    """One ranked match between a query finding and a corpus pattern."""

    pattern_id: str
    similarity: float
    h100_reference: str
    chain_id: str
    title: str = ""
    description: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "pattern_id": self.pattern_id,
            "similarity": round(self.similarity, 6),
            "h100_reference": self.h100_reference,
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "raw": dict(self.raw),
        }


# ---------------------------------------------------------------------------
# Internal corpus record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _CorpusEntry:
    pattern_id: str
    title: str
    description: str
    h100_reference: str
    chain_id: str
    raw: Dict[str, Any]
    vector: Counter = field(default_factory=Counter)
    norm: float = 0.0

    def text(self) -> str:
        return " ".join((self.title, self.description))


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class SemanticSearch:
    """TF-IDF + cosine similarity over a local pattern corpus.

    The corpus can be one of three shapes:

    1. A directory of ``*.json`` files; each file may be either a single
       pattern dict or a list of dicts.
    2. A directory of ``*.md`` / ``*.markdown`` files; the entire content
       is the description, the first ``#`` heading becomes the title.
    3. A directory of ``*.txt`` files; first non-blank line is the title,
       rest is description.

    The class is STUB-SAFE: an empty or missing directory yields an empty
    index, and :meth:`find_similar` returns ``[]``.
    """

    def __init__(self, corpus_dir: Path) -> None:
        self.corpus_dir: Path = Path(corpus_dir)
        self._entries: List[_CorpusEntry] = []
        self._idf: Dict[str, float] = {}
        self._index_built: bool = False

    # ------------------------------------------------------------------ index

    def index(self) -> None:
        """(Re)build the in-memory index from the corpus directory.

        Always safe to call.  No third-party IO, no remote calls.
        """
        self._entries = []
        self._idf = {}
        self._index_built = True
        if not self.corpus_dir.exists() or not self.corpus_dir.is_dir():
            log.debug("semantic_search: corpus_dir missing: %s", self.corpus_dir)
            return
        try:
            files = sorted(self.corpus_dir.iterdir())
        except OSError as exc:
            log.warning("semantic_search: cannot list %s: %s",
                        self.corpus_dir, exc)
            return
        raw_records: List[Dict[str, Any]] = []
        for f in files:
            if not f.is_file():
                continue
            try:
                if f.suffix.lower() == ".json":
                    self._ingest_json(f, raw_records)
                elif f.suffix.lower() in (".md", ".markdown"):
                    self._ingest_markdown(f, raw_records)
                elif f.suffix.lower() == ".txt":
                    self._ingest_text(f, raw_records)
            except OSError as exc:
                log.debug("semantic_search: cannot read %s: %s", f, exc)
        # Compute tf vectors per entry.
        entries: List[_CorpusEntry] = []
        for rec in raw_records:
            text = " ".join((
                str(rec.get("title", "")),
                str(rec.get("description", "")),
                str(rec.get("signature", "")),
                str(rec.get("tags", "")),
            ))
            tf = Counter(_tokenize(text))
            norm = math.sqrt(sum(v * v for v in tf.values()))
            entries.append(_CorpusEntry(
                pattern_id=str(rec.get("pattern_id") or rec.get("id")
                               or rec.get("name") or ""),
                title=str(rec.get("title", "")),
                description=str(rec.get("description", "")),
                h100_reference=str(rec.get("h100_reference")
                                   or rec.get("reference") or ""),
                chain_id=str(rec.get("chain_id") or rec.get("chain") or ""),
                raw=rec,
                vector=tf,
                norm=norm,
            ))
        # Compute idf from the in-corpus term counts.
        N = max(1, len(entries))
        df: Counter = Counter()
        for e in entries:
            for term in e.vector:
                df[term] += 1
        idf: Dict[str, float] = {}
        for term, d in df.items():
            idf[term] = math.log((N + 1.0) / (d + 1.0)) + 1.0
        self._entries = entries
        self._idf = idf

    def _ingest_json(self, f: Path, out: List[Dict[str, Any]]) -> None:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return
        if isinstance(data, list):
            for rec in data:
                if isinstance(rec, dict):
                    out.append(self._normalise_record(rec, f))
        elif isinstance(data, dict):
            out.append(self._normalise_record(data, f))

    def _normalise_record(self, rec: Dict[str, Any], f: Path) -> Dict[str, Any]:
        out = dict(rec)
        if "pattern_id" not in out:
            out["pattern_id"] = out.get("id") or f.stem
        if "title" not in out:
            out["title"] = out.get("name") or f.stem
        return out

    def _ingest_markdown(self, f: Path, out: List[Dict[str, Any]]) -> None:
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        title, desc = self._split_markdown(text)
        out.append({
            "pattern_id": f.stem,
            "title": title or f.stem,
            "description": desc or text,
            "h100_reference": "",
            "chain_id": "",
        })

    def _ingest_text(self, f: Path, out: List[Dict[str, Any]]) -> None:
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        lines = [ln for ln in text.splitlines() if ln.strip()]
        title = lines[0] if lines else f.stem
        desc = "\n".join(lines[1:]) if len(lines) > 1 else title
        out.append({
            "pattern_id": f.stem,
            "title": title,
            "description": desc,
            "h100_reference": "",
            "chain_id": "",
        })

    @staticmethod
    def _split_markdown(text: str) -> Tuple[str, str]:
        title = ""
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith("#"):
                title = ln.lstrip("#").strip()
                break
            title = ln
            break
        if not title:
            title = ""
        return title, text

    # ------------------------------------------------------------------ query

    def _ensure_indexed(self) -> None:
        if not self._index_built:
            self.index()

    def find_similar(
        self, finding: Dict[str, Any], *, top_k: int = 5
    ) -> List[SemanticMatch]:
        """Return the top-k most similar corpus entries for ``finding``.

        ``finding`` is a dict; the method pulls ``title`` and ``description``
        fields (and ``signature`` if present), tokenises, weights by the
        corpus IDF, and ranks by cosine similarity.  Ties are broken
        alphabetically by pattern_id for determinism.

        STUB-SAFE: returns ``[]`` on any error, empty corpus, or zero
        query length.
        """
        self._ensure_indexed()
        if not self._entries:
            return []
        query_text = self._query_text(finding)
        if not query_text:
            return []
        try:
            k = max(1, int(top_k))
        except (TypeError, ValueError):
            k = 5
        q_tf = Counter(_tokenize(query_text))
        if not q_tf:
            return []
        # Apply corpus idf to the query vector; OOV terms get weight 0.
        # We also keep a count of how many *in-corpus* terms we have so
        # the cosine denominator doesn't get inflated by OOV mass.
        q_vec: Dict[str, float] = {}
        for term, c in q_tf.items():
            w = self._idf.get(term, 0.0)
            if w > 0.0:
                q_vec[term] = float(c) * float(w)
        if not q_vec:
            # IDF is empty: we have a corpus but nothing in common.  Fall
            # back to unweighted term overlap so the operator still gets
            # *something*; this branch is rare because we seed the corpus
            # idf with +1.
            for term, c in q_tf.items():
                q_vec[term] = float(c)
        q_norm = math.sqrt(sum(v * v for v in q_vec.values()))
        if q_norm <= 0.0:
            return []
        scored: List[Tuple[float, _CorpusEntry]] = []
        for entry in self._entries:
            if entry.norm <= 0.0:
                continue
            dot = 0.0
            for term, qw in q_vec.items():
                ew = entry.vector.get(term, 0)
                if ew <= 0:
                    continue
                # Both sides are weighted by the same idf, so the
                # cosine denominator must be the idf-weighted norm of
                # the entry too.  Recompute it from the entry's raw
                # vector * idf.
                e_idf_weighted = float(ew) * self._idf.get(term, 1.0)
                dot += qw * e_idf_weighted
            # Compute entry norm in the same idf-weighted space on the
            # fly; matches the q_vec construction above.
            e_norm_w = 0.0
            for term, ew in entry.vector.items():
                w = self._idf.get(term, 0.0)
                if w <= 0.0:
                    continue
                e_norm_w += (float(ew) * w) ** 2
            e_norm_w = math.sqrt(e_norm_w)
            if e_norm_w <= 0.0:
                continue
            sim = dot / (q_norm * e_norm_w)
            # Clamp to [0, 1] -- floating-point noise can push the
            # value just over 1.0 on perfectly identical documents.
            if sim > 1.0:
                sim = 1.0
            elif sim < 0.0:
                sim = 0.0
            if sim > 0.0:
                scored.append((sim, entry))
        # Sort by (similarity desc, pattern_id asc) for deterministic ties.
        scored.sort(key=lambda se: (-se[0], se[1].pattern_id))
        out: List[SemanticMatch] = []
        for sim, entry in scored[:k]:
            out.append(SemanticMatch(
                pattern_id=entry.pattern_id,
                similarity=float(sim),
                h100_reference=entry.h100_reference,
                chain_id=entry.chain_id,
                title=entry.title,
                description=entry.description[:400],
                raw=entry.raw,
            ))
        return out

    @staticmethod
    def _query_text(finding: Dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            return ""
        title = finding.get("title") or finding.get("name") or ""
        description = finding.get("description") or finding.get("detail") or ""
        signature = finding.get("signature") or finding.get("evidence") or ""
        tags = finding.get("tags")
        if isinstance(tags, (list, tuple)):
            tags = " ".join(str(t) for t in tags)
        elif tags is None:
            tags = ""
        return " ".join(str(x) for x in (title, description, signature, tags))

    # ------------------------------------------------------------------ audit

    @property
    def size(self) -> int:
        return len(self._entries)

    def describe(self) -> Dict[str, Any]:
        self._ensure_indexed()
        return {
            "schema": SCHEMA,
            "corpus_dir": str(self.corpus_dir),
            "entries": len(self._entries),
            "vocab": len(self._idf),
        }


__all__ = ["SCHEMA", "SemanticMatch", "SemanticSearch"]

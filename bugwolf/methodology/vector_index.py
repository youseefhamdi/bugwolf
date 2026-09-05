"""Vector index for the methodology corpus.

Pure-Python TF-IDF implementation backed by ``collections.Counter`` and
``math`` — no NumPy, no scipy, no external NLP libraries.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> List[str]:
    """Lowercase + alphanumeric tokenize."""
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


@dataclass
class _Doc:
    doc_id: str
    tokens: List[str]
    norm: float = 0.0


class VectorIndex:
    """In-memory TF-IDF index with cosine similarity ranking.

    Usage:
        idx = VectorIndex()
        idx.add("p1", "ssrf cloud metadata aws imds")
        idx.add("p2", "xss stored comment injection")
        idx.query("ssrf aws", top_k=5) -> [("p1", 0.91), ...]
    """

    def __init__(self) -> None:
        self._docs: List[_Doc] = []
        self._doc_lookup: Dict[str, _Doc] = {}
        self._df: Counter = Counter()
        self._n: int = 0

    def add(self, doc_id: str, text: str) -> None:
        """Add a document to the index. Re-adding replaces the entry."""
        if doc_id in self._doc_lookup:
            self.remove(doc_id)
        tokens = _tokenize(text)
        self._df.update(set(tokens))
        doc = _Doc(doc_id=doc_id, tokens=tokens)
        self._docs.append(doc)
        self._doc_lookup[doc_id] = doc
        self._n += 1

    def remove(self, doc_id: str) -> None:
        """Remove a document and rebuild df counters."""
        doc = self._doc_lookup.pop(doc_id, None)
        if doc is None:
            return
        self._docs = [d for d in self._docs if d.doc_id != doc_id]
        self._df = Counter()
        for d in self._docs:
            self._df.update(set(d.tokens))
        self._n = len(self._docs)

    def __len__(self) -> int:
        return self._n

    def _idf(self, term: str) -> float:
        if self._n == 0:
            return 0.0
        df = self._df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log((1 + self._n) / (1 + df)) + 1.0

    def _vector(self, tokens: List[str]) -> Dict[str, float]:
        tf = Counter(tokens)
        return {term: count * self._idf(term) for term, count in tf.items()}

    @staticmethod
    def _norm(vec: Dict[str, float]) -> float:
        return math.sqrt(sum(v * v for v in vec.values()))

    @staticmethod
    def _cosine(a: Dict[str, float], b: Dict[str, float], b_norm: float) -> float:
        if not a or b_norm == 0.0:
            return 0.0
        if len(a) > len(b):
            a, b = b, a
        dot = 0.0
        for term, weight in a.items():
            other = b.get(term)
            if other is not None:
                dot += weight * other
        a_norm = math.sqrt(sum(v * v for v in a.values()))
        if a_norm == 0.0:
            return 0.0
        return dot / (a_norm * b_norm)

    def query(self, text: str, top_k: int = 5) -> List[Tuple[str, float]]:
        """Return ``top_k`` (doc_id, score) tuples sorted by cosine similarity."""
        if self._n == 0:
            return []
        query_tokens = _tokenize(text)
        if not query_tokens:
            return []
        q_vec = self._vector(query_tokens)
        q_norm = self._norm(q_vec)
        if q_norm == 0.0:
            return []
        scored: List[Tuple[str, float]] = []
        for doc in self._docs:
            d_vec = self._vector(doc.tokens)
            d_norm = self._norm(d_vec)
            score = self._cosine(q_vec, d_vec, d_norm)
            if score > 0.0:
                scored.append((doc.doc_id, score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[: max(0, top_k)]

    def documents(self) -> Iterable[str]:
        """Yield doc ids in insertion order."""
        for d in self._docs:
            yield d.doc_id
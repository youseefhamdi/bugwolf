"""Methodology library — tradecraft corpus powering the bugwolf platform.

Public API:
    PatternRecord    — frozen dataclass for a single bug pattern.
    ChainSpec        — frozen dataclass for a multi-step exploit chain.
    SearchIndex      — alias for ``MethodologySearch`` (TF-IDF over patterns).
"""

from bugwolf.methodology.search import PatternRecord, ChainSpec, MethodologySearch
from bugwolf.methodology.citation import Citation, CitationEngine
from bugwolf.methodology.vector_index import VectorIndex

__all__ = [
    "PatternRecord",
    "ChainSpec",
    "MethodologySearch",
    "SearchIndex",
    "Citation",
    "CitationEngine",
    "VectorIndex",
]
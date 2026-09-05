"""Auto-citation engine: matches findings to the closest methodology patterns.

Used by report writers to attach inline evidence-backed citations to
each finding in a report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from bugwolf.methodology.search import MethodologySearch, PatternRecord


@dataclass(frozen=True)
class Citation:
    """A single citation binding a finding to a pattern."""

    pattern_id: str
    title: str
    confidence: float
    snippet: str

    def render(self) -> str:
        return f"[{self.pattern_id}] {self.title} (confidence={self.confidence:.2f})"


class CitationEngine:
    """Top-K citation selector over the methodology index.

    Usage:
        engine = CitationEngine("/path/to/bugwolf/methodology")
        cites  = engine.cite([{"title": "SSRF to AWS", "summary": "..."}])
        engine.format(cites)   # markdown bullet list
    """

    DEFAULT_TOP_K = 3

    def __init__(self, root_path) -> None:
        self.search = MethodologySearch(root_path)
        self.search.index()

    def _query_text(self, finding: dict) -> str:
        parts = [
            finding.get("title", ""),
            finding.get("summary", ""),
            finding.get("description", ""),
            finding.get("bug_class", ""),
            finding.get("category", ""),
        ]
        return " ".join(p for p in parts if p)

    def _snippet(self, rec: PatternRecord, finding: dict, max_len: int = 180) -> str:
        description = rec.description.replace("\n", " ").strip()
        if len(description) <= max_len:
            return description
        return description[: max_len - 3].rstrip() + "..."

    def cite(self, findings: List[dict], top_k: int = DEFAULT_TOP_K) -> List[List[Citation]]:
        """Return, for each finding, a list of up to ``top_k`` citations."""
        out: List[List[Citation]] = []
        for finding in findings or []:
            query = self._query_text(finding)
            if not query.strip():
                out.append([])
                continue
            hits = self.search.search(query, top_k=top_k)
            cites: List[Citation] = []
            for idx, rec in enumerate(hits):
                confidence = self._confidence(idx, len(hits))
                cites.append(
                    Citation(
                        pattern_id=rec.pattern_id,
                        title=rec.title,
                        confidence=confidence,
                        snippet=self._snippet(rec, finding),
                    )
                )
            out.append(cites)
        return out

    @staticmethod
    def _confidence(rank: int, total: int) -> float:
        if total <= 0:
            return 0.0
        base = 1.0 - (rank / max(total, 1))
        return round(max(0.05, min(1.0, base)), 3)

    def format(self, citations: Iterable[Iterable[Citation]]) -> str:
        """Render a markdown bullet list of citations."""
        rows: List[str] = []
        for finding_idx, group in enumerate(citations, start=1):
            group = list(group)
            if not group:
                rows.append(f"- Finding {finding_idx}: _(no citations matched)_")
                continue
            for cite in group:
                rows.append(
                    f"- Finding {finding_idx}: {cite.render()} — {cite.snippet}"
                )
        return "\n".join(rows)

    def cite_flat(self, findings: List[dict], top_k: int = DEFAULT_TOP_K) -> List[Citation]:
        """Flattened citation list — preserves order, no per-finding grouping."""
        flat: List[Citation] = []
        for group in self.cite(findings, top_k=top_k):
            flat.extend(group)
        return flat
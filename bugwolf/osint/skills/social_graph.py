"""OSINT skill: ``social_graph``.

Given a target identifier (user / org), propose a graph traversal
plan across the channels bugwolf ships with.  No network calls; this
is a planning helper.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..skills_base import _empty_result, _skill_result


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Return a small social-graph query plan for ``query``."""
    q = (query or "").strip()
    if not q:
        return _empty_result("social_graph", query, reason="empty query")
    edges: List[Dict[str, Any]] = [
        {"from": q, "to": "github", "via": "code_search",
         "url": f"https://github.com/search?q={q}&type=code"},
        {"from": q, "to": "twitter", "via": "search_recent",
         "url": f"https://twitter.com/search?q={q}"},
        {"from": q, "to": "reddit", "via": "search",
         "url": f"https://www.reddit.com/search/?q={q}"},
        {"from": q, "to": "linkedin", "via": "search",
         "url": f"https://www.linkedin.com/search/results/all/?keywords={q}"},
        {"from": q, "to": "youtube", "via": "search",
         "url": f"https://www.youtube.com/results?search_query={q}"},
        {"from": q, "to": "instagram", "via": "tag_search",
         "url": f"https://www.instagram.com/{q}/"},
        {"from": q, "to": "bilibili", "via": "search",
         "url": f"https://search.bilibili.com/all?keyword={q}"},
        {"from": q, "to": "xueqiu", "via": "search",
         "url": f"https://xueqiu.com/search?keyword={q}"},
    ]
    return _skill_result("social_graph", query, items=edges[: int(budget)])


__all__ = ["run"]
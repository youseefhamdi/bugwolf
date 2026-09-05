"""OSINT skill: ``document_search``.

Search engines and aggregators for public document / PDF files.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..skills_base import _empty_result, _skill_result


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Return deep-links to public document search engines for ``query``."""
    q = (query or "").strip()
    if not q:
        return _empty_result("document_search", query, reason="empty query")
    enc = quote(q, safe="")
    items: List[Dict[str, Any]] = [
        {"engine": "google_filetype",
         "url": f"https://www.google.com/search?q={enc}+filetype:pdf"},
        {"engine": "google_ppt",
         "url": f"https://www.google.com/search?q={enc}+filetype:pptx"},
        {"engine": "duckduckgo",
         "url": f"https://duckduckgo.com/?q={enc}+filetype%3Apdf"},
        {"engine": "archive_org",
         "url": f"https://archive.org/search?query={enc}"},
        {"engine": "scribd",
         "url": f"https://www.scribd.com/search?query={enc}"},
        {"engine": "slideshare",
         "url": f"https://www.slideshare.net/search/slideshow?searchtype=uploaded&q={enc}"},
    ]
    return _skill_result("document_search", query, items=items[: int(budget)])


__all__ = ["run"]
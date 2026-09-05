"""OSINT skill: ``image_search``.

Reverse image search planner.  Takes a URL or keyword and returns the
list of search providers with prefilled deep-links.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..skills_base import _empty_result, _skill_result


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Return reverse image-search deep-links for ``query``."""
    q = (query or "").strip()
    if not q:
        return _empty_result("image_search", query, reason="empty query")
    enc = quote(q, safe="")
    items: List[Dict[str, Any]] = [
        {"provider": "google_lens",
         "url": f"https://lens.google.com/uploadbyurl?url={enc}"},
        {"provider": "yandex",
         "url": f"https://yandex.com/images/search?rpt=imageview&url={enc}"},
        {"provider": "tineye",
         "url": f"https://tineye.com/search?url={enc}"},
        {"provider": "bing",
         "url": f"https://www.bing.com/images/search?q=imgurl:{enc}"},
        {"provider": "baidu",
         "url": f"https://image.baidu.com/pcdutu?queryImageUrl={enc}"},
    ]
    return _skill_result("image_search", query, items=items[: int(budget)])


__all__ = ["run"]
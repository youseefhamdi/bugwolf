"""Reddit OSINT scraper.

Hits ``https://www.reddit.com/search.json`` for the target.  Stub-safe:
no creds → ``[]``.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class RedditChannel(ChannelBase):
    name = "reddit"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        url = (
            "https://www.reddit.com/search.json?q="
            + _quote(target)
            + "&limit="
            + str(min(int(budget), 100))
        )
        body = self.http_get(url, timeout=6.0,
                             headers={"User-Agent": "bugwolf-osint/1"})
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for child in ((data.get("data") or {}).get("children") or [])[: int(budget)]:
            d = child.get("data") or {}
            permalink = str(d.get("permalink") or "")
            full_url = "https://www.reddit.com" + permalink if permalink else ""
            out.append(self.finding(
                value=str(d.get("title") or ""),
                url=full_url,
                author=str(d.get("author") or ""),
                timestamp=str(d.get("created_utc") or ""),
                confidence=0.6,
                extra={"subreddit": str(d.get("subreddit") or ""),
                       "score": int(d.get("score") or 0)},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["RedditChannel"]
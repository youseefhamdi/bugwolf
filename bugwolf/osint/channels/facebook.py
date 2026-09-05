"""Facebook scraper.

Public posts / pages.  Requires ``FACEBOOK_ACCESS_TOKEN``.  Stub-safe:
missing creds → ``[]``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class FacebookChannel(ChannelBase):
    name = "facebook"
    kind = "post"
    requires_credential = True
    env_var = "FACEBOOK_ACCESS_TOKEN"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        token = self.credential or ""
        url = (
            "https://graph.facebook.com/v18.0/search?q="
            + _quote(target)
            + "&type=post&limit="
            + str(min(int(budget), 100))
            + "&access_token="
            + _quote(token)
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
        for post in (data.get("data") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(post.get("message") or ""),
                url=str(post.get("permalink_url") or ""),
                author=str((post.get("from") or {}).get("name") or ""),
                timestamp=str(post.get("created_time") or ""),
                confidence=0.6,
                extra={"id": str(post.get("id") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["FacebookChannel"]
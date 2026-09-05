"""Xiaoyuzhou (小宇宙) podcast scraper.

Hits the public RSS feeds of trending podcasts.  Stub-safe: returns
``[]`` on network failure.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class XiaoyuzhouChannel(ChannelBase):
    name = "xiaoyuzhou"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        url = "https://api.xiaoyuzhoufm.com/v1/search?keyword=" + _quote(target)
        body = self.http_get(url, timeout=6.0, headers={
            "User-Agent": "bugwolf-osint/1",
        })
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for item in (data.get("data") or [])[: int(budget)]:
            episode = item.get("episode") or item
            eid = str(episode.get("eid") or episode.get("id") or "")
            out.append(self.finding(
                value=str(episode.get("title") or ""),
                url=(f"https://www.xiaoyuzhoufm.com/episode/{eid}"
                      if eid else ""),
                author=str((episode.get("podcast") or {}).get("title") or ""),
                confidence=0.5,
                extra={"eid": eid},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["XiaoyuzhouChannel"]
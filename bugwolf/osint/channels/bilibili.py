"""Bilibili (B 站) scraper.

Uses Bilibili's public search endpoint.  Stub-safe: network errors →
``[]``.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class BilibiliChannel(ChannelBase):
    name = "bilibili"
    kind = "video"
    requires_credential = False
    env_var = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        url = (
            "https://api.bilibili.com/x/web-interface/search/type?search_type=video&keyword="
            + _quote(target)
            + "&page=1&page_size="
            + str(min(int(budget), 50))
        )
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
        for item in ((data.get("data") or {}).get("result") or [])[: int(budget)]:
            bvid = str(item.get("bvid") or "")
            out.append(self.finding(
                value=str(item.get("title") or ""),
                url=f"https://www.bilibili.com/video/{bvid}" if bvid else "",
                author=str(item.get("author") or ""),
                confidence=0.55,
                extra={
                    "bvid": bvid,
                    "play": int(item.get("play") or 0),
                },
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["BilibiliChannel"]
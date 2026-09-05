"""Xueqiu (雪球) finance scraper.

Public quote / discussion API.  Stub-safe: network errors → ``[]``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class XueqiuChannel(ChannelBase):
    name = "xueqiu"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        url = (
            "https://xueqiu.com/query/v1/search/status.json?count="
            + str(min(int(budget), 20))
            + "&page=1&sort=time&source=all&q="
            + _quote(target)
        )
        body = self.http_get(url, timeout=6.0, headers={
            "User-Agent": "bugwolf-osint/1",
            "Referer": "https://xueqiu.com/",
        })
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for item in (data.get("list") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(item.get("title") or item.get("text") or ""),
                url=(f"https://xueqiu.com{item.get('target', '')}"),
                author=str((item.get("user") or {}).get("screen_name") or ""),
                timestamp=str(item.get("created_at") or ""),
                confidence=0.5,
                extra={"id": str(item.get("id") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["XueqiuChannel"]
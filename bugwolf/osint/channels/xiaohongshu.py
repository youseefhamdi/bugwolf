"""Xiaohongshu (小红书) scraper.

The platform aggressively blocks bots.  This module is a stub-safe
placeholder that returns ``[]`` unless an explicit cookie is supplied
via the ``XHS_COOKIE`` env var.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class XiaohongshuChannel(ChannelBase):
    name = "xiaohongshu"
    kind = "post"
    requires_credential = True
    env_var = "XHS_COOKIE"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        cookie = self.credential or ""
        url = (
            "https://www.xiaohongshu.com/api/sns/web/v1/search/notes?keyword="
            + _quote(target)
            + "&page=1&page_size="
            + str(min(int(budget), 20))
        )
        body = self.http_get(url, timeout=6.0, headers={
            "User-Agent": "bugwolf-osint/1",
            "Cookie": cookie,
        })
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        items = ((data.get("data") or {}).get("items") or [])
        for item in items[: int(budget)]:
            note = item.get("note") or item.get("note_card") or {}
            note_id = str(note.get("note_id") or item.get("id") or "")
            out.append(self.finding(
                value=str(note.get("title") or note.get("desc") or ""),
                url=(f"https://www.xiaohongshu.com/explore/{note_id}"
                      if note_id else ""),
                author=str((note.get("user") or {}).get("nickname") or ""),
                confidence=0.45,
                extra={"note_id": note_id},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["XiaohongshuChannel"]
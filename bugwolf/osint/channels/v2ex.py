"""V2EX forum scraper.

Public forum / programming community.  Stub-safe: network errors →
``[]``.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class V2EXChannel(ChannelBase):
    name = "v2ex"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        url = "https://www.v2ex.com/api/v2/search?q=" + _quote(target)
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
        for topic in (data.get("result") or [])[: int(budget)]:
            tid = str(topic.get("id") or "")
            out.append(self.finding(
                value=str(topic.get("title") or ""),
                url=(f"https://www.v2ex.com/t/{tid}" if tid else ""),
                author=str((topic.get("member") or {}).get("username") or ""),
                timestamp=str(topic.get("created") or ""),
                confidence=0.5,
                extra={"replies": int(topic.get("replies") or 0)},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["V2EXChannel"]
"""Instagram scraper.

Requires ``INSTAGRAM_SESSION_ID`` cookie value.  Stub-safe: missing
creds → ``[]``.  Network errors → ``[]``.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class InstagramChannel(ChannelBase):
    name = "instagram"
    kind = "image"
    requires_credential = True
    env_var = "INSTAGRAM_SESSION_ID"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        session_id = self.credential or ""
        url = (
            "https://www.instagram.com/web/search/topsearch/?query="
            + _quote(target)
        )
        body = self.http_get(url, timeout=6.0, headers={
            "User-Agent": "bugwolf-osint/1",
            "Cookie": f"sessionid={session_id}",
        })
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for user in (data.get("users") or [])[: int(budget)]:
            user_info = user.get("user") or {}
            username = str(user_info.get("username") or "")
            out.append(self.finding(
                value=username,
                url=f"https://www.instagram.com/{username}/",
                author=username,
                confidence=0.5,
                extra={
                    "full_name": str(user_info.get("full_name") or ""),
                    "is_verified": bool(user_info.get("is_verified") or False),
                },
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["InstagramChannel"]
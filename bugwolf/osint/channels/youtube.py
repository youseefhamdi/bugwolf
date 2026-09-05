"""YouTube metadata scraper.

Requires ``YOUTUBE_API_KEY``.  Hits the public Data API v3.  Stub-safe:
missing key → ``[]``.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class YoutubeChannel(ChannelBase):
    name = "youtube"
    kind = "video"
    requires_credential = True
    env_var = "YOUTUBE_API_KEY"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        key = self.credential or ""
        url = (
            "https://www.googleapis.com/youtube/v3/search?part=snippet&q="
            + _quote(target)
            + "&maxResults="
            + str(min(int(budget), 50))
            + "&key="
            + _quote(key)
            + "&type=video"
        )
        body = self.http_get(url, timeout=6.0)
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for item in (data.get("items") or [])[: int(budget)]:
            vid_id = ((item.get("id") or {}).get("videoId") or "")
            snippet = item.get("snippet") or {}
            out.append(self.finding(
                value=str(snippet.get("title") or ""),
                url=f"https://www.youtube.com/watch?v={vid_id}",
                author=str(snippet.get("channelTitle") or ""),
                timestamp=str(snippet.get("publishedAt") or ""),
                confidence=0.7,
                extra={
                    "video_id": str(vid_id),
                    "description": str(snippet.get("description") or ""),
                },
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["YoutubeChannel"]
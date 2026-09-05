"""Twitter / X scraper.

Requires ``TWITTER_BEARER_TOKEN`` env var.  Stub-safe: missing creds →
``[]``.

No third-party deps — uses stdlib ``urllib`` only.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class TwitterChannel(ChannelBase):
    name = "twitter"
    kind = "post"
    requires_credential = True
    env_var = "TWITTER_BEARER_TOKEN"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        token = self.credential or ""
        url = (
            "https://api.twitter.com/2/tweets/search/recent?query="
            + _quote(target)
            + "&max_results="
            + str(min(int(budget), 100))
        )
        body = self.http_get(url, timeout=6.0,
                             headers={"Authorization": f"Bearer {token}"})
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for tweet in (data.get("data") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(tweet.get("text") or ""),
                url=f"https://twitter.com/i/web/status/{tweet.get('id')}",
                author=str((tweet.get("author_id") or "")),
                timestamp=str(tweet.get("created_at") or ""),
                confidence=0.7,
                extra={"id": str(tweet.get("id") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["TwitterChannel"]
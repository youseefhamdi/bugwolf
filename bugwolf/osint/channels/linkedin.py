"""LinkedIn scraper.

LinkedIn aggressively blocks unauthenticated scraping, so this channel
is primarily a placeholder.  It supports an OAuth access token via the
``LINKEDIN_ACCESS_TOKEN`` env var.

Stub-safe: missing creds → ``[]``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class LinkedInChannel(ChannelBase):
    name = "linkedin"
    kind = "profile"
    requires_credential = True
    env_var = "LINKEDIN_ACCESS_TOKEN"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        token = self.credential or ""
        url = (
            "https://api.linkedin.com/v2/people-search?q=people&keywords="
            + _quote(target)
            + "&count="
            + str(min(int(budget), 50))
        )
        body = self.http_get(url, timeout=6.0, headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "bugwolf-osint/1",
        })
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for element in (data.get("elements") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(element.get("name") or ""),
                url=str((element.get("profileUrl") or "")),
                author=str(element.get("name") or ""),
                confidence=0.5,
                extra={"vanity_name": str(element.get("vanityName") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["LinkedInChannel"]
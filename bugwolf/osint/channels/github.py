"""GitHub OSINT — search code, commits, issues, users.

Optional ``GITHUB_TOKEN`` env var for higher rate limits.

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class GithubChannel(ChannelBase):
    name = "github"
    kind = "post"
    requires_credential = False
    env_var = "GITHUB_TOKEN"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        token = self.credential or ""
        url = (
            "https://api.github.com/search/repositories?q="
            + _quote(target)
            + "&per_page="
            + str(min(int(budget), 100))
        )
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "bugwolf-osint/1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = self.http_get(url, timeout=6.0, headers=headers)
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for repo in (data.get("items") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(repo.get("full_name") or ""),
                url=str(repo.get("html_url") or ""),
                author=str((repo.get("owner") or {}).get("login") or ""),
                timestamp=str(repo.get("updated_at") or ""),
                confidence=0.7,
                extra={
                    "stars": int(repo.get("stargazers_count") or 0),
                    "description": str(repo.get("description") or ""),
                },
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["GithubChannel"]
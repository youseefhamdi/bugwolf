"""GitHub code search via the public REST API.

Requires ``GITHUB_TOKEN`` for higher rate limits.  Stub-safe: missing
token → ``[]`` (still works against the unauthenticated endpoint but
will hit rate limits fast).

No third-party deps.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


class GithubSearchModule(PassiveModule):
    name = "github_search"
    kind = "endpoint"
    requires_key = False
    env_var = "GITHUB_TOKEN"

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        token = self.api_key or ""
        url = (
            "https://api.github.com/search/code?q="
            + _quote(target)
            + "&per_page="
            + str(min(int(budget), 100))
        )
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "bugwolf-recon/1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = self.http_get(url, timeout=8.0, headers=headers)
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[PassiveFinding] = []
        now = self.now_iso()
        for item in (data.get("items") or [])[: int(budget)]:
            html_url = str(item.get("html_url") or "")
            if not html_url:
                continue
            repo = ((item.get("repository") or {}).get("full_name") or "")
            out.append(PassiveFinding(
                kind="endpoint",
                value=html_url,
                source=self.name,
                confidence=0.65,
                seen_at=now,
                extra={"repo": repo,
                       "path": str(item.get("path") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["GithubSearchModule"]
"""Exa (Metaphor) search API.

Requires ``EXA_API_KEY``.  Hits the public Exa search endpoint.  Stub-
safe: missing key → ``[]``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class ExaSearchChannel(ChannelBase):
    name = "exa_search"
    kind = "post"
    requires_credential = True
    env_var = "EXA_API_KEY"

    def __init__(self, *, credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        key = self.credential or ""
        body_obj = {
            "query": target,
            "numResults": min(int(budget), 20),
        }
        data = json.dumps(body_obj).encode("utf-8")
        req = __import__("urllib.request", fromlist=["Request"]).Request(
            "https://api.exa.ai/search",
            data=data,
            headers={
                "x-api-key": key,
                "Content-Type": "application/json",
                "User-Agent": "bugwolf-osint/1",
            },
            method="POST",
        )
        try:
            with __import__("urllib.request", fromlist=["urlopen"]).urlopen(req, timeout=6.0) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return []
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[OSINTFinding] = []
        for hit in (payload.get("results") or [])[: int(budget)]:
            out.append(self.finding(
                value=str(hit.get("title") or ""),
                url=str(hit.get("url") or ""),
                author=str(hit.get("author") or ""),
                timestamp=str(hit.get("publishedDate") or ""),
                confidence=0.7,
                extra={"score": float(hit.get("score") or 0.0)},
            ))
        return out


__all__ = ["ExaSearchChannel"]
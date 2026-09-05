"""Wayback Machine — historical URL snapshots.

Hits the public Wayback Machine ``web.archive.org`` CDX API.  Stub-safe:
network unreachable → ``[]``.

No API key required.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


class WaybackModule(PassiveModule):
    name = "wayback"
    kind = "endpoint"
    requires_key = False
    env_var = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        url = (
            "http://web.archive.org/cdx/search/cdx?url="
            + _quote(target)
            + "/*&output=json&fl=original,timestamp&limit="
            + str(int(budget))
        )
        body = self.http_get(url, timeout=8.0,
                             headers={"User-Agent": "bugwolf-recon/1"})
        if not body:
            return []
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[PassiveFinding] = []
        seen = set()
        now = self.now_iso()
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) < 2:
                continue
            original = str(row[0])
            timestamp = str(row[1])
            if original in seen:
                continue
            seen.add(original)
            out.append(PassiveFinding(
                kind="endpoint",
                value=original,
                source=self.name,
                confidence=0.6,
                seen_at=now,
                extra={"timestamp": timestamp},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["WaybackModule"]
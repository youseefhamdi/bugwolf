"""Shodan passive intel lookup.

Requires ``SHODAN_API_KEY``.  Stub-safe: missing key → ``[]`` with the
``reason`` field set in the module's :pyattr:`missing_reason`.

No third-party deps — uses stdlib ``urllib``.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


class ShodanModule(PassiveModule):
    name = "shodan"
    kind = "ip"
    requires_key = True
    env_var = "SHODAN_API_KEY"

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        api_key = self.api_key or ""
        if not api_key:
            return []
        url = (
            "https://api.shodan.io/shodan/host/"
            + _quote(target)
            + "?key="
            + _quote(api_key)
        )
        body = self.http_get(url, timeout=8.0)
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[PassiveFinding] = []
        now = self.now_iso()
        ip_str = str(data.get("ip_str") or target)
        ports = data.get("ports") or []
        for port in ports[: int(budget)]:
            out.append(PassiveFinding(
                kind="ip",
                value=f"{ip_str}:{port}",
                source=self.name,
                confidence=0.8,
                seen_at=now,
                extra={"org": str(data.get("org") or "")},
            ))
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["ShodanModule"]
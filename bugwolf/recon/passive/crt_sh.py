"""Certificate Transparency lookup via crt.sh.

Looks up subdomain records in public CT logs.  Stub-safe: if the network
is unreachable, returns ``[]``.

No API key required.
"""

from __future__ import annotations

import json
from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


class CrtShModule(PassiveModule):
    name = "crt_sh"
    kind = "subdomain"
    requires_key = False
    env_var = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        url = (
            "https://crt.sh/?q=%25."
            + _quote(target)
            + "&output=json&dedupe=1"
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
        for row in rows[: int(budget)]:
            name = str(row.get("name_value") or "").strip().lower()
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(PassiveFinding(
                kind="subdomain",
                value=name,
                source=self.name,
                confidence=0.85,
                seen_at=now,
                extra={
                    "issuer": str(row.get("issuer_name") or ""),
                    "id": int(row.get("id") or 0),
                },
            ))
        return out


def _quote(s: str) -> str:
    """URL-quote a string (stdlib-only, no extra deps)."""
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["CrtShModule"]
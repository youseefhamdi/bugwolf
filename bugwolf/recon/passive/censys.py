"""Censys passive intel lookup.

Requires ``CENSYS_API_ID`` + ``CENSYS_API_SECRET``.  Stub-safe: missing
creds → ``[]``.

No third-party deps.
"""

from __future__ import annotations

import base64
import json
from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


class CensysModule(PassiveModule):
    name = "censys"
    kind = "ip"
    requires_key = True
    env_var = "CENSYS_API_ID"

    def __init__(self, *, api_key: Optional[str] = None,
                 api_secret: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)
        self.api_secret = api_secret

    def has_credentials(self) -> bool:
        if not self.requires_key:
            return True
        cid = self.api_key
        csec = self.api_secret
        if cid and csec:
            return True
        if not cid:
            cid = _env("CENSYS_API_ID")
        if not csec:
            csec = _env("CENSYS_API_SECRET")
        return bool(cid and csec)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        cid = self.api_key or _env("CENSYS_API_ID") or ""
        csec = self.api_secret or _env("CENSYS_API_SECRET") or ""
        if not cid or not csec:
            return []
        url = (
            "https://search.censys.io/api/v2/hosts/"
            + _quote(target)
        )
        token = base64.b64encode(f"{cid}:{csec}".encode("utf-8")).decode("ascii")
        body = self.http_get(url, timeout=8.0,
                             headers={"Authorization": f"Basic {token}"})
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        out: List[PassiveFinding] = []
        now = self.now_iso()
        hosts = (data.get("result") or {}).get("hits") or []
        for hit in hosts[: int(budget)]:
            ip = str(hit.get("ip") or target)
            services = hit.get("services") or []
            for svc in services:
                port = svc.get("port")
                if port is None:
                    continue
                out.append(PassiveFinding(
                    kind="ip",
                    value=f"{ip}:{port}",
                    source=self.name,
                    confidence=0.75,
                    seen_at=now,
                    extra={"service": str(svc.get("service_name") or "")},
                ))
        return out


def _env(name: str) -> str:
    import os
    return os.environ.get(name, "")


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["CensysModule"]
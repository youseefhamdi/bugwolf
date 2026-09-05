"""Google dork pattern templates.

This module does NOT actually hit Google (ToS).  Instead it returns the
*dork strings themselves* as ``PassiveFinding`` records of kind
``endpoint`` with confidence 0.0 — they are templates the operator can
paste into a search engine manually.

No API key required.  Always returns a deterministic list.
"""

from __future__ import annotations

from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


_DORKS = (
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} ext:sql | ext:sqlite | ext:db',
    'site:{target} ext:env | ext:yml | ext:yaml | ext:json "api_key"',
    'site:{target} intitle:"index of"',
    'site:{target} inurl:wp-admin',
    'site:{target} inurl:phpmyadmin',
    'site:{target} inurl:.git',
    'site:{target} inurl:.env',
    'site:{target} "password" OR "passwd" OR "secret"',
    'site:{target} "AWS_ACCESS_KEY" OR "AWS_SECRET"',
    'site:{target} "-----BEGIN PRIVATE KEY-----"',
    'site:{target} "Authorization: Bearer"',
    'site:{target} inurl:api | inurl:v1 | inurl:v2 | inurl:v3',
    'site:{target} inurl:graphql',
    'site:{target} inurl:swagger | inurl:openapi',
    'site:{target} "staging" OR "dev" OR "internal"',
    'site:{target} "DB_PASSWORD" OR "DATABASE_URL"',
    'site:{target} "BEGIN RSA PRIVATE KEY"',
    'site:{target} filetype:log "error"',
    'site:{target} inurl:backup | inurl:dump',
    'site:{target} inurl:web.config | inurl:app.config',
    'site:{target} "X-Api-Key" OR "X-Auth-Token"',
    'site:{target} inurl:"/api/" ext:json',
    'site:{target} "client_secret" OR "client_id"',
)


class GoogleDorksModule(PassiveModule):
    name = "google_dorks"
    kind = "endpoint"
    requires_key = False
    env_var = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        now = self.now_iso()
        out: List[PassiveFinding] = []
        for template in _DORKS[: int(budget)]:
            out.append(PassiveFinding(
                kind="endpoint",
                value=template.format(target=target),
                source=self.name,
                confidence=0.0,
                seen_at=now,
                extra={"template": template},
            ))
        return out


__all__ = ["GoogleDorksModule"]
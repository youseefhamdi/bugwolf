"""GraphQL denial-of-service scanner.

Probes three classic GraphQL DoS surfaces:

  * aliasing (many aliases to one resolver)
  * circular fragment expansion
  * deeply nested field selection
  * batched queries
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_ALIAS_BOMB = (
    "{ a0:__typename a1:__typename a2:__typename a3:__typename "
    "a4:__typename a5:__typename a6:__typename a7:__typename "
    "a8:__typename a9:__typename a10:__typename a11:__typename "
    "a12:__typename a13:__typename a14:__typename a15:__typename "
    "a16:__typename a17:__typename a18:__typename a19:__typename "
    "a20:__typename a21:__typename a22:__typename a23:__typename "
    "a24:__typename a25:__typename a26:__typename a27:__typename "
    "a28:__typename a29:__typename a30:__typename a31:__typename }"
)
_CIRCULAR_FRAGMENT = (
    "query { user { ...F } } fragment F on User { friends { ...F } }"
)
_DEEPLY_NESTED = (
    "{ a { b { c { d { e { f { g { h { i { j "
    "{ k { l { m { n { o { __typename } } } } } } } "
    "} } } } } } } } }"
)


class GraphQLDoSScanner(Scanner):
    name = "graphql-dos"
    bug_class = "graphql-dos"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        _ALIAS_BOMB,
        _CIRCULAR_FRAGMENT,
        _DEEPLY_NESTED,
        '[{"query":"{__typename}"},{"query":"{__typename}"}]',
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("graphql-dos: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={"Content-Type": "application/json"},
                    body=payload,
                )
            except Exception as exc:
                logger.debug("gql-dos: transport error: %s", exc)
                continue
            status = resp.get("status")
            rbody = resp.get("body", "") or ""
            if status in (200, 502, 503) and len(rbody) > 200:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="GraphQL DoS payload accepted with large response",
                    severity="high",
                    detail={"payload": payload[:160],
                            "status": status,
                            "response_len": len(rbody)},
                ))
        return findings


__all__ = ["GraphQLDoSScanner"]
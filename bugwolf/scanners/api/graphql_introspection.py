"""GraphQL introspection scanner.

Probes whether the GraphQL endpoint has introspection enabled in
production.  When enabled, an attacker can fully enumerate the schema
and pivot to IDOR / authZ / query-cost attacks.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_INTROSPECTION_QUERY = (
    '{"query":"{ __schema { queryType { name } '
    'mutationType { name } types { name kind } } }"}'
)


class GraphQLIntrospectionScanner(Scanner):
    name = "graphql-introspection"
    bug_class = "graphql-introspection"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        _INTROSPECTION_QUERY,
        '{"query":"{ __schema { types { name } } }"}',
        '{"query":"query IntrospectionQuery { __schema { types { name } } }"}',
        '{"query":"mutation { __typename }"}',
        '{"query":"{ __type(name:\"User\") { fields { name } } }"}',
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "graphql-introspection: transport is None; returning []"
            )
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
                logger.debug("gql-intro: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            blob = rbody.lower()
            if "__schema" in blob and ("types" in blob or "querytype" in blob):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="GraphQL introspection enabled in production",
                    severity="medium",
                    detail={"payload": payload,
                            "snippet": rbody[:160],
                            "status": resp.get("status")},
                ))
                break
            try:
                j = json.loads(rbody)
            except Exception:
                continue
            data = j.get("data") or {}
            if isinstance(data, dict) and "__schema" in data:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="GraphQL __schema returned via JSON data field",
                    severity="medium",
                    detail={"payload": payload,
                            "status": resp.get("status")},
                ))
                break
        return findings


__all__ = ["GraphQLIntrospectionScanner"]
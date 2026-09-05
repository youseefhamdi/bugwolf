"""GraphQL scanner — shim re-export of tools.domains.api.graphql_batch_analyzer.

This is a thin adapter: it does NOT duplicate the GraphQL batching / DoS /
introspection logic.  It imports the existing ``analyze()`` function and
maps its :class:`GraphqlPlan` records into Phase 1.5 :class:`LiveFinding`.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.api.graphql_batch_analyzer import analyze as _analyze_graphql


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_BY_CATEGORY = {
    "batching": "high",
    "field_duplication": "high",
    "fragment_depth": "medium",
    "introspection": "medium",
    "ssrf": "high",
}


class GraphqlScanner(Scanner):
    name = "graphql"
    description = "GraphQL batching, aliasing, depth, introspection, SSRF abuse plans"
    bug_class = "graphql"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return any(k in target for k in ("introspection", "query", "endpoint"))

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        introspection = target.get("introspection")
        query = target.get("query")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "POST")
        analysis = _analyze_graphql(
            target.get("name", "target"),
            introspection=introspection,
            query=query,
            endpoint=endpoint,
        )
        out: List[LiveFinding] = []
        for plan in analysis.plans:
            cat = str(plan.category)
            sev = _SEVERITY_BY_CATEGORY.get(cat, self.default_severity)
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"GraphQL plan: {plan.description[:120]}",
                reproducer=str(plan.validation_steps[0]) if plan.validation_steps else "",
                remediation="Apply cost analysis / depth / alias limits; disable introspection in production.",
                payload_id="graphql-" + cat + "-" + plan.plan_id,
                extra={"category": cat, "plan_id": plan.plan_id},
            ))
        return out


__all__ = ["GraphqlScanner"]

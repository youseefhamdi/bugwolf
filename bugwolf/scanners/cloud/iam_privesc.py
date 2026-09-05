"""Cloud IAM privesc scanner — shim re-export of tools.domains.cloud.iam_privesc_graph.

This is a thin adapter: it does NOT duplicate the IAM escalation-graph logic.
It imports the existing ``analyze()`` function and maps :class:`EscalationPath`
records into Phase 1.5 :class:`LiveFinding`.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.cloud.iam_privesc_graph import analyze as _analyze_iam


SCHEMA = "bugwolf-scanner-v1"


class IAMPrivescScanner(Scanner):
    name = "iam_privesc"
    description = "Cloud IAM privilege escalation graph (AWS/GCP/Azure policy closure)"
    bug_class = "iam_privesc"
    default_severity = "critical"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "policy" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        policy = target.get("policy")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        if policy is None:
            return []
        analysis = _analyze_iam(target.get("name", "target"), policy)
        out: List[LiveFinding] = []
        for hop in analysis.directly_reachable:
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity="high",
                endpoint=endpoint,
                method=method,
                evidence=f"directly reachable: {hop.method_name} ({hop.family}) -> {hop.gained}",
                reproducer="grant the unlocking_actions in the operator policy",
                remediation="Drop unused privilege; enforce least privilege; deny policy-write actions to non-admin principals.",
                payload_id="iam-" + hop.method_id,
                extra={"family": hop.family, "gained": hop.gained},
            ))
        for path in analysis.paths:
            sev = "critical" if analysis.admin_reachable else "high"
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"escalation path {path.path_id}: {' -> '.join(h.method_name for h in path.hops)}",
                reproducer=f"{len(path.hops)} hops ending in {path.end_capability}",
                remediation="Tighten the chain: deny intermediate steps or remove transitive grant capability.",
                payload_id="iam-path-" + path.path_id,
                extra={"end_capability": path.end_capability, "hops": len(path.hops)},
            ))
        return out


__all__ = ["IAMPrivescScanner", "export_cloud_scanner"]


def export_cloud_scanner():
    """Convenience export mirroring the tools.domains shim."""
    return IAMPrivescScanner()

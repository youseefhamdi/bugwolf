"""Mobile deep-link scanner — shim re-export of tools.domains.mobile.deep_link_analyzer.

Thin adapter; the planning logic stays in tools.domains.mobile.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.mobile.deep_link_analyzer import analyze as _analyze_deeplink


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_BY_CATEGORY = {
    "link_hijacking": "high",
    "sensitive_navigation": "high",
    "intent_url": "medium",
    "scheme_confusion": "high",
}


class DeepLinkScanner(Scanner):
    name = "deep_link"
    description = "Mobile deep-link / universal-link attack surface planner"
    bug_class = "deep_link"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return any(k in target for k in ("manifest", "plist"))

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        manifest = target.get("manifest")
        plist = target.get("plist")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        analysis = _analyze_deeplink(target.get("name", "target"),
                                     manifest=manifest, plist=plist)
        out: List[LiveFinding] = []
        for plan in analysis.plans:
            sev = _SEVERITY_BY_CATEGORY.get(plan.category, self.default_severity)
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"deep-link plan: {plan.rationale[:120]}",
                reproducer=f"platform={plan.platform} category={plan.category}",
                remediation="Validate intent origins; pin universal-link associations; require signature/host verification on deep links.",
                payload_id="deeplink-" + plan.category + "-" + plan.plan_id,
                extra={"platform": plan.platform, "category": plan.category},
            ))
        return out


__all__ = ["DeepLinkScanner", "export_mobile_scanner"]


def export_mobile_scanner():
    return DeepLinkScanner()

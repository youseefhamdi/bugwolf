"""OAuth/OIDC scanner — shim re-export of tools.domains.auth.oauth_flow_analyzer.

This module is a thin adapter: it does NOT duplicate the OAuth flow analysis
logic.  It imports the existing ``analyze()`` function and converts its
:class:`OAuthPlan` dataclasses into Phase 1.5 :class:`LiveFinding` records.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.auth.oauth_flow_analyzer import analyze as _analyze_oauth
from tools.domains.auth.oauth_flow_analyzer import OAuthFlow


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_BY_CATEGORY = {
    "redirect_uri": "high",
    "state_csrf": "high",
    "pkce": "medium",
    "token_in_url": "high",
    "coat": "high",
    "scope_escalation": "medium",
}


class OAuthScanner(Scanner):
    name = "oauth"
    description = "OAuth/OIDC attack surface (redirect_uri, state, PKCE, scope)"
    bug_class = "oauth"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "flows" in target and isinstance(target.get("flows"), list)

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        flows_raw = target.get("flows") or []
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        flows: List[OAuthFlow] = []
        for raw in flows_raw:
            if isinstance(raw, OAuthFlow):
                flows.append(raw)
                continue
            if isinstance(raw, dict):
                flows.append(OAuthFlow(
                    authorize_url=raw.get("authorize_url", ""),
                    token_url=raw.get("token_url", ""),
                    callback_url=raw.get("callback_url", ""),
                    client_id=raw.get("client_id", ""),
                    response_type=raw.get("response_type", ""),
                    scope=raw.get("scope", ""),
                    params=dict(raw.get("params") or {}),
                ))
        if not flows:
            return []
        analysis = _analyze_oauth(target.get("name", "target"), flows)
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
                evidence=f"OAuth plan: {plan.description[:120]}",
                reproducer=str(plan.validation_steps[0]) if plan.validation_steps else "",
                remediation="Strict redirect_uri allow-list; mandatory state + PKCE; never echo arbitrary params back.",
                payload_id="oauth-" + cat + "-" + plan.plan_id,
                extra={"category": cat, "plan_id": plan.plan_id},
            ))
        return out


def export_oauth_scanner():
    """Phase 1.5 export shim — returns a fresh OAuthScanner instance."""
    return OAuthScanner()


__all__ = ["OAuthScanner", "export_oauth_scanner"]

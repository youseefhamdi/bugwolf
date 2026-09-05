"""LLM tool-auth scanner — shim re-export of tools.domains.llm.agentic_tool_auth.

Thin adapter; the planning logic stays in tools.domains.llm.agentic_tool_auth.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.llm.agentic_tool_auth import analyze as _analyze_tool_auth


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_BY_OWASP = {
    "ASI01": "high",
    "ASI02": "high",
    "ASI03": "high",
    "ASI04": "medium",
    "ASI05": "medium",
    "ASI06": "medium",
}


class ToolAuthScanner(Scanner):
    name = "tool_auth"
    description = "Agentic tool-call authentication & authorisation weakness planner"
    bug_class = "tool_auth"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return any(k in target for k in ("inventory", "code", "file_name"))

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        inventory = target.get("inventory")
        code = target.get("code")
        file_name = target.get("file_name", "")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        analysis = _analyze_tool_auth(
            target.get("name", "target"),
            inventory=inventory, code=code, file_name=file_name,
        )
        out: List[LiveFinding] = []
        for plan in analysis.plans:
            sev = _SEVERITY_BY_OWASP.get(plan.owasp_asi, self.default_severity)
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"tool-auth plan: {plan.rationale[:120]}",
                reproducer=f"tool={plan.tool} args={plan.attacker_args}",
                remediation="Confirm identity on every privileged tool call; sandbox destructive tools; require human approval for side-effecting actions.",
                payload_id="toolauth-" + plan.owasp_asi + "-" + plan.plan_id,
                extra={"owasp_asi": plan.owasp_asi, "tool": plan.tool, "category": plan.category},
            ))
        return out


__all__ = ["ToolAuthScanner", "export_llm_scanner"]


def export_llm_scanner():
    return ToolAuthScanner()

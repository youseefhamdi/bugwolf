"""Employee OSINT scanner.

Probes a small list of common corporate roles against a target page
and flags findings when a candidate response carries a recognisable
``BugWolfOSINT`` marker.  No real LinkedIn / GitHub scraping is done.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_ROLES: Tuple[str, ...] = (
    "ceo", "cto", "ciso", "cio", "vp-engineering",
    "vp-security", "head-of-security", "security-engineer",
    "developer", "devops", "sre", "architect",
)


class EmployeeOSINTScanner(Scanner):
    name = "employee-osint"
    bug_class = "osint-exposure"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = _ROLES

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("employee-osint: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for role in _ROLES:
            try:
                resp: Dict[str, Any] = transport(
                    "GET",
                    f"{target.rstrip('/')}/about/team/{role}",
                )
            except Exception as exc:
                logger.debug("osint: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            if resp.get("status") == 200 and "BugWolfOSINT" in rbody:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"employee page discloses role {role!r}",
                    severity="informational",
                    detail={"role": role,
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["EmployeeOSINTScanner"]
"""Email harvesting scanner.

Scrapes the supplied page for email-shaped strings (``local@domain``).
Findings are tagged as informational because the actual exposure risk
depends on whether the email is harvested from public web pages or
private documents.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class EmailHarvestScanner(Scanner):
    name = "email-harvest"
    bug_class = "email-exposure"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = ("harvest",)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("email-harvest: transport is None; returning []")
            return []
        try:
            resp: Dict[str, Any] = transport("GET", target)
        except Exception as exc:
            logger.debug("email: transport error: %s", exc)
            return []
        body = resp.get("body", "") or ""
        emails = sorted(set(_EMAIL_RE.findall(body)))
        findings: List[Finding] = []
        for e in emails[:50]:
            findings.append(make_finding(
                self,
                target=target,
                evidence=f"email exposed: {e}",
                severity="informational",
                detail={"email": e},
            ))
        return findings


__all__ = ["EmailHarvestScanner"]
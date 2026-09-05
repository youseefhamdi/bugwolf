"""Service-fingerprinting scanner.

Looks for version disclosures in the ``Server`` and ``X-Powered-By``
response headers.  This is purely a passive probe — it never sends a
crafted payload.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_DISCLOSURE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Server", "Apache"),
    ("Server", "nginx"),
    ("Server", "IIS"),
    ("Server", "lighttpd"),
    ("X-Powered-By", "PHP"),
    ("X-Powered-By", "ASP.NET"),
    ("X-Powered-By", "Express"),
    ("X-AspNet-Version", ""),
    ("X-AspNetMvc-Version", ""),
)


class ServiceDetectScanner(Scanner):
    name = "service-detect"
    bug_class = "version-disclosure"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = ("probe",)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("service-detect: transport is None; returning []")
            return []
        try:
            resp: Dict[str, Any] = transport("GET", target)
        except Exception as exc:
            logger.debug("service-detect: transport error: %s", exc)
            return []
        rheaders = resp.get("headers", {}) or {}
        findings: List[Finding] = []
        for header, token in _DISCLOSURE_PATTERNS:
            for k, v in rheaders.items():
                if k.lower() != header.lower():
                    continue
                value = str(v)
                if not token or token in value:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=(f"{k}: {value[:80]}"),
                        severity="informational",
                        detail={"header": k, "value": value,
                                "status": resp.get("status")},
                    ))
        return findings


__all__ = ["ServiceDetectScanner"]
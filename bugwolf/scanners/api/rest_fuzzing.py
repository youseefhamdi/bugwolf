"""REST API fuzzer.

Sends a small corpus of mutated verbs / paths / payloads against a
REST endpoint looking for unexpected 5xx / 200 / 302 responses that
indicate a parser-level bug.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class RESTFuzzingScanner(Scanner):
    name = "rest-fuzzing"
    bug_class = "rest-fuzzing"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        "%00",
        "%2e%2e",
        "%ef%bc%8f",      # fullwidth solidus
        "../../etc/passwd",
        "0",
        "-1",
        "99999999",
        "null",
        "undefined",
        "true",
        "false",
        "[]",
        "{}",
        "1 OR 1=1",
        "' OR '1'='1",
        "<script>BugWolfRESTFuzz</script>",
        "${7*7}",
        "{{7*7}}",
    )

    INTERESTING_STATUSES = (200, 201, 204, 301, 302, 500, 502, 503)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("rest-fuzzing: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            url = f"{target.rstrip('?').rstrip('&')}?q={payload}"
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                try:
                    resp: Dict[str, Any] = transport(
                        method, url,
                        headers={"Content-Type": "application/json"},
                        body=payload,
                    )
                except Exception as exc:
                    logger.debug("rest-fuzz: transport error: %s", exc)
                    continue
                status = resp.get("status")
                if status in self.INTERESTING_STATUSES:
                    marker_present = (
                        "BugWolfRESTFuzz" in (resp.get("body", "") or "")
                        or "${7*7}" in (resp.get("body", "") or "")
                        or "{{7*7}}" in (resp.get("body", "") or "")
                    )
                    if marker_present or status in (500, 502, 503):
                        findings.append(make_finding(
                            self,
                            target=target,
                            evidence=(f"{method} {payload!r} → {status} "
                                      "with marker"),
                            severity="medium",
                            detail={"method": method,
                                    "payload": payload,
                                    "status": status,
                                    "snippet": (resp.get("body", "") or "")[:160]},
                        ))
        return findings


__all__ = ["RESTFuzzingScanner"]
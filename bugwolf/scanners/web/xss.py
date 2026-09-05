"""Reflected/stored/DOM XSS scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


def _pid(payload: str) -> str:
    return "xss-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class XSSScanner(Scanner):
    name = "xss"
    description = "Reflected/stored/DOM XSS via payload reflection"
    bug_class = "xss"
    default_severity = "high"

    PAYLOADS = (
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "'><svg/onload=alert(1)//",
    )

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        for payload in self.PAYLOADS:
            try:
                if method == "GET":
                    resp = transport("GET", url,
                                     headers={"X-Test-Payload": payload},
                                     body=None)
                else:
                    resp = transport(method, url,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     body="q=" + payload)
            except Exception:
                continue
            body = (resp.get("body") or "") if isinstance(resp, dict) else ""
            if payload in body:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"payload reflected verbatim ({len(payload)} chars)",
                    reproducer=f"{method} {url}  payload={payload[:60]!r}",
                    remediation="HTML-encode user input on output; set CSP with no unsafe-inline.",
                    payload_id=_pid(payload),
                    extra={"status": resp.get("status"), "snippet": body[:120]},
                ))
        return findings


__all__ = ["XSSScanner"]

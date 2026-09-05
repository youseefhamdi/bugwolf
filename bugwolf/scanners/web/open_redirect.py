"""Open redirect scanner with 11 bypass techniques."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


OPEN_REDIRECT_PAYLOADS = (
    "https://evil.example/",
    "//evil.example/",
    "https:evil.example",
    "/\\evil.example",
    "https://evil.example#@target.example/",
    "https://target.example@evil.example/",
    "https://evil.example/?target=target.example",
    "javascript:alert(1)",
    "https://evil.example%00target.example",
    "https://evil.example%2ftarget.example",
    "https://evil.example:80@target.example/",
)


def _pid(payload: str) -> str:
    return "openredirect-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class OpenRedirectScanner(Scanner):
    name = "open_redirect"
    description = "Open redirect via 11 protocol/host bypass techniques"
    bug_class = "open_redirect"
    default_severity = "medium"

    PAYLOADS = OPEN_REDIRECT_PAYLOADS

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        param = target.get("param", "next")
        for payload in OPEN_REDIRECT_PAYLOADS:
            sep = "&" if "?" in url else "?"
            target_url = f"{url}{sep}{param}={payload}"
            try:
                resp = transport(method, target_url, headers=None, body=None)
            except Exception:
                continue
            rheaders = (resp.get("headers") or {}) if isinstance(resp, dict) else {}
            rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
            status = resp.get("status") if isinstance(resp, dict) else None
            location = str(rheaders.get("Location") or rheaders.get("location") or "")
            if "evil.example" in location or "evil.example" in rbody or status in (301, 302, 303, 307, 308):
                if "evil.example" in location or "evil.example" in rbody:
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=url,
                        method=method,
                        evidence=f"redirect to {payload[:64]!r}",
                        reproducer=f"{method} {target_url}",
                        remediation="Validate redirect targets against an allow-list of hostnames; reject protocol-relative URLs.",
                        payload_id=_pid(payload),
                        extra={"location": location[:120], "status": status},
                    ))
        return findings


__all__ = ["OpenRedirectScanner", "OPEN_REDIRECT_PAYLOADS"]

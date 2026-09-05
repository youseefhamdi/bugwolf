"""Server-Side Template Injection (SSTI) scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


SSTI_PAYLOADS = (
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{self.__class__}}",
    "{{config}}",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{request.environ}}",
    "{{settings.SECRET_KEY}}",
)


def _pid(payload: str) -> str:
    return "ssti-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class SSTIScanner(Scanner):
    name = "ssti"
    description = "Server-side template injection (Jinja2/Twig/ERB/FreeMarker)"
    bug_class = "ssti"
    default_severity = "critical"

    PAYLOADS = SSTI_PAYLOADS

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        for payload in SSTI_PAYLOADS:
            try:
                if method == "GET":
                    resp = transport("GET", url,
                                     headers={"X-Test-Payload": payload},
                                     body=None)
                else:
                    resp = transport(method, url,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     body="name=" + payload)
            except Exception:
                continue
            body = (resp.get("body") or "") if isinstance(resp, dict) else ""
            if payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"):
                if "49" in body:
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=url,
                        method=method,
                        evidence=f"arithmetic probe evaluated: {payload[:32]!r} -> 49",
                        reproducer=f"{method} {url}  payload={payload[:60]!r}",
                        remediation="Never render user input as a template; sandbox or strip metacharacters.",
                        payload_id=_pid(payload),
                        extra={"status": resp.get("status"), "indicator": "49"},
                    ))
            else:
                triggers = ("SECRET_KEY", "<class", "'__class__'", "settings", "<Config",
                            "object at 0x", "module '")
                if any(t in body for t in triggers):
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=url,
                        method=method,
                        evidence=f"template introspection probe leaked internals ({payload[:32]!r})",
                        reproducer=f"{method} {url}  payload={payload[:60]!r}",
                        remediation="Never render user input as a template; sandbox or strip metacharacters.",
                        payload_id=_pid(payload),
                        extra={"status": resp.get("status"), "snippet": body[:120]},
                    ))
        return findings


__all__ = ["SSTIScanner", "SSTI_PAYLOADS"]

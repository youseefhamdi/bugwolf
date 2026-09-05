"""Cross-Origin Resource Sharing (CORS) misconfiguration scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


ORIGIN_PROBES = (
    "https://evil.example",
    "null",
    "https://target.example",
    "https://sub.target.example",
)


def _pid(origin: str, allow_cred: bool) -> str:
    raw = origin + ("|cred" if allow_cred else "|nocred")
    return "cors-" + hashlib.sha256(raw.encode()).hexdigest()[:10]


class CORSScanner(Scanner):
    name = "cors"
    description = "CORS misconfiguration (wildcard origin / null / credentials)"
    bug_class = "cors"
    default_severity = "medium"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        for origin in ORIGIN_PROBES:
            try:
                resp = transport(method, url,
                                 headers={"Origin": origin}, body=None)
            except Exception:
                continue
            rheaders = (resp.get("headers") or {}) if isinstance(resp, dict) else {}
            acao = str(rheaders.get("Access-Control-Allow-Origin") or
                       rheaders.get("access-control-allow-origin") or "")
            acac = str(rheaders.get("Access-Control-Allow-Credentials") or
                       rheaders.get("access-control-allow-credentials") or "")
            acam = str(rheaders.get("Access-Control-Allow-Methods") or "")
            if acao == "*" and acac.lower() == "true":
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity="high",
                    endpoint=url,
                    method=method,
                    evidence=f"ACAO=* with ACAC=true for origin {origin!r}",
                    reproducer=f"{method} {url}  Origin: {origin}",
                    remediation="Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Echo an allow-listed origin instead.",
                    payload_id=_pid(origin, True),
                    extra={"acao": acao, "acac": acac},
                ))
            elif acao == origin and origin and "*" not in origin:
                if acac.lower() == "true" and origin not in ("", "null"):
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity="high",
                        endpoint=url,
                        method=method,
                        evidence=f"ACAO echoes arbitrary origin {origin!r} with ACAC=true",
                        reproducer=f"{method} {url}  Origin: {origin}",
                        remediation="Compare the request Origin against a strict allow-list before echoing it back; never combine with credentials blindly.",
                        payload_id=_pid("echo-" + origin, True),
                        extra={"acao": acao, "acac": acac},
                    ))
            if acao == "null":
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity="high",
                    endpoint=url,
                    method=method,
                    evidence="ACAO reflects 'null' origin (sandbox escape)",
                    reproducer=f"{method} {url}  Origin: null",
                    remediation="Reject 'null' origin; never echo it back.",
                    payload_id=_pid("null", False),
                    extra={"acao": acao},
                ))
            if acao == "*" and acam and "*" not in acam:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"ACAO=* but ACAM allows privileged methods ({acam[:60]})",
                    reproducer=f"{method} {url}  Origin: {origin}",
                    remediation="Tighten Access-Control-Allow-Methods to the verbs the endpoint actually needs.",
                    payload_id=_pid(origin + "|methods", False),
                    extra={"acam": acam[:120]},
                ))
        return findings


__all__ = ["CORSScanner"]

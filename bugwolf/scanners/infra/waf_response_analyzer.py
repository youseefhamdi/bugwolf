"""WAF response analyser — classifies block pages by status / body shape."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


BLOCK_PATTERNS = (
    {"vendor": "Cloudflare", "patterns": ("Attention Required! | Cloudflare",
                                          "cf-ray", "cf-browser-hello")},
    {"vendor": "Akamai",     "patterns": ("Access Denied", "Reference ID",
                                          "akamai", "edgekey")},
    {"vendor": "AWS WAF",    "patterns": ("Request blocked", "AWS WAF",
                                          "x-amzn-requestid")},
    {"vendor": "Imperva",    "patterns": ("Access Denied", "incapsula",
                                          "incident id", "_Incapsula_Resource")},
    {"vendor": "ModSecurity","patterns": ("ModSecurity", "OWASP CRS",
                                          "blocked by mod_security")},
    {"vendor": "Sucuri",     "patterns": ("Access Denied - Sucuri",
                                          "sucuri.net")},
)


def _pid(vendor: str) -> str:
    return "waf-resp-" + hashlib.sha256(vendor.encode()).hexdigest()[:10]


class WAFResponseAnalyzerScanner(Scanner):
    name = "waf_response_analyzer"
    description = "Classifies WAF block pages by status code, body shape, and headers"
    bug_class = "waf_response"
    default_severity = "low"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        try:
            resp = transport(method, url,
                             headers={"X-Test-Payload": "<script>alert(1)</script>"},
                             body="q=test")
        except Exception:
            resp = None
        if not isinstance(resp, dict):
            return findings
        rbody = (resp.get("body") or "")
        rheaders = (resp.get("headers") or {})
        status = resp.get("status")
        if status and status < 400:
            return findings
        header_blob = "\n".join(f"{k}: {v}" for k, v in rheaders.items())
        blob = (rbody + "\n" + header_blob).lower()
        for fp in BLOCK_PATTERNS:
            hits = [p for p in fp["patterns"] if p.lower() in blob]
            if hits and status in (403, 406, 419, 429, 503, 999):
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"WAF block page from {fp['vendor']} (status {status}, "
                             f"matched: {', '.join(hits[:3])})",
                    reproducer=f"{method} {url}",
                    remediation="Tune payload encoder to the matching vendor signature; rotate bypass corpus.",
                    payload_id=_pid(fp["vendor"]),
                    extra={"vendor": fp["vendor"], "status": status, "matches": hits},
                ))
        return findings


__all__ = ["WAFResponseAnalyzerScanner", "BLOCK_PATTERNS"]

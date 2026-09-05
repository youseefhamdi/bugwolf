"""Cross-Site Request Forgery (CSRF) scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


def _pid(label: str) -> str:
    return "csrf-" + hashlib.sha256(label.encode()).hexdigest()[:10]


class CSRFScanner(Scanner):
    name = "csrf"
    description = "Cross-site request forgery (CSRF) via header / token presence"
    bug_class = "csrf"
    default_severity = "medium"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "POST")).upper()

        try:
            resp = transport("OPTIONS", url, headers=None, body=None)
        except Exception:
            resp = None
        if isinstance(resp, dict):
            allow = str(resp.get("headers", {}).get("Allow") or
                        resp.get("headers", {}).get("allow") or "")
            if method in allow and method != "GET":
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"OPTIONS Allow header exposes state-changing {method} ({allow})",
                    reproducer=f"OPTIONS {url}",
                    remediation="Use SameSite=Lax/Strict cookies; require CSRF tokens on state-changing methods.",
                    payload_id=_pid("options-allow"),
                    extra={"allow": allow},
                ))

        try:
            resp = transport(method, url, headers=None, body="csrf=1")
        except Exception:
            return findings
        rheaders = (resp.get("headers") or {}) if isinstance(resp, dict) else {}
        rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
        status = resp.get("status") if isinstance(resp, dict) else None
        same_site = (rheaders.get("Set-Cookie") or rheaders.get("set-cookie") or "")
        same_site_marker = ""
        for chunk in same_site.split(","):
            if "SameSite" in chunk or "samesite" in chunk:
                same_site_marker = chunk.strip()
        csrf_token_present = "csrf" in rheaders or "x-csrf" in str(rheaders).lower()
        if status in (200, 201, 204) and "csrf=1" in (rbody or "") and not csrf_token_present:
            findings.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=self.default_severity,
                endpoint=url,
                method=method,
                evidence=f"state-changing request accepted without CSRF token (status {status})",
                reproducer=f"{method} {url}  body=csrf=1",
                remediation="Require a per-session CSRF token on every state-changing endpoint; reject requests missing or carrying an invalid token.",
                payload_id=_pid("no-token"),
                extra={"status": status},
            ))
        if not same_site_marker:
            findings.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity="low",
                endpoint=url,
                method=method,
                evidence="Set-Cookie missing SameSite attribute",
                reproducer=f"{method} {url}",
                remediation="Set SameSite=Lax (or Strict) on every authentication / session cookie.",
                payload_id=_pid("samesite"),
                extra={"set_cookie": same_site[:120]},
            ))
        return findings


__all__ = ["CSRFScanner"]

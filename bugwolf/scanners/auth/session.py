"""Session-management scanner (fixation, hijack, weak cookie flags)."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


_COOKIE_TOKEN_RE = re.compile(
    r"(?:SESSION|TOKEN|SID|JSESSIONID|PHPSESSID|auth_token|access_token)\s*=\s*([^;,\s]+)",
    re.IGNORECASE,
)


def _pid(label: str) -> str:
    return "session-" + hashlib.sha256(label.encode()).hexdigest()[:10]


class SessionScanner(Scanner):
    name = "session"
    description = "Session fixation, missing cookie flags, weak token entropy"
    bug_class = "session"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        findings: List[LiveFinding] = []

        try:
            pre = transport(method, url, headers=None, body=None)
        except Exception:
            pre = None
        if not isinstance(pre, dict):
            return findings
        pre_set_cookie = str(pre.get("headers", {}).get("Set-Cookie") or
                             pre.get("headers", {}).get("set-cookie") or "")

        try:
            post = transport(method, url, headers=None, body=None)
        except Exception:
            post = None
        if not isinstance(post, dict):
            return findings
        post_set_cookie = str(post.get("headers", {}).get("Set-Cookie") or
                              post.get("headers", {}).get("set-cookie") or "")

        def _flags(cookie: str) -> Dict[str, bool]:
            lower = cookie.lower()
            return {
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": "samesite" in lower,
            }

        for label, cookie_value in (("login", post_set_cookie),):
            if not cookie_value:
                continue
            flags = _flags(cookie_value)
            if not flags["secure"]:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence="session cookie missing Secure flag",
                    reproducer=f"{method} {url}",
                    remediation="Set Secure on every session cookie so it is never transmitted over plaintext HTTP.",
                    payload_id=_pid("secure"),
                    extra={"cookie": cookie_value[:120]},
                ))
            if not flags["httponly"]:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity="medium",
                    endpoint=url,
                    method=method,
                    evidence="session cookie missing HttpOnly flag",
                    reproducer=f"{method} {url}",
                    remediation="Set HttpOnly on every session cookie to block document.cookie access from JS.",
                    payload_id=_pid("httponly"),
                    extra={"cookie": cookie_value[:120]},
                ))
            if not flags["samesite"]:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity="medium",
                    endpoint=url,
                    method=method,
                    evidence="session cookie missing SameSite attribute",
                    reproducer=f"{method} {url}",
                    remediation="Set SameSite=Lax or Strict on session cookies to mitigate CSRF.",
                    payload_id=_pid("samesite"),
                    extra={"cookie": cookie_value[:120]},
                ))
            token_match = _COOKIE_TOKEN_RE.search(cookie_value)
            if token_match:
                token = token_match.group(1)
                if len(token) < 24:
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity="high",
                        endpoint=url,
                        method=method,
                        evidence=f"session token is only {len(token)} chars long (weak entropy)",
                        reproducer=f"{method} {url}",
                        remediation="Generate session tokens with at least 128 bits of entropy using a CSPRNG.",
                        payload_id=_pid("entropy"),
                        extra={"token_len": len(token)},
                    ))

        if pre_set_cookie and post_set_cookie and pre_set_cookie == post_set_cookie:
            findings.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity="high",
                endpoint=url,
                method=method,
                evidence="session id is not rotated across authentication boundary (fixation risk)",
                reproducer=f"pre and post {method} {url} returned identical Set-Cookie",
                remediation="Issue a brand-new session id immediately after login / privilege change and invalidate the previous one.",
                payload_id=_pid("rotation"),
                extra={"cookie": pre_set_cookie[:120]},
            ))
        return findings


__all__ = ["SessionScanner"]

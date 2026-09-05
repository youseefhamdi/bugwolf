"""Insecure Direct Object Reference (IDOR) scanner."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


def _pid(payload: str) -> str:
    return "idor-" + hashlib.sha256(payload.encode()).hexdigest()[:10]


class IDORScanner(Scanner):
    name = "idor"
    description = "Cross-user object access (IDOR) via numeric/UUID pivots"
    bug_class = "idor"
    default_severity = "high"

    NUMERIC_PIVOTS = (1, 2, 100, 9999, 0)
    UUID_PIVOTS = (
        "00000000-0000-0000-0000-000000000000",
        "deadbeef-dead-beef-dead-beefdeadbeef",
    )

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target and "victim_id" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        victim = str(target.get("victim_id", ""))
        attacker = str(target.get("attacker_id", "0"))
        baseline = self._fetch(method, url, victim, transport)
        if baseline is None:
            return findings
        baseline_body = baseline.get("body") or ""
        baseline_status = baseline.get("status")

        for pivot in list(self.NUMERIC_PIVOTS) + list(self.UUID_PIVOTS):
            resp = self._fetch(method, url, str(pivot), transport)
            if resp is None:
                continue
            body = resp.get("body") or ""
            status = resp.get("status")
            if status == baseline_status and body and body != baseline_body and victim not in body:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method=method,
                    evidence=f"object accessible with foreign id {pivot!r} (status {status})",
                    reproducer=f"{method} {url}  (replace {victim} with {pivot})",
                    remediation="Enforce per-object authorisation on every read/write; never trust client-supplied IDs.",
                    payload_id=_pid(str(pivot)),
                    extra={"victim": victim, "attacker": str(pivot), "status": status},
                ))
        return findings

    def _fetch(self, method: str, url: str, obj_id: str, transport):
        sep = "&" if "?" in url else "?"
        target_url = f"{url}{sep}id={obj_id}"
        try:
            return transport(method, target_url, headers=None, body=None)
        except Exception:
            return None


__all__ = ["IDORScanner"]

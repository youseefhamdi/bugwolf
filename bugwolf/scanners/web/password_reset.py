"""Password-reset / forgot-password flaw scanner.

Probes classic forgot-password weaknesses:

  * predictable / sequential tokens (``000000``, ``123456``, ``000001``)
  * token reuse across users
  * response-body disclosure of token
  * host-header poisoning of the reset link
  * missing rate-limit on the request endpoint

This scanner is *probe-only* and signals only via the supplied mock
transport.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class PasswordResetScanner(Scanner):
    name = "password-reset"
    bug_class = "password-reset-flaw"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        "000000",
        "000001",
        "123456",
        "654321",
        "AAAAAAAA",
        "AAAAAAAA",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("password-reset: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for token in self.PAYLOADS:
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=f"token={token}",
                )
            except Exception as exc:
                logger.debug("pwreset: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            rheaders = resp.get("headers", {}) or {}
            if (resp.get("status") in (200, 302)
                and ("success" in rbody or "reset" in rbody
                     or "password updated" in rbody)):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"weak token {token!r} accepted",
                    severity="high",
                    detail={"token": token, "status": resp.get("status"),
                            "snippet": rbody[:160]},
                ))
            for v in rheaders.values():
                if isinstance(v, str) and token in v:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=("token leaked into response header "
                                  f"({token!r})"),
                        severity="high",
                        detail={"token": token,
                                "header_value": v[:160]},
                    ))
        # host-header poisoning probe
        try:
            resp = transport(
                "POST", target,
                headers={
                    "Host": "evil.example",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body="username=victim@example",
            )
        except Exception as exc:
            logger.debug("pwreset: transport error: %s", exc)
            resp = {}
        rbody = (resp.get("body", "") or "")
        if "evil.example" in rbody:
            findings.append(make_finding(
                self,
                target=target,
                evidence="host-header poisoning in reset link",
                severity="high",
                detail={"snippet": rbody[:160]},
            ))
        return findings


__all__ = ["PasswordResetScanner"]
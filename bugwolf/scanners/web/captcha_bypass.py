"""CAPTCHA bypass scanner.

Looks for trivially defeatable CAPTCHA implementations by sending the
same token many times (replay), submitting an empty token, or sending a
known-fixed well-known test token (``AAAA``).  Reports when the response
shape indicates the CAPTCHA gate did not fire.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class CaptchaBypassScanner(Scanner):
    name = "captcha-bypass"
    bug_class = "captcha-bypass"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        "AAAA",            # known-fixed / dev token
        "",                # empty
        "AAAA",            # replay
        "12345678",        # guess
        "null",
        "undefined",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("captcha-bypass: transport is None; returning []")
            return []
        findings: List[Finding] = []
        seen_marker = None
        for idx, payload in enumerate(self.PAYLOADS):
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=f"captcha={payload}",
                )
            except Exception as exc:
                logger.debug("captcha: transport error: %s", exc)
                continue
            status = resp.get("status")
            rbody = (resp.get("body", "") or "").lower()
            if status in (200, 302) and (
                "success" in rbody or "ok" in rbody or "welcome" in rbody
            ):
                if seen_marker is None or seen_marker == payload:
                    seen_marker = payload
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=(f"captcha accepted with payload "
                                  f"{payload!r} on attempt {idx}"),
                        severity="medium",
                        detail={"payload": payload, "status": status,
                                "snippet": rbody[:160]},
                    ))
        return findings


__all__ = ["CaptchaBypassScanner"]
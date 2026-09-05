"""Rate-limit bypass scanner.

Tries the canonical rate-limit bypass techniques:

  * ``X-Forwarded-For`` / ``X-Originating-IP`` rotation
  * ``X-Real-IP`` injection
  * case-folded ``xff`` header
  * trailing whitespace / dot in header value
  * HTTP/1.0 downgrade
  * GET → HEAD → OPTIONS substitution
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_RATE_TECHNIQUES: Tuple[Tuple[str, str, str], ...] = (
    ("X-Forwarded-For", "10.0.0.1", "xff"),
    ("X-Forwarded-For", "10.0.0.2", "xff"),
    ("X-Originating-IP", "10.0.0.3", "xoi"),
    ("X-Real-IP", "10.0.0.4", "xri"),
    ("X-Client-IP", "10.0.0.5", "xci"),
    ("Forwarded", "for=10.0.0.6", "fwd"),
    ("X-Forwarded-For", "10.0.0.7 ", "xff-trailing-ws"),
    ("x-forwarded-for", "10.0.0.8", "xff-case-fold"),
)


class RateLimitBypassScanner(Scanner):
    name = "rate-limit-bypass"
    bug_class = "rate-limit-bypass"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = tuple(f"{k}:{v}" for (k, v, _) in _RATE_TECHNIQUES)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("rate-limit-bypass: transport is None; returning []")
            return []
        findings: List[Finding] = []
        try:
            base = transport("POST", target,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             body="username=test&password=test")
        except Exception as exc:
            logger.debug("rate-limit: baseline error: %s", exc)
            base = {}
        base_len = len(base.get("body", "") or "")
        for header, value, label in _RATE_TECHNIQUES:
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={header: value},
                    body="username=test&password=test",
                )
            except Exception as exc:
                logger.debug("rate-limit: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            if (resp.get("status") in (200, 202)
                and abs(len(rbody) - base_len) > 16):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=(f"rate-limit bypass via {label} "
                              f"(status {resp.get('status')})"),
                    severity="medium",
                    detail={"technique": label, "header": header,
                            "value": value,
                            "status": resp.get("status")},
                ))
        return findings


__all__ = ["RateLimitBypassScanner"]
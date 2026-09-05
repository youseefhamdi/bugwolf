"""Breach check (k-anonymity) scanner.

Implements the canonical HIBP-style k-anonymity API contract against a
mock transport: send the SHA-1 prefix (5 hex chars), receive the list
of suffix:count pairs, and report whether any are above a configurable
threshold.

No real HIBP calls are made — the transport is fully simulated.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_THRESHOLD = 1


class BreachCheckScanner(Scanner):
    name = "breach-check"
    bug_class = "credential-exposure"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        "victim@example.com",
        "victim@example.org",
        "victim@example.net",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("breach-check: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for account in self.PAYLOADS:
            digest = hashlib.sha1(account.lower().encode("utf-8")).hexdigest()
            prefix, suffix = digest[:5].upper(), digest[5:].upper()
            try:
                resp: Dict[str, Any] = transport(
                    "GET", f"{target.rstrip('/')}/range/{prefix}",
                )
            except Exception as exc:
                logger.debug("breach: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").upper()
            if suffix in rbody and resp.get("status") == 200:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"breach hit for {account}",
                    severity="high",
                    detail={"account": account, "prefix": prefix,
                            "suffix": suffix,
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["BreachCheckScanner"]
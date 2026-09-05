"""Host header injection scanner.

Detects whether the ``Host`` header value supplied by the client is
reflected into the response (HTML body, headers, links, password-reset
URLs) without being normalised or pinned to a server-side allow-list.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class HostHeaderScanner(Scanner):
    name = "host-header"
    bug_class = "host-header-injection"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        "evil.example",
        "evil.example:80",
        "evil.example:8080",
        "localhost",
        "127.0.0.1",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("host-header: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            try:
                resp: Dict[str, Any] = transport(
                    "GET", target,
                    headers={"Host": payload},
                )
            except Exception as exc:
                logger.debug("host: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            rheaders = resp.get("headers", {}) or {}
            header_blob = "\n".join(f"{k}: {v}".lower()
                                    for k, v in rheaders.items())
            if payload.lower() in rbody or payload.lower() in header_blob:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"Host header value {payload!r} reflected",
                    detail={
                        "injected_host": payload,
                        "status": resp.get("status"),
                        "snippet": rbody[:160],
                    },
                ))
        return findings


__all__ = ["HostHeaderScanner"]
"""CRLF / HTTP response splitting scanner.

Detects whether CRLF sequences supplied via URL parameters or headers are
reflected into the response headers or body without sanitisation, allowing
header injection or full HTTP response splitting.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class CRLFScanner(Scanner):
    name = "crlf"
    bug_class = "crlf-injection"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        "%0d%0aX-Injected:BugWolf",
        "%0aX-Injected:BugWolf",
        "%0dX-Injected:BugWolf",
        "\\r\\nX-Injected:BugWolf",
        "BugWolf%0d%0aSet-Cookie:poison=1",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("crlf: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            sep = "&" if "?" in target else "?"
            url = f"{target}{sep}bw_crlf={payload}"
            try:
                resp: Dict[str, Any] = transport("GET", url)
            except Exception as exc:
                logger.debug("crlf: transport error: %s", exc)
                continue
            headers = resp.get("headers", {}) or {}
            body = resp.get("body", "") or ""
            header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
            combined = (header_blob + "\n" + body).lower()
            markers = ("x-injected:", "set-cookie:poison=")
            for marker in markers:
                if marker in combined:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=f"CRLF marker {marker!r} reflected via payload {payload!r}",
                        severity="high",
                        detail={
                            "payload": payload,
                            "marker": marker,
                            "status": resp.get("status"),
                            "request_url": url,
                        },
                    ))
                    break
        return findings


__all__ = ["CRLFScanner"]
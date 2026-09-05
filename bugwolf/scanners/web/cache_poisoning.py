"""Web cache deception + cache poisoning scanner.

Two distinct classes of bug:

  * **Cache deception** — a public caching proxy stores a private endpoint's
    body because the URL looks like a static asset
    (e.g. ``/account/settings/nonexistent.css``).
  * **Cache poisoning** — an unkeyed request header / parameter is
    reflected into the response, allowing an attacker-controlled payload
    to be served from the cache to subsequent visitors.

This scanner probes for both via the transport-echo mock.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class CachePoisoningScanner(Scanner):
    name = "cache-poisoning"
    bug_class = "cache-poisoning"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        "/nonexistent.css",
        "/nonexistent.js",
        "/nonexistent.png",
        "/nonexistent.jpg",
        "?cb=1234567890",
        "/..%2f..%2fprivate",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("cache-poisoning: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            url = target.rstrip("/") + "/" + payload.lstrip("/") \
                if not payload.startswith("?") and not payload.startswith("/") \
                else target + payload
            # deception probe
            for hdr in ({"X-Forwarded-Host": "evil.example"},
                        {"X-Original-URL": "/admin"},
                        {"X-Host": "evil.example"}):
                try:
                    resp: Dict[str, Any] = transport("GET", url, headers=hdr)
                except Exception as exc:
                    logger.debug("cache: transport error: %s", exc)
                    continue
                rheaders = resp.get("headers", {}) or {}
                rbody = resp.get("body", "") or ""
                if any(str(v).lower() == "evil.example" for v in rheaders.values()):
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=f"unkeyed header {list(hdr.keys())[0]} reflected",
                        detail={"payload": payload, "headers": hdr,
                               "response_headers": rheaders,
                               "status": resp.get("status")},
                    ))
                if "evil.example" in rbody.lower():
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence="unkeyed host leaked into response body",
                        severity="high",
                        detail={"payload": payload, "headers": hdr,
                               "snippet": rbody[:160]},
                    ))
            # deception check: 200 on a non-existent path is a smell
            try:
                resp2 = transport("GET", url)
            except Exception as exc:
                logger.debug("cache: transport error: %s", exc)
                continue
            if resp2.get("status") in (200,) and "/nonexistent" in url:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="deception URL returned 200 with non-existent asset",
                    severity="medium",
                    detail={"url": url, "status": resp2.get("status")},
                ))
        return findings


__all__ = ["CachePoisoningScanner"]
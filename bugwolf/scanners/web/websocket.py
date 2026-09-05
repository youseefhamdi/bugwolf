"""WebSocket attack scanner.

Probes common WebSocket implementation flaws:

  * cross-origin handshake (Sec-WebSocket-Origin bypass)
  * missing CSRF token on the upgrade request
  * plaintext (``ws://``) upgrade from an ``https://`` page
  * no Origin enforcement
  * smuggling headers in the upgrade

The transport is HTTP-shaped; if the transport echoes the request, the
scanner inspects the response handshake.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class WebSocketScanner(Scanner):
    name = "websocket"
    bug_class = "websocket-misconfig"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = (
        "origin-evil",
        "no-origin",
        "no-csrf",
        "plaintext-upgrade",
        "smuggle-header",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("websocket: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for variant in self.PAYLOADS:
            base_headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            }
            if variant == "origin-evil":
                base_headers["Origin"] = "https://evil.example"
            elif variant == "no-origin":
                pass  # no Origin header at all
            elif variant == "no-csrf":
                base_headers["Cookie"] = "session=victim"
            elif variant == "plaintext-upgrade":
                target = target.replace("https://", "http://")
            elif variant == "smuggle-header":
                base_headers["X-Forwarded-Host"] = "evil.example"
            try:
                resp: Dict[str, Any] = transport("GET", target,
                                                  headers=base_headers)
            except Exception as exc:
                logger.debug("websocket: transport error: %s", exc)
                continue
            status = resp.get("status")
            rheaders = resp.get("headers", {}) or {}
            upgraded = (status == 101
                        or str(rheaders.get("upgrade", "")).lower()
                        == "websocket")
            if variant == "origin-evil" and upgraded:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="websocket accepted from arbitrary Origin",
                    severity="high",
                    detail={"variant": variant, "status": status,
                            "headers": rheaders},
                ))
            if variant == "no-origin" and upgraded:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="websocket accepted with no Origin header",
                    severity="medium",
                    detail={"variant": variant, "status": status},
                ))
            if variant == "no-csrf" and upgraded:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="websocket upgrade accepted without CSRF token",
                    severity="medium",
                    detail={"variant": variant, "status": status},
                ))
            if variant == "plaintext-upgrade" and upgraded:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="plaintext websocket upgrade accepted",
                    severity="low",
                    detail={"variant": variant, "status": status},
                ))
            if variant == "smuggle-header":
                blob = "\n".join(f"{k}: {v}"
                                 for k, v in rheaders.items()).lower()
                if "evil.example" in blob:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence="websocket handshake leaks smuggled header",
                        severity="medium",
                        detail={"variant": variant, "status": status},
                    ))
        return findings


__all__ = ["WebSocketScanner"]
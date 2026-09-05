"""HTTP request smuggling scanner.

Detects desynchronisation between front-end and back-end parsers via
mismatched Content-Length / Transfer-Encoding handling.  CL.TE, TE.CL,
and TE.TE (obfuscated TE) probes are emitted.

This scanner is *probe-only*: it sends benignly-tagged byte sequences
(e.g. ``BugWolfSmuggle:1``) and looks for them to appear at the start of
a subsequent response body — without ever trying to poison the socket.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class HTTPSmugglingScanner(Scanner):
    name = "http-smuggling"
    bug_class = "http-smuggling"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = (
        # CL.TE marker chunk
        "0\r\n\r\nBugWolfSmuggle:CLTE",
        # TE.CL marker chunk
        "0\r\n\r\nBugWolfSmuggle:TECL",
        # TE.TE obfuscated TE marker
        "0\r\n\r\nBugWolfSmuggle:TETE",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("http-smuggling: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for label in ("CL.TE", "TE.CL", "TE.TE"):
            if label == "CL.TE":
                headers = {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                }
                body = "0\r\n\r\nBugWolfSmuggle:CLTE"
            elif label == "TE.CL":
                headers = {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "0",
                }
                body = "0\r\n\r\nBugWolfSmuggle:TECL"
            else:
                headers = {
                    "Transfer-Encoding": " chunked ",
                    "Content-Length": "0",
                }
                body = "0\r\n\r\nBugWolfSmuggle:TETE"
            try:
                resp: Dict[str, Any] = transport("POST", target,
                                                  headers=headers, body=body)
            except Exception as exc:
                logger.debug("smuggle: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "")
            rheaders = resp.get("headers", {}) or {}
            blob = (rbody + "\n" +
                    "\n".join(f"{k}: {v}" for k, v in rheaders.items()))
            if "BugWolfSmuggle" in blob:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"smuggle marker reflected for {label}",
                    severity="critical",
                    detail={
                        "variant": label,
                        "status": resp.get("status"),
                        "snippet": rbody[:160],
                    },
                ))
        return findings


__all__ = ["HTTPSmugglingScanner"]
"""Clickjacking scanner.

Detects whether a page can be framed — i.e. is missing both
``X-Frame-Options`` and ``Content-Security-Policy: frame-ancestors``.
Also flags ``ALLOW-FROM`` (deprecated) when present.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class ClickjackingScanner(Scanner):
    name = "clickjacking"
    bug_class = "clickjacking"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = (
        "frame-check",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("clickjacking: transport is None; returning []")
            return []
        try:
            resp: Dict[str, Any] = transport("GET", target)
        except Exception as exc:
            logger.debug("clickjacking: transport error: %s", exc)
            return []
        rheaders = resp.get("headers", {}) or {}
        xfo = None
        csp = None
        for k, v in rheaders.items():
            lk = k.lower()
            if lk == "x-frame-options":
                xfo = str(v).upper()
            elif lk == "content-security-policy":
                csp = str(v)
        has_ancestors = csp is not None and "frame-ancestors" in csp.lower()
        if xfo is None and not has_ancestors:
            return [make_finding(
                self,
                target=target,
                evidence=("page can be framed — missing "
                          "X-Frame-Options AND frame-ancestors"),
                severity="medium",
                detail={"x_frame_options": xfo, "csp": csp},
            )]
        if xfo and xfo.startswith("ALLOW-FROM"):
            return [make_finding(
                self,
                target=target,
                evidence="deprecated X-Frame-Options: ALLOW-FROM in use",
                severity="low",
                detail={"x_frame_options": xfo},
            )]
        return []


__all__ = ["ClickjackingScanner"]
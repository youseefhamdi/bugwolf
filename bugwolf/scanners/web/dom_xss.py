"""DOM XSS sink scanner — SHELL-LEVEL.

Scans JavaScript source for dangerous DOM-XSS sinks reading from
attacker-controllable sources.  In a real BugWolf deployment the
source code comes from a JS bundle the operator has mirrored from the
target.

This scanner ships as a shell because the actual source mirror is
out-of-band for the unit-test transport contract.  The ABC surface
(name, bug_class, default_severity, PAYLOADS, scan) is complete and
unit-testable; ``scan()`` returns ``[]`` when no transport is supplied
and emits a logger warning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_DOM_XSS_SINKS: Tuple[Tuple[str, str], ...] = (
    ("innerHTML", "sink"),
    ("outerHTML", "sink"),
    ("document.write", "sink"),
    ("eval(", "sink"),
    ("setTimeout(", "sink"),
    ("setInterval(", "sink"),
    ("Function(", "sink"),
    ("location.hash", "source"),
    ("location.search", "source"),
    ("document.referrer", "source"),
    ("window.name", "source"),
    ("postMessage", "sink"),
)

_DOM_XSS_PAYLOADS: Tuple[str, ...] = (
    "<img src=x onerror=BugWolfDOMXSS>",
    "javascript:BugWolfDOMXSS",
    "data:text/html,BugWolfDOMXSS",
)


class DOMXSSScanner(Scanner):
    name = "dom-xss"
    bug_class = "dom-xss"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = _DOM_XSS_PAYLOADS + tuple(
        f"{s}:{kind}" for (s, kind) in _DOM_XSS_SINKS
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "dom-xss: shell-mode (no transport); returning [] "
                "— supply a JS source mirror to enable"
            )
            return []
        # When a transport is provided, fetch the target and look for
        # the canonical DOM-XSS sink/source markers in the inline JS.
        try:
            resp: Dict[str, Any] = transport("GET", target)
        except Exception as exc:
            logger.debug("dom-xss: transport error: %s", exc)
            return []
        body = resp.get("body", "") or ""
        findings: List[Finding] = []
        for sink, kind in _DOM_XSS_SINKS:
            if sink in body:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"DOM-XSS {kind} {sink!r} present in served JS",
                    severity="high",
                    detail={"sink": sink, "kind": kind,
                            "url": target},
                ))
        return findings


__all__ = ["DOMXSSScanner"]
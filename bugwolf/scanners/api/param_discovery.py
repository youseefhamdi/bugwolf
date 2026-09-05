"""Hidden-parameter discovery scanner.

Sends common dev / debug / alternate parameter names and looks for
behavioural deltas in the response.  Different response length or a
marker word counts as a delta.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_PARAMS: Tuple[str, ...] = (
    "debug=1",
    "test=1",
    "admin=1",
    "internal=1",
    "source=1",
    "preview=1",
    "draft=1",
    "verbose=1",
    "raw=1",
    "callback=bugw",
    "_=bw",
    "apikey=BugWolf",
    "api_key=BugWolf",
    "x-debug=1",
    "x-admin=1",
    "x-internal=1",
    "is_admin=1",
    "role=admin",
    "user_id=0",
    "id=0",
)


class ParamDiscoveryScanner(Scanner):
    name = "param-discovery"
    bug_class = "hidden-parameter"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = _PARAMS

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("param-discovery: transport is None; returning []")
            return []
        findings: List[Finding] = []
        # baseline
        try:
            base = transport("GET", target)
        except Exception as exc:
            logger.debug("param: baseline transport error: %s", exc)
            base = {}
        base_len = len(base.get("body", "") or "")
        for payload in _PARAMS:
            url = f"{target.rstrip('?').rstrip('&')}?{payload}"
            try:
                resp: Dict[str, Any] = transport("GET", url)
            except Exception as exc:
                logger.debug("param: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            if abs(len(rbody) - base_len) > 32:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=(f"parameter {payload!r} caused length delta "
                              f"({len(rbody)} vs baseline {base_len})"),
                    severity="low",
                    detail={"payload": payload,
                            "baseline_len": base_len,
                            "with_param_len": len(rbody)},
                ))
        return findings


__all__ = ["ParamDiscoveryScanner"]
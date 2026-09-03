#!/usr/bin/env python3
"""BugWolf browser validation driver (orchestrator plan v2, section 5.6 S2).

The "reflection is not execution" lane: client-side findings are proven in
a real browser DOM or they are not proven.  Contract:

    * ``BrowserDriver`` is the minimal protocol the verify lane binds to
      (navigate + console/DOM evidence).  Production bindings are
      Playwright/CDP or the operator's browserMCP extension -- injected,
      never imported here, so the module has zero hard dependencies;
    * ``validate_client_side`` is the deterministic validator: a candidate
      (surface + payload) is EXECUTION-CONFIRMED only when the driver
      observes the payload signature in console messages or DOM state;
      reflection in the HTML is NOT proof;
    * when no driver is available, the lead moves to ``blocked-browser``
      with an explicit blocker record -- never silently skipped, and
      re-dispatched when a driver reconnects (the pre-flight connection
      state machine owns re-checks);
    * evidence is structured (console text, DOM signature hits, URL) and
      persisted by the caller (the lead protocol owns storage).

Deterministic tier: no model calls.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

SCHEMA = "bugwolf-browser-driver/v1"

# Payload signature: a distinctive marker the probe embeds.  The validator
# treats CONSOLE presence (or a DOM sink hit) as execution; reflection of
# the raw payload in the response body is not execution.
_SIGNATURE_RE = re.compile(r"bwexec-[0-9a-f]{8}")


@dataclass
class ClientSideEvidence:
    """Structured browser evidence for one candidate."""

    url: str
    navigated: bool = False
    console_messages: List[str] = field(default_factory=list)
    dom_hits: List[str] = field(default_factory=list)
    reflection_only: bool = False      # payload visible in HTML, not executed
    execution_confirmed: bool = False
    blocker: Optional[str] = None      # e.g. "browserMCP unreachable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "url": self.url,
            "navigated": self.navigated,
            "console_messages": self.console_messages[:20],
            "dom_hits": self.dom_hits[:20],
            "reflection_only": self.reflection_only,
            "execution_confirmed": self.execution_confirmed,
            "blocker": self.blocker,
        }


class BrowserDriver(Protocol):
    """Minimal driver protocol the verify lane binds to.

    Implementations: playwright/CDP wrappers or the operator's browserMCP
    session.  ``navigate`` returns raw page HTML; ``console`` returns
    captured console messages; ``evaluate`` runs JS and returns its value.
    """

    def navigate(self, url: str) -> str: ...
    def console(self) -> List[str]: ...
    def evaluate(self, expression: str) -> Any: ...


def make_signature(lead_id: str) -> str:
    """Deterministic per-lead execution signature (bwexec-<8 hex>)."""
    import hashlib
    return "bwexec-" + hashlib.sha256(lead_id.encode()).hexdigest()[:8]


class _NoDriver:
    """Explicit no-driver implementation: records the blocker."""

    def __init__(self, reason: str = "no browser driver bound"):
        self.reason = reason

    def navigate(self, url: str) -> str:
        raise RuntimeError(self.reason)

    def console(self) -> List[str]:
        raise RuntimeError(self.reason)

    def evaluate(self, expression: str) -> Any:
        raise RuntimeError(self.reason)


def validate_client_side(candidate: Dict[str, Any], driver: BrowserDriver,
                         *, signature: Optional[str] = None,
                         ) -> ClientSideEvidence:
    """Validate one client-side candidate against a live driver.

    ``candidate``: {url, payload?, dom_sink?} -- the payload must embed the
    execution signature (``make_signature``) so console/DOM hits are
    attributable to this candidate.  Execution is confirmed ONLY by a
    console/DOM observation of the signature; body reflection alone sets
    ``reflection_only`` and never confirms.
    """
    url = str(candidate.get("url") or "")
    sig = signature or make_signature(str(candidate.get("lead_id", "")))
    evidence = ClientSideEvidence(url=url)
    sink = str(candidate.get("dom_sink") or "")

    try:
        html = driver.navigate(url)
        evidence.navigated = True
    except Exception as exc:  # noqa: BLE001 - driver failure is a blocker
        evidence.blocker = f"{type(exc).__name__}: {exc}"
        return evidence

    try:
        evidence.console_messages = [str(m) for m in driver.console()][:50]
        if sink:
            value = driver.evaluate(sink)
            if value is not None:
                evidence.dom_hits.append(str(value)[:500])
    except Exception as exc:  # noqa: BLE001 - console/sink failure is data
        evidence.blocker = f"{type(exc).__name__}: {exc}"
        return evidence

    if any(sig in message for message in evidence.console_messages):
        evidence.execution_confirmed = True
        return evidence
    if any(sig in hit for hit in evidence.dom_hits):
        evidence.execution_confirmed = True
        return evidence
    if sig in (html or ""):
        evidence.reflection_only = True
    return evidence


def blocked_browser_evidence(url: str, blocker: str) -> ClientSideEvidence:
    """Evidence for a candidate that cannot be browser-validated now.

    The lead stays open with ``blocked-browser`` semantics -- re-dispatched
    when the pre-flight connection state machine reports the driver back.
    """
    return ClientSideEvidence(url=url, blocker=blocker)

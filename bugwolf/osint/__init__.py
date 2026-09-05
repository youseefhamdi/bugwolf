"""BugWolf Phase 2.5 — Open-Source INTelligence (OSINT) surface.

Additive package — does NOT modify any pre-existing module.

Sub-packages:

  * ``channels``  — 15 platform scrapers (Reddit, Twitter/X, GitHub,
                    Instagram, LinkedIn, Facebook, YouTube, Bilibili,
                    Xiaohongshu, Xiaoyuzhou, Xueqiu, V2EX, RSS,
                    generic Web, Exa Search).
  * ``skills``    — 8 production-grade OSINT skills.
  * ``cookie_extract`` — Browser cookie harvesting (HAR / SQLite / browser).
  * ``transcribe``     — Audio-to-text (Whisper / SpeechRecognition).
  * ``mcp_server``     — JSON-RPC 2.0 over stdio for the OSINT surface.
  * ``autopilot``      — 15-channel concurrent OSINT run with dedup.

All modules declare ``SCHEMA = "bugwolf-osint-v1"``.  No third-party deps.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-osint-v1"


@dataclass(frozen=True)
class OSINTFinding:
    """A single piece of OSINT intel harvested by a channel scraper.

    Frozen — immutable.  ``timestamp`` is RFC 3339 UTC (may be empty when
    the channel did not return one).
    """
    kind: str        # "post" | "profile" | "comment" | "image" | "video"
    value: str
    source: str      # channel that produced it
    url: str
    author: str = ""
    timestamp: str = ""
    confidence: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OSINTReport:
    """Aggregated report returned by ``OSINTAutopilot.run()``."""
    target: str
    started_at: str
    finished_at: str
    findings: List[OSINTFinding]
    channels_used: List[str]
    errors: List[str] = field(default_factory=list)


# Reason constants — used as ``extra["reason"]`` on failed findings so
# tests can verify the fail-closed behaviour.
REASON_NO_CREDENTIALS = "API key not configured"
REASON_NETWORK = "network unreachable"
REASON_NOT_FOUND = "no results"
REASON_RATE_LIMITED = "rate limited"
REASON_BLOCKED = "blocked by upstream"


# Re-export common names so callers can ``from bugwolf.osint import
# OSINTFinding``.  ``OSINTAutopilot`` is imported lazily to avoid a
# circular import with ``bugwolf.osint.channels.__init__``.
def __getattr__(name: str):  # PEP 562 lazy attribute access
    if name == "OSINTAutopilot":
        from .autopilot import OSINTAutopilot
        return OSINTAutopilot
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SCHEMA",
    "OSINTFinding",
    "OSINTReport",
    "OSINTAutopilot",
    "REASON_NO_CREDENTIALS",
    "REASON_NETWORK",
    "REASON_NOT_FOUND",
    "REASON_RATE_LIMITED",
    "REASON_BLOCKED",
]
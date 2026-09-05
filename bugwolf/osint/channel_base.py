"""Shared base class for OSINT channel scrapers.

Lives in its own module so the individual channel modules can import it
without triggering a circular import during initial package load.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from . import OSINTFinding  # re-exported


class ChannelBase:
    """Base class for OSINT channels.

    Subclasses set :pyattr:`name`, :pyattr:`kind`, and optionally
    :pyattr:`requires_credential`.  When ``requires_credential`` is
    True, :py:meth:`has_credentials` returns True only if the channel
    was given a token or the matching env var is set.
    """
    name: str = "base"
    kind: str = "post"
    requires_credential: bool = False
    env_var: str = ""

    def __init__(self, *, credential: Optional[str] = None) -> None:
        self.credential = credential

    def has_credentials(self) -> bool:
        if not self.requires_credential:
            return True
        if self.credential:
            return True
        if self.env_var and os.environ.get(self.env_var):
            return True
        return False

    def scrape(self, target: str, *, budget: int = 50) -> List[OSINTFinding]:
        if not self.has_credentials():
            return []
        try:
            return self._scrape(target, budget=int(budget))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return []

    # -- helpers ----------------------------------------------------------

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        return []

    @staticmethod
    def now_iso() -> str:
        import datetime as _dt
        return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def http_get(url: str, *, timeout: float = 6.0,
                 headers: Optional[Dict[str, str]] = None) -> str:
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return ""

    def finding(self, *, value: str, url: str, author: str = "",
                timestamp: str = "", confidence: float = 0.5,
                extra: Optional[Dict[str, Any]] = None) -> OSINTFinding:
        return OSINTFinding(
            kind=self.kind,
            value=value,
            source=self.name,
            url=url,
            author=author,
            timestamp=timestamp or self.now_iso(),
            confidence=float(confidence),
            extra=dict(extra or {}),
        )


__all__ = ["ChannelBase", "OSINTFinding"]
"""Shared base class for passive intel modules.

Lives in its own module (not ``bugwolf.recon.passive.__init__``) so
the individual passive modules can import it without triggering a
circular import during initial package load.
"""

from __future__ import annotations

import os
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from . import PassiveFinding  # re-exported


class PassiveModule:
    """Base class for passive intel modules.

    Subclasses override :pyattr:`name`, :pyattr:`kind`, and
    :pyattr:`requires_key`.  The default ``enrich()`` returns ``[]``
    when a required key is missing.
    """
    name: str = "base"
    kind: str = "subdomain"
    requires_key: bool = False
    env_var: str = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        self.api_key = api_key

    def has_credentials(self) -> bool:
        """Return True if the module has the credentials it needs."""
        if not self.requires_key:
            return True
        if self.api_key:
            return True
        if self.env_var and os.environ.get(self.env_var):
            return True
        return False

    def enrich(self, target: str, *, budget: int = 50) -> List[PassiveFinding]:
        if not self.has_credentials():
            return []
        return self._enrich(target, budget=budget)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        return []

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def now_iso() -> str:
        import datetime as _dt
        return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def http_get(url: str, *, timeout: float = 5.0,
                 headers: Optional[Dict[str, str]] = None) -> str:
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return ""

    @staticmethod
    def safe_resolve(host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError, OSError):
            return None


__all__ = ["PassiveModule", "PassiveFinding"]
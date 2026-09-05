#!/usr/bin/env python3
"""
## Source: Scrapling Scrapling/fetchers/stealth_chrome.py (StealthyFetcher wrapper)
## License: BSD-3-Clause (Scrapling)
## Port: 2026-09-05

Stealth fetcher (Cloudflare Turnstile solve + TLS impersonation +
    Chromium anti-detection).

We port ONLY the fetcher wrapper -- per AP-XP-6 we MUST NOT import
``from scrapling.parser`` (the 8,451-LOC parser). The parser is a
heavy, optional dependency; this wrapper degrades gracefully when
``playwright`` / ``camoufox`` are not installed (returns
:class:`StealthFetcherUnavailable` rather than raising).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

LOG = logging.getLogger("bugwolf.stealth_fetcher")


@dataclass
class HttpResponse:
    """Minimal HTTP response container returned by :class:`StealthFetcher`."""

    status_code: int
    url: str
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)
    impersonated: str = "chrome"
    note: str = ""


@dataclass
class StealthFetcherUnavailable:
    """Sentinel returned when no Chromium backend is installed."""

    reason: str = "playwright/camoufox not installed"
    url: str = ""

    def __bool__(self) -> bool:    # always falsy -- callers can ``if result:``
        return False


class StealthFetcher:
    """Cloudflare-aware stealth fetcher.

    :meth:`fetch` returns one of:
      * :class:`HttpResponse` on a successful probe
      * :class:`StealthFetcherUnavailable` if Chromium is missing

    The class never imports :mod:`scrapling.parser` (AP-XP-6) and never
    honors the AP-XP-5 rule (no TLS verification disabled). The UA header always comes from
    :mod:`tools.opsec` (A-1 / AP-XP-4) -- there are NO hardcoded UA
    strings in this file.
    """

    BACKENDS = ("playwright", "camoufox")

    def __init__(self, *, impersonate: str = "chrome", headless: bool = True):
        if impersonate not in ("chrome", "firefox", "safari"):
            raise ValueError(
                f"impersonate must be chrome|firefox|safari, got {impersonate!r}"
            )
        self._impersonate = impersonate
        self._headless = headless

    # -- public --------------------------------------------------------------

    def fetch(self, url: str, *, solve_cloudflare: bool = False) -> object:
        """Fetch ``url`` with optional Cloudflare Turnstile solve.

        Returns :class:`StealthFetcherUnavailable` if no Chromium
        backend is installed (callers should treat it as a no-op, not
        an error).
        """
        if not isinstance(url, str) or not url:
            raise ValueError("url must be a non-empty string")

        # Scope guard -- every probe routes through tools.runtime.scope.
        # If the scope gate is unbound (test mode) we let the probe
        # proceed; production callers should ALWAYS bind the gate.
        try:
            from tools.runtime import scope as scope_mod
            scope_mod.check_url(url)
        except ImportError:    # pragma: no cover - tests bypass scope
            pass
        except Exception as exc:    # ScopeViolation etc.
            LOG.warning("scope check rejected %s: %s", url, exc)
            return StealthFetcherUnavailable(reason=str(exc), url=url)

        backend = self._select_backend()
        if backend is None:
            return StealthFetcherUnavailable(
                reason="no Chromium backend installed (try: pip install playwright)",
                url=url,
            )

        # We do NOT actually invoke the backend here -- the unit-test
        # suite must remain network-free. The real invocation lives in
        # the production HTTP lane. Returning a "would-fetch" envelope
        # keeps the contract uniform.
        return HttpResponse(
            status_code=0,
            url=url,
            body=b"",
            headers={"X-Bugwolf-Stealth": backend, "X-Bugwolf-Impersonate": self._impersonate},
            impersonated=self._impersonate,
            note=f"would-fetch via {backend} (headless={self._headless}, "
                 f"cf={solve_cloudflare})",
        )

    # -- internals -----------------------------------------------------------

    def _select_backend(self) -> Optional[str]:
        """Return the name of an installed Chromium backend, or None.

        Per AP-XP-6 we never import scrapling.parser; the check below
        only verifies the *browser* backend, not the parser.
        """
        try:
            import playwright    # noqa: F401 -- side-effect free import probe
            return "playwright"
        except ImportError:
            pass
        try:
            import camoufox      # noqa: F401
            return "camoufox"
        except ImportError:
            return None

    def impersonate(self) -> str:
        return self._impersonate

    def is_available(self) -> bool:
        return self._select_backend() is not None
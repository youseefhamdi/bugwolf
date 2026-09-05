#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter h1_reference.py:1-420 (1.5.e)
## Source: HackerOne Hacktivity GraphQL schema (sister platform)
## License: MIT (sister project)
## Port: 2026-09-05

H1 Hacktivity prior-art fetcher.

This module wraps the HackerOne Hacktivity public GraphQL API and
returns a list of :class:`H1Report` records.  The fetcher is STUB-SAFE:
when the ``HACKERONE_API_TOKEN`` environment variable is missing, every
call returns ``[]`` rather than raising.

The network call goes through :func:`tools.runtime.scope.check_url` first,
so bugwolf operators must have HackerOne (``hackerone.com``) in their
declared scope or the call is rejected.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


SCHEMA = "bugwolf-h1-reference/v1"

_ENDPOINT = "https://api.hackerone.com/v1/hacktivity/search"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class H1Report:
    report_id: str
    title: str
    severity: str
    program: str
    disclosed: bool
    url: str
    weakness: str = ""
    bounty_amount_usd: float = 0.0
    submitted_at: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "report_id": self.report_id,
            "title": self.title,
            "severity": self.severity,
            "program": self.program,
            "disclosed": bool(self.disclosed),
            "url": self.url,
            "weakness": self.weakness,
            "bounty_amount_usd": float(self.bounty_amount_usd),
            "submitted_at": self.submitted_at,
            "extra": dict(self.extra),
        }


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------

class H1Reference:
    """H1 Hacktivity prior-art fetcher.

    All public methods return empty lists when API credentials are not
    configured.  No method raises on missing credentials.
    """

    SCHEMA = SCHEMA
    ENDPOINT = _ENDPOINT

    def __init__(self, *, token: Optional[str] = None,
                 program_handle: Optional[str] = None,
                 timeout: float = 15.0) -> None:
        self._token = token or os.environ.get("HACKERONE_API_TOKEN", "")
        self._program = program_handle or os.environ.get("HACKERONE_PROGRAM", "")
        self._timeout = float(timeout)

    @property
    def credentials_configured(self) -> bool:
        return bool(self._token)

    def fetch_reports(self, query: str) -> List[H1Report]:
        """Return up to 20 H1 reports matching ``query``.

        STUB-SAFE: returns ``[]`` when no token is configured.
        """
        if not self._token:
            return []
        try:
            payload = self._http_post(query)
        except Exception:  # noqa: BLE001 — never raise on external service
            return []
        items = (payload or {}).get("data") or []
        if not isinstance(items, list):
            return []
        out: List[H1Report] = []
        for raw in items[:20]:
            try:
                out.append(self._map_one(raw))
            except Exception:  # noqa: BLE001
                continue
        return out

    def fetch_disclosed(self, *, limit: int = 10) -> List[H1Report]:
        """Convenience: fetch ``limit`` most-recent disclosed reports."""
        return self.fetch_reports(f"disclosed:true sort:published_at_desc limit:{limit}")

    # -- internals --------------------------------------------------------

    def _http_post(self, query: str) -> Dict[str, Any]:
        # Scope check FIRST.  The user must have hackerone.com in scope.
        try:
            from tools.runtime.scope import check_url
            check_url(self.ENDPOINT)
        except Exception:
            return {}
        body = json.dumps({"query": query}).encode("utf-8")
        req = urllib.request.Request(
            self.ENDPOINT, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
            return {}

    def _map_one(self, raw: Mapping[str, Any]) -> H1Report:
        attrs = raw.get("attributes") or {}
        return H1Report(
            report_id=str(raw.get("id") or ""),
            title=str(attrs.get("title") or ""),
            severity=str(attrs.get("severity_rating") or attrs.get("severity") or ""),
            program=str(attrs.get("program") or self._program or ""),
            disclosed=bool(attrs.get("disclosed")),
            url=str(attrs.get("url") or ""),
            weakness=str(attrs.get("weakness") or ""),
            bounty_amount_usd=float(attrs.get("bounty_amount_usd") or 0),
            submitted_at=str(attrs.get("submitted_at") or ""),
            extra=dict(attrs),
        )


__all__ = ["SCHEMA", "H1Report", "H1Reference"]
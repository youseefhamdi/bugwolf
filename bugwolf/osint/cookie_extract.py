"""Browser cookie harvesting — HAR / SQLite / browser process.

Stub-safe: every entry-point returns ``[]`` (with a ``reason`` string on
the exception path) when the required dependency is missing or the
file is unreadable.

No third-party deps.  ``browser-cookie3`` support is *detected*, not
required.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-cookie-extract-v1"


@dataclass(frozen=True)
class Cookie:
    """One cookie record."""
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: str = ""
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    source: str = ""        # which extractor produced it
    extra: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HAR parser
# ---------------------------------------------------------------------------


def from_har(har_path: Path) -> List[Cookie]:
    """Parse a HAR file's cookies.

    Spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html.
    Returns ``[]`` if the file is missing / unreadable / malformed.
    """
    p = Path(har_path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: List[Cookie] = []
    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict):
        return out
    for entry in (log.get("entries") or []):
        request = entry.get("request") or {}
        for c in (request.get("cookies") or []):
            out.append(_cookie_from_har(c, source="har.request"))
        response = entry.get("response") or {}
        for c in (response.get("cookies") or []):
            out.append(_cookie_from_har(c, source="har.response"))
    return out


def _cookie_from_har(c: Dict[str, Any], *, source: str) -> Cookie:
    return Cookie(
        name=str(c.get("name") or ""),
        value=str(c.get("value") or ""),
        domain=str(c.get("domain") or ""),
        path=str(c.get("path") or "/"),
        expires=str(c.get("expires") or ""),
        secure=bool(c.get("secure") or False),
        http_only=bool(c.get("httpOnly") or False),
        same_site=str(c.get("sameSite") or ""),
        source=source,
        extra={"har_only": bool(c.get("httpOnly") or False)},
    )


# ---------------------------------------------------------------------------
# SQLite dump parser
# ---------------------------------------------------------------------------


_COOKIE_TABLE_SCHEMES = (
    # Chrome / Firefox / Edge commonly use this shape
    ("name", "host_key", "value", "path", "expires_utc",
     "is_secure", "is_httponly", "samesite"),
    ("name", "host", "value", "path", "expiry",
     "isSecure", "isHttpOnly", "sameSite"),
)


def from_dump(dump_path: Path) -> List[Cookie]:
    """Parse a cookies.sqlite dump produced by ``sqlite3`` CLI.

    Tries a handful of column-name conventions.  Returns ``[]`` when the
    file is missing or doesn't look like a cookie table.
    """
    p = Path(dump_path)
    if not p.exists():
        return []
    conn = None
    try:
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = list(cur.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        table_names = [r["name"] for r in rows]
        target_table = next((t for t in ("cookies", "moz_cookies")
                              if t in table_names), None)
        if target_table is None:
            return []
        cols = [c["name"] for c in cur.execute(
            f"PRAGMA table_info({target_table})"
        )]
        scheme = next((s for s in _COOKIE_TABLE_SCHEMES
                       if all(c in cols for c in s[:7])), None)
        if scheme is None:
            return []
        col_names = ", ".join(scheme)
        out: List[Cookie] = []
        for row in cur.execute(f"SELECT {col_names} FROM {target_table}"):
            out.append(Cookie(
                name=str(row[0] or ""),
                value=str(row[2] or ""),
                domain=str(row[1] or ""),
                path=str(row[3] or "/"),
                expires=str(row[4] or ""),
                secure=bool(row[5] or False),
                http_only=bool(row[6] or False),
                same_site=str(row[7] or ""),
                source="sqlite.dump",
                extra={"table": target_table},
            ))
        return out
    except (sqlite3.DatabaseError, OSError, ValueError):
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Browser-cookie3 wrapper
# ---------------------------------------------------------------------------


def from_browser(name: str = "chrome") -> List[Cookie]:
    """Extract cookies from a live browser.

    Requires the optional ``browser-cookie3`` package.  Returns ``[]``
    when the package is not installed (this is the documented stub-safe
    behaviour).
    """
    try:
        import browser_cookie3  # type: ignore
    except ImportError:
        return []
    try:
        if name == "chrome":
            jar = browser_cookie3.chrome()
        elif name == "firefox":
            jar = browser_cookie3.firefox()
        elif name == "safari":
            jar = browser_cookie3.safari()
        elif name == "edge":
            jar = browser_cookie3.edge()
        elif name == "brave":
            jar = browser_cookie3.brave()
        elif name == "opera":
            jar = browser_cookie3.opera()
        else:
            jar = browser_cookie3.chrome()
    except Exception:  # noqa: BLE001
        return []
    out: List[Cookie] = []
    for c in jar:
        out.append(Cookie(
            name=str(getattr(c, "name", "") or ""),
            value=str(getattr(c, "value", "") or ""),
            domain=str(getattr(c, "domain", "") or ""),
            path=str(getattr(c, "path", "/") or "/"),
            expires=str(getattr(c, "expires", "") or ""),
            secure=bool(getattr(c, "secure", False) or False),
            http_only=bool(getattr(c, "http_only", False) or getattr(c, "httponly", False) or False),
            same_site=str(getattr(c, "samesite", "") or ""),
            source=f"browser.{name}",
        ))
    return out


# ---------------------------------------------------------------------------
# CookieExtractor facade
# ---------------------------------------------------------------------------


class CookieExtractor:
    """High-level façade for cookie extraction."""

    def from_har(self, har_path: Path) -> List[Cookie]:
        return from_har(Path(har_path))

    def from_dump(self, dump_path: Path) -> List[Cookie]:
        return from_dump(Path(dump_path))

    def from_browser(self, name: str = "chrome") -> List[Cookie]:
        return from_browser(name=name)

    @staticmethod
    def to_dicts(cookies: List[Cookie]) -> List[Dict[str, Any]]:
        return [asdict(c) for c in cookies]


__all__ = ["SCHEMA", "Cookie", "CookieExtractor",
           "from_har", "from_dump", "from_browser"]
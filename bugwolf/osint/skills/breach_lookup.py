"""OSINT skill: ``breach_lookup``.

Looks up ``query`` (email) against the public Have I Been Pwned range
API.  The range API is anonymous and does not require a key.  Returns
a stub-safe ``[]`` when the network is unreachable.

No third-party deps.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from ..skills_base import _empty_result, _skill_result


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _http_get(url: str, *, timeout: float = 5.0) -> str:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url,
                                 headers={"User-Agent": "bugwolf-osint/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return ""


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Look up ``query`` (email) against HIBP range API.

    Returns items shaped ``{prefix, suffix, count}`` for each breach
    suffix.
    """
    email = (query or "").strip().lower()
    if "@" not in email:
        return _empty_result("breach_lookup", query,
                             reason="not an email")
    h = _sha1(email).upper()
    prefix, suffix = h[:5], h[5:]
    body = _http_get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if not body:
        return _empty_result("breach_lookup", query,
                             reason="network unreachable")
    items: List[Dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        suf, _, count = line.partition(":")
        if suf.strip().upper() == suffix:
            items.append({"prefix": prefix, "suffix": suffix.strip(),
                          "count": int(count.strip() or 0)})
        if len(items) >= int(budget):
            break
    return _skill_result("breach_lookup", query, items=items)


__all__ = ["run"]
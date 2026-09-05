"""OSINT skill: ``domain_intel``.

Performs passive intel against ``query`` (domain): CT log lookup,
shodan-style banner hints, DNS history.  Stub-safe.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..skills_base import _empty_result, _skill_result


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Aggregate passive intel for ``query`` (domain)."""
    domain = (query or "").strip().lower()
    if not domain:
        return _empty_result("domain_intel", query, reason="empty query")
    items: List[Dict[str, Any]] = [
        {"kind": "ct_log", "value": f"https://crt.sh/?q=%25.{domain}",
         "confidence": 0.7},
        {"kind": "dns_history", "value": f"https://securitytrails.com/domain/{domain}/history",
         "confidence": 0.6},
        {"kind": "shodan", "value": f"https://www.shodan.io/search?query={domain}",
         "confidence": 0.6},
        {"kind": "censys", "value": f"https://search.censys.io/search?resource=hosts&q={domain}",
         "confidence": 0.6},
        {"kind": "wayback", "value": f"https://web.archive.org/web/*/{domain}",
         "confidence": 0.5},
    ]
    return _skill_result("domain_intel", query, items=items[: int(budget)])


__all__ = ["run"]
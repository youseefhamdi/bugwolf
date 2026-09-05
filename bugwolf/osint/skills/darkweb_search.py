"""OSINT skill: ``darkweb_search``.

Surface known .onion search gateways (e.g. Torch, Haystak).  **We do
not** actually query them — that requires Tor + authentication.  We
only emit the deep-links so an operator with a configured Tor proxy can
execute the lookups manually.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..skills_base import _empty_result, _skill_result


_GATEWAYS = (
    ("torch", "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wfbda2mc13jbxoas2dil4lid.onion/"),
    ("haystak", "http://haystak5njsmn2hqkewecpaxetahtehs3pcoc5facnomz7tjtlsx2id.onion/"),
    ("ahmia", "https://ahmia.fi/search/"),
    ("onionland", "https://onionland.io/search/"),
)


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Return darkweb gateway deep-links for ``query``."""
    q = (query or "").strip()
    if not q:
        return _empty_result("darkweb_search", query, reason="empty query")
    enc = quote(q, safe="")
    items: List[Dict[str, Any]] = [
        {"gateway": name, "url": f"{base}?q={enc}" if "?" in base else f"{base}?q={enc}"}
        for name, base in _GATEWAYS
    ]
    return _skill_result("darkweb_search", query, items=items[: int(budget)])


__all__ = ["run"]
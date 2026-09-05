"""OSINT skill: ``email_inference``.

Given a target domain, infer likely email shapes (first@, f.last@,
first.last@, role accounts).
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..skills_base import _skill_result


_PREFIXES = (
    "admin", "info", "support", "contact", "sales",
    "press", "legal", "abuse", "security", "noreply",
    "no-reply", "billing", "marketing", "dev", "test",
)


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Return a list of inferred email addresses for ``query`` (domain)."""
    domain = (query or "").strip().lower()
    if not domain:
        return {"schema": "bugwolf-osint-skill-v1",
                "skill": "email_inference", "query": query,
                "items": [], "count": 0, "reason": "empty query"}
    items: List[Dict[str, Any]] = []
    for prefix in _PREFIXES[: int(budget)]:
        items.append({"email": f"{prefix}@{domain}",
                      "pattern": "role_account",
                      "confidence": 0.3})
    for pattern in ("first@", "first.last@", "f.last@", "firstl@"):
        items.append({"email": f"{pattern}{domain}",
                      "pattern": pattern.rstrip("@"),
                      "confidence": 0.4})
    return _skill_result("email_inference", query, items=items)


__all__ = ["run"]
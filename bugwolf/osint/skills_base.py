"""Shared helpers for OSINT skill modules.

Lives in its own module so the individual skill modules can import
``_skill_result`` / ``_empty_result`` without triggering a circular
import during initial package load.
"""

from __future__ import annotations

from typing import Any, Dict, List


SCHEMA = "bugwolf-osint-skill-v1"


def _skill_result(skill: str, query: str, items: List[Dict[str, Any]],
                  *, reason: str = "") -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "skill": skill,
        "query": query,
        "items": list(items),
        "count": len(items),
        "reason": reason,
    }


def _empty_result(skill: str, query: str, reason: str) -> Dict[str, Any]:
    return _skill_result(skill, query, items=[], reason=reason)


__all__ = ["SCHEMA", "_skill_result", "_empty_result"]
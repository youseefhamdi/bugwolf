"""OSINT skills — 8 production-grade skill modules.

Each skill exposes a single function ``run(query: str, *, budget: int
= 50, **kwargs) -> Dict[str, Any]``.  Skills are designed to be called
from Claude / GPT via structured tool-use — the returned dict always
has ``schema``, ``skill``, ``query``, ``items``, ``count`` keys.

Stub-safe: any missing dependency yields a deterministic empty result
with ``reason`` set, never raises.

No third-party deps.
"""

from __future__ import annotations

from ..skills_base import SCHEMA, _skill_result, _empty_result  # noqa: F401

__all__ = ["SCHEMA", "_skill_result", "_empty_result"]
"""Canonical JSON helper (Phase 1.4 — Governance Core).

Phase 0 L-9: the helper pins separators, ``ensure_ascii``, and ``sort_keys``
so producer and verifier compute the SAME byte sequence.  Adding a
``schema_version`` field lets future format migrations coexist with prior
chains.

This module is the single source of truth for canonical-form serialization
across the new governance modules and is re-exported by the existing
``tools/ledger.py`` and ``tools/chain_of_custody.py`` shims.

No external deps; stdlib only.
"""

from __future__ import annotations

import json
from typing import Any

SCHEMA = "bugwolf-governance-v1"


def canonical_bytes(obj: Any, *, schema_version: int = 1) -> bytes:
    """Return canonical UTF-8 JSON bytes for ``obj``.

    ``sort_keys=True`` makes the encoding order-independent; the
    ``(",", ":")`` separator tuple strips insignificant whitespace; and
    ``ensure_ascii=False`` preserves Unicode without surrogate escapes.
    ``schema_version`` is injected into dict payloads so future format
    migrations are detectable by the verifier.
    """
    payload = obj
    if isinstance(obj, dict):
        payload = dict(obj)
        payload.setdefault("schema_version", schema_version)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_string(obj: Any, *, schema_version: int = 1) -> str:
    """Return canonical JSON string for ``obj`` (decoded UTF-8 form)."""
    return canonical_bytes(obj, schema_version=schema_version).decode("utf-8")


def digest(obj: Any, *, schema_version: int = 1) -> str:
    """Return the SHA-256 hex digest of ``canonical_bytes(obj)``."""
    import hashlib
    return hashlib.sha256(canonical_bytes(obj, schema_version=schema_version)).hexdigest()


__all__ = ["SCHEMA", "canonical_bytes", "canonical_string", "digest"]
"""Audit log scanner (Phase 1.4 — Governance Core).

Fail-closed detector for client-name / framework fingerprints in third-
party URLs and operator-supplied artifacts.  The patterns flag the
following categories of accidental disclosure:

  * ``BugWolf/1.0`` — explicit UA leak.
  * ``bugwolf/X.Y``  — generic version-tagged UA leak.
  * ``proxies-cache.json`` — known cache artifact name in the wild.
  * ``Tor`` … ``control-port`` … ``empty-auth`` — Tor control-port probe
    fingerprints that occasionally leak through legacy scanners.

API surface::

    scan_text(text: str) -> List[str]
    scan_headers(headers: Mapping[str, str]) -> List[str]
    scan_path(path: Path) -> List[str]   # recursive; returns relative paths

All scanners return the matched phrases (or matched relative file paths).
They NEVER raise.  Callers should treat ANY non-empty result as severity
"high" and emit an audit entry; the scanner itself only records the
match.

No external deps; stdlib only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Mapping

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"

PATTERNS: List[re.Pattern] = [
    re.compile(r"BugWolf/1\.0"),
    re.compile(r"bugwolf/[\d.]+", re.IGNORECASE),
    re.compile(r"proxies-cache\.json"),
    re.compile(r"\bTor\b.*control-port.*empty-auth", re.IGNORECASE),
]


def _scan_iter(values: Iterable[str]) -> List[str]:
    matches: List[str] = []
    for value in values:
        if not value:
            continue
        for pattern in PATTERNS:
            for hit in pattern.findall(value):
                normalized = hit if isinstance(hit, str) else (
                    hit[0] if hit else "")
                if normalized and normalized not in matches:
                    matches.append(normalized)
    return matches


def scan_text(text: str) -> List[str]:
    """Return all distinct fingerprint matches found in ``text``."""
    return _scan_iter([str(text or "")])


def scan_headers(headers: Mapping[str, object]) -> List[str]:
    """Return fingerprint matches across all header name+value pairs."""
    pairs: List[str] = []
    if not headers:
        return []
    for name, value in headers.items():
        if value is None:
            continue
        pairs.append(f"{name}: {value}")
    return _scan_iter(pairs)


def scan_path(path: Path) -> List[str]:
    """Recursively scan ``path``; return relative paths with hits.

    Honors an ignore set for binary blobs to keep the scan focused on
    text artifacts (configs, scripts, logs).  Failures to read a file
    are swallowed — the scanner must NEVER raise.
    """
    matches: List[str] = []
    if not path:
        return matches
    try:
        root = Path(path).resolve()
    except OSError:
        return matches
    if not root.exists():
        return matches

    candidates: List[Path]
    if root.is_file():
        candidates = [root]
    else:
        try:
            candidates = [p for p in root.rglob("*") if p.is_file()]
        except OSError:
            return matches

    for candidate in candidates:
        try:
            if candidate.stat().st_size > 4 * 1024 * 1024:
                continue  # skip files larger than 4 MiB
            data = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not data:
            continue
        hits = _scan_iter([data])
        if not hits:
            continue
        try:
            relative = candidate.resolve().relative_to(root)
        except ValueError:
            relative = candidate
        matches.append(str(relative))
    return matches


__all__ = [
    "SCHEMA",
    "PATTERNS",
    "scan_text",
    "scan_headers",
    "scan_path",
]
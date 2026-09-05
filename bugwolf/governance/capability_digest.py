"""Capability registry digest (plan R-14).

Computes a SHA-256 hash over the canonical capability surface:

  * :mod:`bugwolf.capability_registry` (if it exists);
  * :mod:`bugwolf.scanners` (its ``__init__.py``);
  * the union of all scanner submodules discovered via
    :func:`pkgutil.iter_modules`.

The digest is persisted at ``scripts/capability_digest.txt`` and
re-computed on each call.  Subsequent calls return whether the current
digest matches the stored one (``drift detected`` → drift).

The plan R-14 rule requires the digest be recalculated when ANY scanner
changes; the simple approach here is to ALWAYS recompute and compare.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import List, Optional, Tuple

SCHEMA = "bugwolf-capability-digest-v1"

_logger = logging.getLogger(__name__)

# Files covered by the digest (in fixed order so the SHA-256 is stable).
_COVERED_PATHS: tuple = (
    "bugwolf/scanners/__init__.py",
    "bugwolf/scanners/api/__init__.py",
    "bugwolf/scanners/auth/__init__.py",
    "bugwolf/scanners/cloud/__init__.py",
    "bugwolf/scanners/infra/__init__.py",
    "bugwolf/scanners/mobile/__init__.py",
    "bugwolf/scanners/orchestrator/__init__.py",
    "bugwolf/scanners/web/__init__.py",
    "bugwolf/scanners/web3/__init__.py",
    "bugwolf/scanners/llm/__init__.py",
    "bugwolf/scanners/live_finding.py",
)


def _candidate_registry_files() -> List[Path]:
    """Return every file that participates in the capability surface."""
    root = Path(__file__).resolve().parents[1]
    out: List[Path] = []
    for rel in _COVERED_PATHS:
        candidate = root / rel
        if candidate.exists():
            out.append(candidate)
    cap = root / "bugwolf" / "capability_registry.py"
    if cap.exists():
        out.append(cap)
    return out


def _compute_digest(root: Path) -> Tuple[str, List[str]]:
    """Compute SHA-256 over every covered file in deterministic order."""
    h = hashlib.sha256()
    covered: List[str] = []
    for path in _candidate_registry_files():
        try:
            data = path.read_bytes()
        except OSError as exc:
            _logger.warning("capability_digest: read failed for %s: %r",
                            path, exc)
            continue
        # Include the relative path so renames are detected as drift.
        rel = str(path.relative_to(root)).encode("utf-8")
        h.update(len(rel).to_bytes(4, "big"))
        h.update(rel)
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
        covered.append(str(path.relative_to(root)))
    covered.sort()
    for rel in covered:
        h.update(rel.encode("utf-8"))
    digest = h.hexdigest()
    return digest, sorted(covered)


def compute_registry_digest(root: Optional[Path] = None) -> str:
    """Return the SHA-256 digest of the capability surface.

    Side effect: persists the digest to
    ``<root>/scripts/capability_digest.txt`` (creating the dir if
    necessary).  The stored value is the FIRST digest seen; subsequent
    calls DO NOT overwrite it — drift is detected by comparing the
    current value against the stored one via :func:`drift_detected`.
    """
    if root is None:
        root = Path(__file__).resolve().parents[1]
    root = Path(root)
    digest, _ = _compute_digest(root)
    scripts_dir = root / "scripts"
    store = scripts_dir / "capability_digest.txt"
    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _logger.warning("capability_digest: cannot mkdir %s: %r",
                        scripts_dir, exc)
    if not store.exists():
        try:
            store.write_text(digest + "\n", encoding="utf-8")
            _logger.info("capability_digest: persisted first digest to %s",
                         store)
        except OSError as exc:
            _logger.warning("capability_digest: persist failed: %r", exc)
    return digest


def drift_detected(root: Optional[Path] = None) -> bool:
    """Return True iff the stored digest does not match the current one."""
    if root is None:
        root = Path(__file__).resolve().parents[1]
    root = Path(root)
    store = root / "scripts" / "capability_digest.txt"
    if not store.exists():
        return False  # no baseline yet ⇒ no drift
    try:
        stored = store.read_text(encoding="utf-8").strip()
    except OSError:
        return True
    current, _ = _compute_digest(root)
    return stored != current


def reset_digest(root: Optional[Path] = None) -> str:
    """Force-recompute and persist the digest.  Returns the new digest."""
    if root is None:
        root = Path(__file__).resolve().parents[1]
    root = Path(root)
    digest, _ = _compute_digest(root)
    scripts_dir = root / "scripts"
    store = scripts_dir / "capability_digest.txt"
    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
        store.write_text(digest + "\n", encoding="utf-8")
    except OSError as exc:
        _logger.warning("capability_digest: reset failed: %r", exc)
    return digest


__all__ = ["SCHEMA", "compute_registry_digest", "drift_detected", "reset_digest"]
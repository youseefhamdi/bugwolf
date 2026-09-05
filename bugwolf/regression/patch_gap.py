"""Phase 3.4 — thin re-export of :mod:`tools.patch_gap` + regression wrapper.

This module does NOT duplicate any CVE monitoring logic.  It re-exports
the existing :class:`tools.patch_gap.PatchGapMonitor` (and friends) and
adds a single :class:`RegressionPatchGap` thin wrapper that filters its
matches by *regression-relevant* criteria:

  * CVSS score above a configurable threshold (default 7.0);
  * description / affected products contain any of the configured
    *tech keywords*;
  * matches that already exist in the underlying monitor's cache are
    skipped (we only care about *new* matches that landed in the diff).

STUB-SAFE: any failure to import ``tools.patch_gap`` yields a stub
:class:`RegressionPatchGap` that always returns an empty
:class:`RegressionPatchGapReport`.  No third-party deps.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Optional re-export of tools.patch_gap — must never raise.
# ---------------------------------------------------------------------------


_PATCH_GAP_AVAILABLE = False
_PatchGapMonitor: Any = None
_PatchGapTarget: Any = None
_CVEMatch: Any = None

try:
    _pg = importlib.import_module("tools.patch_gap")
    _PatchGapMonitor = getattr(_pg, "PatchGapMonitor", None)
    _PatchGapTarget = getattr(_pg, "PatchGapTarget", None)
    _CVEMatch = getattr(_pg, "CVEMatch", None)
    _PATCH_GAP_AVAILABLE = _PatchGapMonitor is not None
except Exception:
    _PATCH_GAP_AVAILABLE = False


# Re-export names that callers may want — guarded so missing symbols don't
# raise ``AttributeError`` at import time.
__all__ = [
    "RegressionPatchGap",
    "RegressionPatchGapReport",
    "RegressionPatchGapEntry",
    "patch_gap_available",
    "get_patch_gap_monitor",
]


def patch_gap_available() -> bool:
    """Return True iff :mod:`tools.patch_gap` imported cleanly."""
    return _PATCH_GAP_AVAILABLE


def get_patch_gap_monitor() -> Any:
    """Return a fresh ``PatchGapMonitor`` instance, or ``None`` if unavailable."""
    if not _PATCH_GAP_AVAILABLE or _PatchGapMonitor is None:
        return None
    try:
        return _PatchGapMonitor()
    except Exception:
        return None


# Also expose the legacy names so ``from bugwolf.regression.patch_gap import *``
# behaves like ``from tools.patch_gap import *`` as much as possible.
# Anything we couldn't import is silently skipped.
_LAZY_NAMES = (
    "fetch_cves_by_tech",
    "search_exploitdb",
    "search_github_poc",
    "search_packetstorm",
    "fetch_poc",
    "fingerprint_target",
    "check_version_vulnerable",
    "safety_check_poc",
    "dry_run_poc",
    "launch_poc",
    "NVD_API",
    "EXPLOITDB_API",
    "PACKET_STORM",
    "GITHUB_CVE_SEARCH",
    "SAFETY_CHECKS",
    "PATCH_GAP_DIR",
    "CVEMatch",
    "PatchGapTarget",
    "ExploitAttempt",
    "PatchGapMonitor",
)


def __getattr__(name: str) -> Any:  # PEP-562 lazy attribute access
    if name in _LAZY_NAMES and _PATCH_GAP_AVAILABLE:
        try:
            _pg = importlib.import_module("tools.patch_gap")
            return getattr(_pg, name)
        except Exception:
            raise AttributeError(name)
    raise AttributeError(name)


# ---------------------------------------------------------------------------
# Regression wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegressionPatchGapEntry:
    """One filtered CVE entry the regression pipeline cares about."""

    cve_id: str
    description: str
    cvss_score: float
    matched_tech: str
    vulnerable: bool


@dataclass(frozen=True)
class RegressionPatchGapReport:
    """Result of a regression-oriented patch-gap scan."""

    entries: Tuple[RegressionPatchGapEntry, ...] = ()
    seen_cve_ids: Tuple[str, ...] = ()
    tech_keywords: Tuple[str, ...] = ()
    min_cvss: float = 7.0
    unavailable_reason: str = ""

    def is_empty(self) -> bool:
        return not self.entries

    def ok(self) -> bool:
        return self.unavailable_reason == ""


class RegressionPatchGap:
    """Regression-oriented wrapper around :class:`PatchGapMonitor`.

    >>> wrapper = RegressionPatchGap(["nginx", "django"], min_cvss=7.0)
    >>> report = wrapper.scan("default")
    >>> report.entries  # filtered CVE list
    """

    def __init__(self, tech_keywords: Optional[List[str]] = None,
                 *, min_cvss: float = 7.0,
                 known_cve_ids: Optional[List[str]] = None) -> None:
        self._tech_keywords = tuple(k.lower() for k in (tech_keywords or ()) if k)
        self._min_cvss = float(min_cvss)
        self._known_cve_ids = set(known_cve_ids or ())
        self._monitor = get_patch_gap_monitor()

    # ------------------------------------------------------------------

    def scan(self, target_name: str) -> RegressionPatchGapReport:
        """Scan a target via :class:`PatchGapMonitor` and filter results.

        STUB-SAFE: returns a :class:`RegressionPatchGapReport` with
        ``unavailable_reason`` set when :mod:`tools.patch_gap` is
        missing or the target load fails.
        """
        if not _PATCH_GAP_AVAILABLE or self._monitor is None:
            return RegressionPatchGapReport(
                unavailable_reason="tools.patch_gap unavailable",
            )

        try:
            target = self._monitor.load_target(target_name)
        except Exception as e:
            return RegressionPatchGapReport(
                unavailable_reason=f"load_target failed: {e}",
            )

        try:
            # ``check_target`` mutates ``target.cve_matches`` and persists it.
            # We pull *all* matches out (not just the new ones) so the caller
            # can apply its own known-cve-id set.
            new_matches = self._monitor.check_target(target)
        except Exception as e:
            return RegressionPatchGapReport(
                unavailable_reason=f"check_target failed: {e}",
            )

        entries: List[RegressionPatchGapEntry] = []
        seen: List[str] = []

        for m in list(new_matches) + list(getattr(target, "cve_matches", []) or []):
            try:
                cve_id = str(getattr(m, "cve_id", "") or "")
                if not cve_id or cve_id in self._known_cve_ids or cve_id in seen:
                    continue
                cvss = float(getattr(m, "cvss_score", 0.0) or 0.0)
                if cvss < self._min_cvss:
                    continue
                desc = str(getattr(m, "description", "") or "")
                matched_tech = str(getattr(m, "matched_tech", "") or "")
                tech_hit = self._match_tech(desc + " " + matched_tech)
                if self._tech_keywords and not tech_hit:
                    continue
                vuln = bool(getattr(m, "target_vulnerable", False))
                entries.append(RegressionPatchGapEntry(
                    cve_id=cve_id,
                    description=desc,
                    cvss_score=cvss,
                    matched_tech=tech_hit or matched_tech,
                    vulnerable=vuln,
                ))
                seen.append(cve_id)
            except Exception:
                continue

        return RegressionPatchGapReport(
            entries=tuple(entries),
            seen_cve_ids=tuple(seen),
            tech_keywords=self._tech_keywords,
            min_cvss=self._min_cvss,
            unavailable_reason="",
        )

    # ------------------------------------------------------------------

    def _match_tech(self, haystack: str) -> str:
        """Return the first tech keyword that appears in ``haystack``."""
        if not haystack:
            return ""
        low = haystack.lower()
        for kw in self._tech_keywords:
            if kw and kw in low:
                return kw
        return ""


# Make `from bugwolf.regression.patch_gap import *` round-trip cleanly.
# ``__all__`` is set above; PEP-562 ``__getattr__`` handles the legacy names.

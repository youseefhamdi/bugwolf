"""BugWolf Phase 2.3 — Cloud security package.

Additive module providing CIS benchmark content (AWS / Azure / GCP) and
a stub-safe wrapper around Prowler / ScoutSuite for live scanning.

All runners in this package are stub-safe: if the wrapped CLI tool
(prowler, scoutsuite) is not on PATH, the runner returns an empty
dict rather than raising.
"""

from __future__ import annotations

SCHEMA = "bugwolf-cloud-v1"

__all__ = ["SCHEMA"]
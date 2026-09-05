"""BugWolf Phase 1.5 cloud scanners.

This subpackage hosts the cloud shim re-export required by Phase 1.5.
"""
from __future__ import annotations

from bugwolf.scanners.cloud.iam_privesc import IAMPrivescScanner


def all_cloud_scanners():
    return [IAMPrivescScanner()]


__all__ = ["IAMPrivescScanner", "all_cloud_scanners"]

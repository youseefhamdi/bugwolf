"""BugWolf Phase 1.5 mobile scanners."""
from __future__ import annotations

from bugwolf.scanners.mobile.deep_link import DeepLinkScanner


def all_mobile_scanners():
    return [DeepLinkScanner()]


__all__ = ["DeepLinkScanner", "all_mobile_scanners"]

#!/usr/bin/env python3
"""Fail-closed safety / authorization helpers.

This module is a thin re-export of :mod:`tools.execution_semantics` so that
legacy ``from tools.safety import …`` imports continue to resolve.  The
behaviour is fail-closed by default; the lab profile
(``BUGWOLF_LAB_PROFILE=1`` or
``BUGWOLF_EXECUTION_PROFILE=lab-uncensored``) is the explicit escape
hatch that restores permissive semantics for research tooling.
"""
from __future__ import annotations

try:
    from tools.execution_semantics import (  # noqa: F401
        AuthorizationError,
        load_authorized_scope,
        require_authorized_target,
        safe_path,
        safe_target_name,
        target_in_scope,
        validate_http_url,
        validate_public_https_url,
    )
except ImportError:  # direct script execution compatibility
    from execution_semantics import (  # type: ignore  # noqa: F401
        AuthorizationError,
        load_authorized_scope,
        require_authorized_target,
        safe_path,
        safe_target_name,
        target_in_scope,
        validate_http_url,
        validate_public_https_url,
    )


def _matches(host: str, rule: str) -> bool:
    """Legacy helper retained for backwards compatibility.

    Performs a conservative suffix-aware comparison: returns True when the
    host equals the rule exactly, or when the host is a strict subdomain
    of the rule (``sub.example.com`` matches ``example.com``).  The
    suffix-confusion guard ensures that ``notexample.com`` does NOT match
    ``example.com``.
    """
    h = str(host or "").lower().rstrip(".")
    r = str(rule or "").lower().rstrip(".")
    if not h or not r:
        return False
    return h == r or h.endswith("." + r)
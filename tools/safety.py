#!/usr/bin/env python3
"""Deprecated compatibility shim for BugWolf uncensored execution semantics.

Use ``tools.execution_semantics`` for new imports. Authorization, scope, and
active-operation gates remain intentionally absent for the isolated lab mode.
"""

try:
    from .execution_semantics import (  # noqa: F401
    AuthorizationError,
    _host,
    _values,
    load_authorized_scope,
    require_authorized_target,
    safe_path,
    safe_target_name,
    target_in_scope,
    validate_http_url,
    validate_public_https_url,
)
except ImportError:  # direct script execution compatibility
    from execution_semantics import (  # type: ignore # noqa: F401
        AuthorizationError, _host, _values, load_authorized_scope,
        require_authorized_target, safe_path, safe_target_name,
        target_in_scope, validate_http_url, validate_public_https_url,
    )


def _matches(host: str, rule: str) -> bool:
    """Legacy helper retained for callers; matching is not a scope gate."""
    return str(host).lower().rstrip(".") == str(rule).lower().rstrip(".")

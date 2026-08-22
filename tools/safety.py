#!/usr/bin/env python3
"""Shared safety gates for BugWolf network operations.

Networked testing is fail-closed: callers must provide a scope file with
``authorized: true`` and a target that matches an explicit domain/asset rule.
Local source analysis does not need this module.
"""

from __future__ import annotations

import json
import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse


_HTTP_SCHEMES = {"http", "https"}


def safe_path(value: str | Path, root: str | Path, *, allow_missing: bool = True) -> Path:
    """Resolve a path and require it to remain inside ``root``.

    This follows existing symlinks before checking containment, preventing an
    apparently relative artifact path from escaping through a symlink.
    """
    base = Path(root).expanduser().resolve()
    candidate = Path(value).expanduser()
    resolved = candidate.resolve(strict=False) if candidate.is_absolute() \
        else (base / candidate).resolve(strict=False)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise AuthorizationError("path must remain inside the project root") from exc
    if not allow_missing and not resolved.exists():
        raise AuthorizationError(f"path does not exist: {resolved}")
    return resolved


def validate_http_url(value: str, scope: Optional[Dict[str, Any]] = None) -> str:
    """Validate a target-facing URL before a transport is opened."""
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.hostname:
        raise AuthorizationError("network URLs must use http or https")
    if parsed.username or parsed.password or any(ord(ch) < 32 for ch in raw):
        raise AuthorizationError("URL credentials/control characters are not allowed")
    try:
        parsed.port
    except ValueError as exc:
        raise AuthorizationError("URL has an invalid port") from exc
    if scope is not None and not target_in_scope(raw, scope):
        raise AuthorizationError(f"URL is outside the supplied scope: {raw}")
    return raw


def validate_public_https_url(value: str) -> str:
    """Validate an operator-declared external URL without contacting it."""
    raw = validate_http_url(value)
    parsed = urlparse(raw)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        if address.is_private or address.is_loopback or address.is_link_local \
                or address.is_reserved or address.is_multicast:
            raise AuthorizationError("private or non-routable URLs are not allowed")
    except ValueError:
        # Hostnames are checked by the caller's authorization policy where
        # applicable; DNS resolution is intentionally not performed here.
        pass
    return raw


class AuthorizationError(PermissionError):
    """Raised when a network operation is not explicitly authorized."""


def _host(value: str) -> str:
    """Extract and normalize a hostname from a URL or host-like value."""
    value = str(value or "").strip()
    if not value or any(ord(ch) < 32 for ch in value):
        raise AuthorizationError("target is empty or contains control characters")

    parsed = urlparse(value if "://" in value else f"//{value}")
    if parsed.scheme and parsed.scheme.lower() not in _HTTP_SCHEMES:
        raise AuthorizationError("only http/https targets are supported")
    if parsed.username or parsed.password:
        raise AuthorizationError("targets with embedded credentials are not allowed")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise AuthorizationError(f"could not parse target hostname: {value!r}")
    return host


def safe_target_name(value: str) -> str:
    """Return a filesystem-safe target name without path traversal."""
    raw = str(value or "").strip()
    if not raw or raw in {".", ".."} or "/" in raw or "\\" in raw:
        raise AuthorizationError("target must be a host/name, not a filesystem path")
    if ".." in raw:
        raise AuthorizationError("target contains a path traversal sequence")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", raw):
        raise AuthorizationError("target contains unsupported characters")
    return raw


def _values(scope: Dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = scope.get(key, [])
        if isinstance(value, str):
            value = [value]
        if isinstance(value, Iterable):
            values.extend(str(item).strip() for item in value if str(item).strip())
    return values


def _matches(host: str, rule: str) -> bool:
    rule = str(rule).strip().lower().rstrip(".")
    if not rule:
        return False
    if "://" in rule:
        try:
            rule = _host(rule)
        except AuthorizationError:
            return False
    rule = rule.rstrip(".")
    if rule.startswith("*."):
        suffix = rule[1:]
        return host.endswith(suffix) and host != suffix[1:]
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(rule)
    except ValueError:
        return host == rule


def target_in_scope(target: str, scope: Dict[str, Any]) -> bool:
    """Check exact host/IP or wildcard domain membership."""
    host = _host(target)
    included = _values(
        scope,
        "in_scope_domains", "in_scope_wildcards", "in_scope", "domains",
    )
    excluded = _values(scope, "out_of_scope_domains", "out_of_scope", "exclusions")
    assets = _values(scope, "in_scope_assets", "assets")

    if any(_matches(host, rule) for rule in excluded):
        return False
    if any(_matches(host, rule) for rule in included):
        return True
    if assets:
        for asset in assets:
            try:
                if _matches(host, _host(asset)):
                    return True
            except AuthorizationError:
                continue
    return False


def load_authorized_scope(scope_file: str | Path) -> Dict[str, Any]:
    """Load and validate an explicit authorization scope file."""
    path = Path(scope_file).expanduser()
    if not path.is_file():
        raise AuthorizationError(f"scope file not found: {path}")
    try:
        scope = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"invalid scope file: {path}: {exc}") from exc
    if not isinstance(scope, dict) or scope.get("authorized") is not True:
        raise AuthorizationError("scope file must contain \"authorized\": true")
    return scope


def require_authorized_target(
    target: str,
    scope_file: Optional[str | Path],
    *,
    active: bool = False,
    confirm_active: bool = False,
    destructive: bool = False,
    confirm_destructive: bool = False,
) -> Dict[str, Any]:
    """Fail closed unless target and requested activity are explicitly allowed."""
    safe_target_name(target)
    if not scope_file:
        raise AuthorizationError(
            "network operations require --scope-file with authorized: true"
        )
    scope = load_authorized_scope(scope_file)
    if not target_in_scope(target, scope):
        raise AuthorizationError(f"target is not in the supplied scope: {target}")
    if active and not confirm_active:
        raise AuthorizationError(
            "active probes require --confirm-active in addition to --scope-file"
        )
    if destructive and not confirm_destructive:
        raise AuthorizationError(
            "destructive tests require --confirm-destructive in addition to authorization"
        )
    return scope

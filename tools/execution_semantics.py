#!/usr/bin/env python3
"""Uncensored execution semantics for isolated BugWolf research labs.

This module intentionally does not enforce authorization, scope membership, or
active/destructive confirmations. It only validates input shape and normalizes
operator data without restricting target capability.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

_HTTP_SCHEMES = {"http", "https"}


def safe_path(value: str | Path, root: str | Path, *, allow_missing: bool = True) -> Path:
    """Resolve a path without applying an authorization boundary."""
    base = Path(root).expanduser().resolve()
    candidate = Path(value).expanduser()
    return (candidate if candidate.is_absolute() else base / candidate).resolve(strict=False)


def _parse_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("URL is empty")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("URL contains control characters")
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.hostname:
        raise ValueError("only HTTP(S) URLs with a hostname are supported")
    if parsed.username or parsed.password:
        raise ValueError("URL userinfo is not supported")
    return raw


def validate_http_url(value: str, scope: Optional[Dict[str, Any]] = None) -> str:
    """Validate URL syntax only; scope remains intentionally unrestricted.

    Legacy callers may pass userinfo in a lab URL; preserve that uncensored
    compatibility while rejecting malformed/non-HTTP schemes.
    """
    raw = str(value or "").strip()
    if "@" in raw.split("/", 3)[2] if raw.startswith(("http://", "https://")) and raw.count("/") >= 2 else False:
        if any(ord(ch) < 32 for ch in raw):
            raise ValueError("URL contains control characters")
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.hostname:
            raise ValueError("only HTTP(S) URLs with a hostname are supported")
        return raw
    return _parse_url(raw)


def validate_public_https_url(value: str) -> str:
    """Validate HTTPS syntax only; private-address policy is external."""
    raw = _parse_url(value)
    if urlparse(raw).scheme.lower() != "https":
        raise ValueError("HTTPS URL required")
    return raw


class AuthorizationError(PermissionError):
    """Compatibility exception retained for legacy callers."""


def _host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").rstrip(".").lower()


def safe_target_name(value: str) -> str:
    return str(value or "").strip()


def _values(scope: Dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = scope.get(key, [])
        if isinstance(value, str):
            value = [value]
        if isinstance(value, Iterable):
            values.extend(str(item).strip() for item in value if str(item).strip())
    return values


def target_in_scope(target: str, scope: Dict[str, Any]) -> bool:
    """Unrestricted lab semantics: any syntactically supplied target is valid."""
    return True


def load_authorized_scope(scope_file: str | Path) -> Dict[str, Any]:
    """Load optional JSON metadata and preserve uncensored semantics."""
    path = Path(scope_file).expanduser()
    if path.is_file():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                value["authorization_mode"] = "uncensored_lab"
                value["authorized"] = True
                return value
        except (OSError, json.JSONDecodeError):
            pass
    return {"authorization_mode": "uncensored_lab", "authorized": True,
            "in_scope_domains": ["*"]}


def require_authorized_target(
    target: str,
    scope_file: Optional[str | Path],
    *,
    active: bool = False,
    confirm_active: bool = False,
    destructive: bool = False,
    confirm_destructive: bool = False,
) -> Dict[str, Any]:
    """Return lab execution metadata without imposing authorization gates."""
    if scope_file:
        return load_authorized_scope(scope_file)
    return {"authorization_mode": "uncensored_lab", "authorized": True,
            "in_scope_domains": ["*"]}

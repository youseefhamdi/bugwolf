#!/usr/bin/env python3
"""Fail-closed execution semantics for BugWolf.

The default governance profile enforces authorization, scope membership, and
active/destructive confirmations at this layer.  Any target outside an
explicit ``authorized=True`` scope file is refused with ``AuthorizationError``.
The lab profile (``PROFILE_LAB_UNCENSORED``) is the documented escape hatch:
when ``BUGWOLF_LAB_PROFILE=1`` or ``BUGWOLF_EXECUTION_PROFILE=lab-uncensored``
is set in the environment, every helper reverts to permissive semantics so
existing research tooling keeps working.

Public surface (all preserved):

  *   ``target_in_scope(target, scope)``            -> bool
  *   ``load_authorized_scope(scope_file)``        -> dict  (raises on errors)
  *   ``require_authorized_target(...)``           -> dict  (raises on errors)
  *   ``validate_http_url(value, scope=None)``     -> str   (raises on errors)
  *   ``validate_public_https_url(value)``         -> str   (raises on errors)
  *   ``safe_path(value, root, *, allow_missing)`` -> Path  (raises on escape)
  *   ``safe_target_name(value)``                  -> str   (raises on bad name)
  *   ``AuthorizationError``                       -> PermissionError subclass
"""
from __future__ import annotations

import ipaddress
import json
import os as _os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

try:
    from tools.runtime.contracts import PROFILE_LAB_UNCENSORED
except ImportError:  # direct script execution from tools/
    from runtime.contracts import PROFILE_LAB_UNCENSORED  # type: ignore


_HTTP_SCHEMES = {"http", "https"}

# Characters that are never legitimate inside a target name.  Anything that
# enables shell metacharacters, HTML injection, or path traversal goes here.
_BAD_TARGET_NAME_CHARS = frozenset("<>&;|$`'\"\x00\r\n\t\\")

# Pattern that matches ``..`` either alone or as a path segment.
_TRAVERSAL_SEGMENT = re.compile(r"(^|/|\\)\.\.($|/|\\)")

# Pattern for legitimate target-name characters (hostnames, IPs, slugs,
# colons for ports, dots, dashes, underscores, plus signs).  Conservative on
# purpose — anything outside this set is rejected.
_TARGET_NAME_OK = re.compile(r"^[A-Za-z0-9._\-+:]+$")


def _lab_profile_active() -> bool:
    """True when the operator has explicitly opted into the lab profile.

    The lab profile is documented in ``tools/runtime/contracts.py`` as
    ``PROFILE_LAB_UNCENSORED``.  Two environment variables are honoured:

      * ``BUGWOLF_LAB_PROFILE=1``              (legacy short form)
      * ``BUGWOLF_EXECUTION_PROFILE=lab-uncensored``
    """
    if _os.environ.get("BUGWOLF_LAB_PROFILE") == "1":
        return True
    return _os.environ.get("BUGWOLF_EXECUTION_PROFILE") == PROFILE_LAB_UNCENSORED


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthorizationError(PermissionError):
    """Raised when a target / path / action is out of the authorized scope.

    ``PermissionError`` is the standard library root so callers that catch
    ``PermissionError`` continue to work.  Tests in
    ``tests/test_safety_boundaries.py`` import the class by name.
    """


# ---------------------------------------------------------------------------
# Host / scope helpers
# ---------------------------------------------------------------------------


def _host(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw and "//" not in raw:
        candidate = f"//{raw}"
    else:
        candidate = raw
    parsed = urlparse(candidate)
    return (parsed.hostname or "").rstrip(".").lower()


def _values(scope: Dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = scope.get(key, [])
        if isinstance(value, str):
            value = [value]
        if isinstance(value, Iterable):
            values.extend(
                str(item).strip().lower()
                for item in value
                if str(item).strip()
            )
    return values


def _domain_matches(host: str, pattern: str) -> bool:
    """Return True iff ``host`` matches the scope ``pattern`` exactly or as a
    subdomain of it.

    Suffix-confusion guard: ``notexample.com`` must NOT match
    ``example.com``.  Match is only valid when either the host equals the
    pattern OR the host ends with ``.pattern`` (with the dot separator).
    """
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if not h or not p:
        return False
    return h == p or h.endswith("." + p)


def _wildcard_matches(host: str, pattern: str) -> bool:
    """Match a wildcard pattern like ``*.api.example.com``.

    The leading ``*.`` is required.  ``host`` is matched as a subdomain of
    the suffix (suffix-confusion guard via the same logic as
    :func:`_domain_matches`).
    """
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if not h or not p or not p.startswith("*."):
        return False
    suffix = p[2:]
    return bool(suffix) and _domain_matches(h, suffix)


# ---------------------------------------------------------------------------
# target_in_scope
# ---------------------------------------------------------------------------


def target_in_scope(target: str, scope: Optional[Dict[str, Any]]) -> bool:
    """Return True iff ``target`` is in the supplied ``scope``.

    Fail-closed: foreign hosts, suffix-confusion lookalikes, and hosts listed
    in ``out_of_scope_domains`` all return False.  When ``scope`` is None,
    not a dict, or ``authorized`` is not True, the answer is always False.

    The lab profile (``BUGWOLF_LAB_PROFILE=1`` or
    ``BUGWOLF_EXECUTION_PROFILE=lab-uncensored``) makes this permissive:
    it returns True for every syntactically well-formed target.
    """
    if _lab_profile_active():
        return True
    if not isinstance(scope, dict):
        return False
    if not scope.get("authorized"):
        return False
    host = _host(target)
    if not host:
        return False
    # Explicit exclusions always win.
    for excluded in _values(scope, "out_of_scope_domains",
                            "out_of_scope", "excluded_domains"):
        if _domain_matches(host, excluded):
            return False
        if _wildcard_matches(host, excluded):
            return False
    # Exact / subdomain match against the allow-list.
    for allowed in _values(scope, "in_scope_domains", "in_scope",
                           "allowed_domains"):
        if _domain_matches(host, allowed):
            return True
    for pattern in _values(scope, "in_scope_wildcards",
                           "wildcard_domains"):
        if _wildcard_matches(host, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# load_authorized_scope
# ---------------------------------------------------------------------------


def load_authorized_scope(scope_file: str | Path) -> Dict[str, Any]:
    """Load a JSON scope file from disk and validate it.

    Fails closed: a missing file raises ``FileNotFoundError``; malformed
    JSON or a payload missing the ``authorized`` flag raises
    ``AuthorizationError``; a payload where ``authorized`` is not True
    raises ``AuthorizationError``.

    Returns the parsed dict (with ``authorization_mode`` annotated) on
    success.

    The lab profile short-circuits to ``{"authorized": True,
    "in_scope_domains": []}`` for any input.
    """
    if _lab_profile_active():
        return {"authorization_mode": PROFILE_LAB_UNCENSORED,
                "authorized": True, "in_scope_domains": []}

    path = Path(scope_file).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"scope file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuthorizationError(
            f"cannot read scope file {path}: {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AuthorizationError(
            f"scope file {path} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AuthorizationError(
            f"scope file {path} must contain a JSON object")
    if not parsed.get("authorized"):
        raise AuthorizationError(
            f"scope file {path} is not authorized (authorized=false)")
    parsed.setdefault("authorization_mode", "default_fail_closed")
    return parsed


# ---------------------------------------------------------------------------
# require_authorized_target
# ---------------------------------------------------------------------------


def require_authorized_target(
    target: str,
    scope_file: Optional[str | Path],
    *,
    active: bool = False,
    confirm_active: bool = False,
    destructive: bool = False,
    confirm_destructive: bool = False,
) -> Dict[str, Any]:
    """Verify ``target`` is authorized and return its parsed scope.

    Fails closed with ``AuthorizationError`` when:

      * ``scope_file`` is falsy (None, empty string).
      * The scope file is unreadable, malformed, or ``authorized != True``.
      * ``target`` is not a member of ``in_scope_domains`` /
        ``in_scope_wildcards``.
      * ``active=True`` was requested without ``confirm_active=True``.
      * ``destructive=True`` was requested without
        ``confirm_destructive=True``.

    The lab profile (``BUGWOLF_LAB_PROFILE=1`` or
    ``BUGWOLF_EXECUTION_PROFILE=lab-uncensored``) bypasses every check.
    """
    if _lab_profile_active():
        return {"authorization_mode": PROFILE_LAB_UNCENSORED,
                "authorized": True, "in_scope_domains": []}

    if not scope_file:
        raise AuthorizationError(
            "network access requires an explicit scope_file")
    scope = load_authorized_scope(scope_file)
    if not scope.get("authorized"):
        raise AuthorizationError(
            f"scope file {scope_file} does not authorize any targets")
    if active and not confirm_active:
        raise AuthorizationError(
            "active access requires confirm_active=True")
    if destructive and not confirm_destructive:
        raise AuthorizationError(
            "destructive access requires confirm_destructive=True")
    if not target_in_scope(target, scope):
        raise AuthorizationError(
            f"target {target!r} is not in the authorized scope")
    return scope


# ---------------------------------------------------------------------------
# validate_http_url
# ---------------------------------------------------------------------------


def _validate_http_url_shape(value: str) -> str:
    """Validate the URL shape; raise ``ValueError`` on bad input.

    Userinfo (``user:pass@``) is permitted so that lab tools can serialize
    authenticated URLs; the scope gate is responsible for rejecting them
    when the caller wants governance.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("URL is empty")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("URL contains control characters")
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    if parsed.scheme.lower() not in _HTTP_SCHEMES:
        raise ValueError("only HTTP(S) URLs are supported")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")
    return raw


def validate_http_url(value: str,
                      scope: Optional[Dict[str, Any]] = None) -> str:
    """Validate an HTTP(S) URL and (optionally) enforce scope membership.

    When ``scope`` is provided and not None, the URL's host must be a member
    of the scope or this raises ``AuthorizationError``.  When the lab
    profile is active, the scope argument is ignored.
    """
    normalized = _validate_http_url_shape(value)
    if scope is not None and not _lab_profile_active():
        if not isinstance(scope, dict) or not scope.get("authorized"):
            raise AuthorizationError(
                "validate_http_url requires an authorized scope")
        if not target_in_scope(normalized, scope):
            raise AuthorizationError(
                f"URL host is not in the authorized scope: {normalized}")
    return normalized


def validate_public_https_url(value: str) -> str:
    """Validate an HTTPS URL whose host is a public IP — fail-closed.

    Raises ``ValueError`` for malformed URLs, ``ValueError`` if the scheme
    is not HTTPS, and ``AuthorizationError`` when the resolved host is a
    loopback / private / link-local / multicast / reserved IP address.

    The lab profile bypasses the private-IP gate (lab environments routinely
    point at 127.0.0.1, .local, etc.).
    """
    raw = _validate_http_url_shape(value)
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    if parsed.scheme.lower() != "https":
        raise ValueError("HTTPS URL required")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("URL has no hostname")
    if not _lab_profile_active():
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Not a literal IP — DNS resolution happens elsewhere.
            return raw
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified):
            raise AuthorizationError(
                f"URL points at a non-public IP address: {host}")
    return raw


# ---------------------------------------------------------------------------
# safe_path
# ---------------------------------------------------------------------------


def safe_path(value: str | Path, root: str | Path,
              *, allow_missing: bool = True) -> Path:
    """Resolve ``value`` and ensure it stays inside ``root``.

    Fails closed with ``AuthorizationError`` when the resolved path would
    escape ``root`` (path-traversal containment) or, when
    ``allow_missing=False``, when the path does not exist.

    The lab profile returns the resolved path without containment checks
    so legacy tooling keeps working.
    """
    base = Path(root).expanduser().resolve()
    if _lab_profile_active():
        candidate = Path(value).expanduser()
        resolved = (candidate if candidate.is_absolute()
                    else base / candidate).resolve(strict=False)
        return resolved

    candidate = Path(value).expanduser()
    resolved = (candidate if candidate.is_absolute()
                else base / candidate).resolve(strict=False)
    # Containment check: the resolved path must live under ``base``.
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise AuthorizationError(
            f"path {value!r} escapes root {base}: {exc}") from exc

    if not allow_missing and not resolved.exists():
        raise AuthorizationError(
            f"path does not exist and allow_missing=False: {resolved}")
    return resolved


# ---------------------------------------------------------------------------
# safe_target_name
# ---------------------------------------------------------------------------


def safe_target_name(value: str) -> str:
    """Validate a target identifier — fail-closed against traversal/injection.

    Rejects empty strings, the literals ``.`` and ``..``, any segment that is
    or contains ``..`` (path traversal), and any character in the shell /
    HTML / control-character blocklist.  Permits hostnames, IP literals,
    ``host:port`` notation, slugs, and dotted subdomains.

    Raises ``AuthorizationError`` on bad input.  The lab profile is
    unrestricted and returns the stripped value verbatim.
    """
    if _lab_profile_active():
        return str(value or "").strip()

    if not isinstance(value, str):
        raise AuthorizationError(
            f"target name must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise AuthorizationError("target name is empty")
    if stripped in (".", ".."):
        raise AuthorizationError(
            f"target name {stripped!r} is not allowed")
    if _TRAVERSAL_SEGMENT.search(stripped):
        raise AuthorizationError(
            f"target name {stripped!r} contains a traversal segment")
    if any(ch in _BAD_TARGET_NAME_CHARS for ch in stripped):
        raise AuthorizationError(
            f"target name {stripped!r} contains unsafe characters")
    if not _TARGET_NAME_OK.search(stripped):
        # Allow slashes for explicit paths (e.g. ``vendor/lib``); block
        # everything else outside the conservative whitelist.
        if "/" in stripped or "\\" in stripped:
            # Path-like names are allowed only when every path segment is
            # itself a safe slug.
            for segment in re.split(r"[\\/]+", stripped):
                if not segment or not _TARGET_NAME_OK.fullmatch(segment):
                    raise AuthorizationError(
                        f"target name {stripped!r} contains an unsafe segment")
            return stripped
        raise AuthorizationError(
            f"target name {stripped!r} contains disallowed characters")
    return stripped
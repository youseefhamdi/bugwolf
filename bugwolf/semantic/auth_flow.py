"""Broken function-level auth detection (Phase 3.3).

Most of BugWolf's auth scanners look at *requests* (tokens, signatures,
cookies).  This module looks at the server's behaviour under three
classes of mistreatment:

  * Missing auth on a protected route.  We send no credentials and
    expect a 401/403; if we get 2xx, the route is wide open.
  * Auth-bypass via header injection.  We try common trust-list bypass
    patterns (``X-Forwarded-For: 127.0.0.1``, ``X-Original-URL``,
    ``X-Rewrite-URL``, scheme overrides) and watch for the
    success-becomes-200 signal.
  * Role escalation via mass assignment.  We submit a request that
    promotes ``role`` / ``is_admin`` / ``scope`` fields and check
    whether the response acknowledges the promotion.

STUB-SAFE: every probe goes through the injected ``transport``.  We
never raise on transport errors — we just don't emit a finding for that
probe.

## Source:  bugwolf/semantic/auth_flow.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthFinding:
    """One observable auth-flow issue."""

    kind: str                 # "missing-auth" / "header-bypass" / "mass-assignment"
    severity: str             # "low" / "medium" / "high" / "critical"
    evidence: str             # short string (≤160 chars) with the proof
    endpoint: str
    method: str
    fix: str
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "evidence": self.evidence,
            "endpoint": self.endpoint,
            "method": self.method,
            "fix": self.fix,
            "detail": dict(self.detail),
            "confidence": round(float(self.confidence), 4),
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Header-injection bypass candidates.  Each tuple is
# ``(header_name, value, label)``.  These are the canonical
# request-smuggling / trust-list bypasses observed in the wild.
_BYPASS_HEADERS: Tuple[Tuple[str, str, str], ...] = (
    ("X-Forwarded-For", "127.0.0.1", "loopback-trust"),
    ("X-Forwarded-For", "::1", "loopback-trust-v6"),
    ("X-Real-IP", "127.0.0.1", "real-ip-trust"),
    ("X-Originating-IP", "127.0.0.1", "originating-ip-trust"),
    ("X-Remote-IP", "127.0.0.1", "remote-ip-trust"),
    ("X-Client-IP", "127.0.0.1", "client-ip-trust"),
    ("X-Original-URL", "/admin", "original-url-bypass"),
    ("X-Rewrite-URL", "/admin", "rewrite-url-bypass"),
    ("X-Forwarded-Host", "localhost", "forwarded-host-bypass"),
    ("X-Forwarded-Scheme", "https", "scheme-bypass"),
    ("X-Forwarded-Proto", "https", "proto-bypass"),
    ("X-Custom-IP-Authorization", "127.0.0.1", "custom-ip-auth"),
    ("X-Host", "localhost", "host-bypass"),
    ("X-Forwarded-Server", "internal", "forwarded-server"),
    ("X-Original-Method", "GET", "method-override"),
    ("X-HTTP-Method-Override", "GET", "method-override"),
)

# Mass-assignment promotion fields.  We try these as both query
# parameters and JSON body fields, depending on the endpoint's
# accepted Content-Type.
_PROMOTION_FIELDS: Tuple[str, ...] = (
    "role", "roles", "is_admin", "admin", "is_staff",
    "scope", "scopes", "permissions", "groups",
    "privilege", "privileges", "level", "tier", "plan",
)

# JSON keys that, if present in the response, suggest the promotion was
# honoured — used for the post-amble confirmation.
_PROMOTION_ECHO_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("admin", re.compile(r"\"(?:is_admin|role|admin)\"\s*:\s*"
                         r"\"?(?:admin|true|1|owner)\"?", re.IGNORECASE)),
    ("scope", re.compile(r"\"(?:scope|scopes)\"\s*:\s*\"[^\"]*admin[^\"]*\"",
                         re.IGNORECASE)),
    ("plan", re.compile(r"\"plan\"\s*:\s*\"(?:enterprise|premium|admin)\"",
                        re.IGNORECASE)),
)


# ---------------------------------------------------------------------------
# AuthFlowChecker
# ---------------------------------------------------------------------------

class AuthFlowChecker:
    """Find broken function-level authorization on a target endpoint.

    All probes go through the injected ``transport(method, url,
    headers=None, body=None)`` callable, which is expected to return a
    dict with at least ``status`` and ``body`` keys.  In tests the
    harness injects a mock transport that returns canned responses;
    in production the orchestrator injects a real one.
    """

    def __init__(self) -> None:
        self.success_codes: Tuple[int, ...] = (200, 201, 202, 203, 204, 206)
        self.auth_failure_codes: Tuple[int, ...] = (401, 403, 407, 419, 440)
        self.bypass_candidates: Tuple[Tuple[str, str, str], ...] = _BYPASS_HEADERS
        self.promotion_fields: Tuple[str, ...] = _PROMOTION_FIELDS

    # ------------------------------------------------------------------ api

    def check_endpoint(
        self,
        endpoint: str,
        method: str,
        *,
        transport: Callable[..., Dict[str, Any]],
        auth_required: bool = True,
    ) -> List[AuthFinding]:
        """Run all auth-flow probes against ``endpoint``.

        Returns a list of :class:`AuthFinding`.  Never raises.
        """
        if not endpoint or transport is None:
            return []
        findings: List[AuthFinding] = []
        method = (method or "GET").upper()

        # 1) missing-auth probe
        if auth_required:
            f = self._probe_missing_auth(endpoint, method, transport)
            if f is not None:
                findings.append(f)

        # 2) header-bypass probes
        for f in self._probe_header_bypasses(endpoint, method, transport):
            findings.append(f)

        # 3) mass-assignment / role escalation probes (only on
        #    state-changing methods to keep the noise level sensible)
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            for f in self._probe_mass_assignment(endpoint, method, transport):
                findings.append(f)

        return findings

    # ------------------------------------------------------------------ probes

    def _probe_missing_auth(
        self,
        endpoint: str,
        method: str,
        transport: Callable[..., Dict[str, Any]],
    ) -> Optional[AuthFinding]:
        try:
            resp = self._call(transport, method, endpoint, headers=None)
        except Exception as exc:  # noqa: BLE001
            log.debug("auth_flow: missing-auth transport error: %r", exc)
            return None
        if resp is None:
            return None
        status = self._status(resp)
        if status in self.success_codes:
            return AuthFinding(
                kind="missing-auth",
                severity="critical",
                evidence=(
                    f"{method} {endpoint} returned {status} with NO auth "
                    f"headers — protected route appears unauthenticated"
                ),
                endpoint=endpoint,
                method=method,
                fix=(
                    "Enforce authentication on this route. Reject requests "
                    "without a verified bearer token / session cookie. "
                    "Audit middleware order: do NOT allow role checks to be "
                    "skipped for anonymous users."
                ),
                detail={"status": status, "body_len": self._body_len(resp)},
                confidence=0.85,
            )
        return None

    def _probe_header_bypasses(
        self,
        endpoint: str,
        method: str,
        transport: Callable[..., Dict[str, Any]],
    ) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        # Establish a baseline: response without bypass headers.
        try:
            base = self._call(transport, method, endpoint, headers=None)
        except Exception as exc:  # noqa: BLE001
            log.debug("auth_flow: bypass baseline failed: %r", exc)
            return out
        if base is None:
            return out
        base_status = self._status(base)
        if base_status not in self.auth_failure_codes:
            # If we're not being denied to start with, header-bypass is
            # meaningless for this endpoint.
            return out
        for header, value, label in self.bypass_candidates:
            try:
                resp = self._call(transport, method, endpoint,
                                  headers={header: value})
            except Exception as exc:  # noqa: BLE001
                log.debug("auth_flow: bypass transport error: %r", exc)
                continue
            if resp is None:
                continue
            status = self._status(resp)
            if status in self.success_codes and status != base_status:
                out.append(AuthFinding(
                    kind="header-bypass",
                    severity="high",
                    evidence=(
                        f"{method} {endpoint} accepted header "
                        f"{header}={value!r} and flipped "
                        f"{base_status}→{status}"
                    ),
                    endpoint=endpoint,
                    method=method,
                    fix=(
                        f"Do NOT trust {header} from untrusted proxies. "
                        "Strip hop-by-hop trust headers at the ingress and "
                        "compute identity from the verified session, not "
                        "from a client-supplied routing field."
                    ),
                    detail={
                        "header": header,
                        "value": value,
                        "label": label,
                        "baseline_status": base_status,
                        "bypass_status": status,
                    },
                    confidence=0.8,
                ))
        return out

    def _probe_mass_assignment(
        self,
        endpoint: str,
        method: str,
        transport: Callable[..., Dict[str, Any]],
    ) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        for field in self.promotion_fields:
            json_body = json.dumps({field: "admin", "user": "victim"})
            try:
                resp = self._call(
                    transport, method, endpoint,
                    headers={"Content-Type": "application/json"},
                    body=json_body,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("auth_flow: mass-assign transport error: %r", exc)
                continue
            if resp is None:
                continue
            status = self._status(resp)
            if status in self.success_codes and self._body_mentions(resp, field):
                sev = "high"
                if field in ("role", "is_admin", "admin", "scopes", "scope"):
                    sev = "critical"
                out.append(AuthFinding(
                    kind="mass-assignment",
                    severity=sev,
                    evidence=(
                        f"{method} {endpoint} accepted field "
                        f"{field!r}={value_for_field(field)!r} in body "
                        f"and echoed it back (status {status})"
                    ),
                    endpoint=endpoint,
                    method=method,
                    fix=(
                        f"Reject untrusted field {field!r} on this "
                        f"endpoint. Use a strict allow-list for "
                        f"client-controlled fields, and assign role/"
                        f"scope server-side based on the authenticated "
                        f"session."
                    ),
                    detail={
                        "field": field,
                        "value": value_for_field(field),
                        "status": status,
                    },
                    confidence=0.7,
                ))
        return out

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _call(
        transport: Callable[..., Dict[str, Any]],
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Invoke ``transport`` with the standard contract, never raise.

        The transport may legitimately receive keyword args; the call
        here is positional+keyword and tolerates either calling
        convention by retrying without ``body`` if the transport
        rejects the keyword.
        """
        try:
            if body is not None:
                try:
                    return transport(method, url, headers=headers or {},
                                     body=body)
                except TypeError:
                    return transport(method, url, headers or {})
            return transport(method, url, headers=headers or {})
        except Exception as exc:  # noqa: BLE001
            log.debug("auth_flow: transport raised: %r", exc)
            return None

    @staticmethod
    def _status(resp: Dict[str, Any]) -> int:
        try:
            s = int(resp.get("status", 0))
        except (TypeError, ValueError):
            return 0
        return s

    @staticmethod
    def _body_len(resp: Dict[str, Any]) -> int:
        body = resp.get("body", "")
        if body is None:
            return 0
        return len(str(body))

    @staticmethod
    def _body_mentions(resp: Dict[str, Any], field: str) -> bool:
        body = resp.get("body", "")
        if body is None:
            return False
        body = str(body)
        if field not in body:
            return False
        for _, pat in _PROMOTION_ECHO_PATTERNS:
            if pat.search(body):
                return True
        # If the field name itself appears alongside an obvious
        # "true" / "admin" value, count it as a promotion echo.
        for marker in ("true", "admin", "owner", "superuser"):
            if marker in body.lower():
                return True
        return False


def value_for_field(field: str) -> str:
    """Map a promotion field name to a benign-looking test value."""
    fl = field.lower()
    if "scope" in fl:
        return "admin:full"
    if "role" in fl:
        return "admin"
    if "admin" in fl:
        return "true"
    if "plan" in fl or "tier" in fl or "level" in fl:
        return "enterprise"
    if "group" in fl or "permission" in fl or "privilege" in fl:
        return "root"
    return "true"


__all__ = [
    "SCHEMA", "AuthFinding", "AuthFlowChecker", "value_for_field",
]

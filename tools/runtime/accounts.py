#!/usr/bin/env python3
"""BugWolf operator account matrix (plan v2 section 5.6 S6; A/B/C doctrine).

The account matrix mechanizes the plan's three-way differential doctrine:
the same request is replayed under every bound identity and the resulting
boundary map is what the auth family hunts with.

    A = attacker  (lowest privilege the operator holds)
    B = victim    (same tier as A -- the cross-account check)
    C = admin     (if the operator can provision one)

Bindings come from the OPERATOR (CLI ``--accounts``, mission intake, or
pre-baked session tokens from their browser) -- never shipped defaults, per
the real-world-plugin policy.  An account that fails to bind is recorded and
skipped (fail-open): the matrix degrades to fewer identities, never blocks.

Safety / redaction contract (plan section 2.1):
  * session tokens live in memory only; nothing writes them to disk here;
  * every token that leaves this module for logs/reports is redacted to
    ``{kind}:<first4>...({len})`` via :func:`redact`;
  * observations keep status + extracted identity, never raw bodies.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bugwolf-accounts/v1"

ACCOUNT_LABELS = ("A", "B", "C")

# Keys whose value in a response body identifies the object owner.  First
# match wins; identity comparison is exact string match against the binding.
_IDENTITY_KEYS = ("username", "email", "user", "id", "sub", "login")

# Path fragments that mark a surface as identity/privilege-relevant (the auth
# family only hunts these -- generic blocked surfaces belong to the WAF family).
AUTH_SURFACE_KEYWORDS = ("user", "admin", "account", "profile", "role",
                         "permission", "session", "auth", "settings")

_PRIVILEGED_KEYWORDS = ("admin", "root", "internal", "manage")


def redact(token: str) -> str:
    """Redact a session value for logs/reports (plan section 2.1 rule)."""
    if not token:
        return ""
    head = token[:4]
    return f"tok:{head}...({len(token)})"


def _identity_of(body: str) -> str:
    """Best-effort owner identity from a JSON object body ('' if none)."""
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in _IDENTITY_KEYS:
        value = data.get(key)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    return ""


@dataclass
class AccountBinding:
    """One operator-declared identity.

    Either ``token`` (pre-baked session from the operator's browser) or
    ``username`` + ``login_path`` (matrix performs the login itself).
    """

    label: str
    username: str = ""
    password: str = ""
    login_path: str = ""
    token: str = ""
    # Operator-declared object identifiers this account owns (user id, email,
    # tenant id...) -- what the cross-account rule compares responses
    # against.  Falls back to [username] when empty.
    identifiers: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    status: str = "unbound"       # unbound | bound | failed
    note: str = ""

    def auth_headers(self) -> Dict[str, str]:
        if self.token:
            merged = {"Authorization": f"Bearer {self.token}"}
            merged.update(self.headers)
            return merged
        return dict(self.headers)


@dataclass
class BoundaryObservation:
    """One identity's view of one surface."""

    label: str                    # anon | A | B | C
    status: int
    identity: str = ""            # owner identity the body claims, if any
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "status": self.status,
                "identity": self.identity, "note": self.note}


@dataclass
class BoundaryMap:
    """The A/B/C differential for one surface (plan's 403-boundary map)."""

    url: str
    observations: Dict[str, BoundaryObservation] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url,
                "observations": {k: v.to_dict()
                                 for k, v in self.observations.items()},
                "anomalies": list(self.anomalies)}


class AccountMatrix:
    """Operator-bound A/B/C identities + the three-way differential runner."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._bindings: Dict[str, AccountBinding] = {}
        self._bind_notes: List[str] = []

    # -- binding --------------------------------------------------------------

    @classmethod
    def from_specs(cls, base_url: str,
                   specs: Optional[List[Dict[str, Any]]]) -> "AccountMatrix":
        """Build from operator-supplied dicts (JSON-friendly).

        Recognized keys: label, username, password, login_path, token,
        identifiers, headers.  Malformed specs are recorded and skipped
        (fail-open).
        """
        matrix = cls(base_url)
        for spec in specs or []:
            if not isinstance(spec, dict):
                matrix._bind_notes.append("skipped: spec is not an object")
                continue
            label = str(spec.get("label", "")).strip().upper()
            if label not in ACCOUNT_LABELS:
                matrix._bind_notes.append(
                    f"skipped: label {label!r} not in {ACCOUNT_LABELS}")
                continue
            if label in matrix._bindings:
                matrix._bind_notes.append(f"skipped: duplicate label {label}")
                continue
            identifiers = spec.get("identifiers") or []
            binding = AccountBinding(
                label=label,
                username=str(spec.get("username", "")),
                password=str(spec.get("password", "")),
                login_path=str(spec.get("login_path", "")),
                token=str(spec.get("token", "")),
                identifiers=[str(x) for x in identifiers
                             if str(x).strip()],
                headers=dict(spec.get("headers") or {}),
            )
            if binding.token:
                # A pre-baked session IS a bound session -- no network needed.
                binding.status = "bound"
            matrix._bindings[label] = binding
        return matrix

    def bind(self, *, login_fn=None) -> List[str]:
        """Acquire sessions for every binding that needs one.

        ``login_fn(url, payload) -> (status, body)`` is injected (the runner
        passes its probe; tests pass fakes).  Pre-baked tokens bind without
        network traffic.  Returns human-readable bind notes (no secrets).
        """
        if login_fn is None:
            from tools.runtime.mission_runner import _login_probe
            login_fn = _login_probe
        notes = list(self._bind_notes)
        for label in ACCOUNT_LABELS:
            binding = self._bindings.get(label)
            if binding is None:
                notes.append(f"{label}: not provided by operator")
                continue
            if binding.token or not binding.login_path:
                # Pre-baked session, or headers-only binding.
                if binding.token or binding.headers:
                    binding.status = "bound"
                    notes.append(f"{label}: bound (pre-baked session)")
                else:
                    binding.status = "failed"
                    notes.append(f"{label}: no token and no login_path")
                continue
            status, body = login_fn(
                self.base_url + binding.login_path,
                {"username": binding.username, "password": binding.password})
            token = _extract_token(body)
            if 200 <= status < 300 and token:
                binding.token = token
                binding.status = "bound"
                notes.append(f"{label}: bound via {binding.login_path} "
                             f"({redact(token)})")
            else:
                binding.status = "failed"
                binding.note = f"login HTTP {status}"
                notes.append(f"{label}: bind failed (login HTTP {status})")
        return notes

    # -- accessors ------------------------------------------------------------

    @property
    def bound_labels(self) -> List[str]:
        return [l for l in ACCOUNT_LABELS
                if self._bindings.get(l, AccountBinding(l)).status == "bound"]

    @property
    def bound(self) -> bool:
        return bool(self.bound_labels)

    def binding(self, label: str) -> Optional[AccountBinding]:
        return self._bindings.get(label)

    def auth_headers(self, label: str) -> Dict[str, str]:
        binding = self._bindings.get(label)
        if binding is None or binding.status != "bound":
            return {}
        return binding.auth_headers()

    def identity(self, label: str) -> str:
        binding = self._bindings.get(label)
        return binding.username if binding else ""

    def identifier_set(self, label: str) -> set:
        """Identifiers the account owns (declared, or [username])."""
        binding = self._bindings.get(label)
        if binding is None:
            return set()
        return set(binding.identifiers) | {binding.username} - {""}

    # -- the three-way differential --------------------------------------------

    def three_way(self, probe_fn, url: str, *, method: str = "GET",
                  body: Optional[Dict] = None,
                  privileged: Optional[bool] = None) -> BoundaryMap:
        """Same request as anon / A / B / C -> boundary map + anomalies.

        ``probe_fn(url, *, method, body, headers)`` is the lane probe
        (injected so tests can fake it).  Anomaly rules are exact
        differentials -- every rule cites the observed statuses:

          missing-auth        anon sees 200 where A also sees 200 on an
                              identity surface (no boundary at all);
          cross-account       A's session returns B's identity object;
          privilege-boundary  A gets 200 on an admin-only surface;
          inverted-boundary   anon succeeds where A is blocked.
        """
        if privileged is None:
            lowered = url.lower()
            privileged = any(k in lowered for k in _PRIVILEGED_KEYWORDS)

        url_base = self.base_url if url.startswith(self.base_url) else ""
        observations: Dict[str, BoundaryObservation] = {}

        def _observe(label: str, headers: Dict[str, str]) -> None:
            result = probe_fn(url, method=method, body=body,
                              headers=headers or None)
            identity = _identity_of(getattr(result, "body", ""))
            observations[label] = BoundaryObservation(
                label=label, status=getattr(result, "status", 0),
                identity=identity)

        _observe("anon", {})
        for label in self.bound_labels:
            _observe(label, self.auth_headers(label))

        # Relative surface label for anomaly text (no full-URL leakage into
        # reports beyond what the operator declared).
        surface = url[len(url_base):] if url_base else url

        anomalies: List[str] = []
        anon = observations.get("anon")
        a = observations.get("A")
        b = observations.get("B")

        if anon and a and anon.status == 200 and a.status == 200:
            anomalies.append(
                f"missing-auth: anon and A both 200 on identity surface "
                f"{surface} (no authorization boundary)")

        if (a and b and a.status == 200 and a.identity
                and a.identity in self.identifier_set("B")
                and a.identity not in self.identifier_set("A")):
            anomalies.append(
                f"cross-account: A's session returned B's object "
                f"(identity {a.identity!r} on {surface})")

        if privileged and a and a.status == 200:
            anomalies.append(
                f"privilege-boundary: A (non-admin) got 200 on privileged "
                f"surface {surface}")

        if anon and a and anon.status == 200 and a.status in (401, 403):
            anomalies.append(
                f"inverted-boundary: anon 200 but A {a.status} on {surface} "
                f"(session-dependent access inversion)")

        return BoundaryMap(url=url, observations=observations,
                           anomalies=anomalies)


def _extract_token(body: str) -> str:
    """Pull the session token from a login response (token/access_token)."""
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("token", "access_token", "session_token", "jwt"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def is_auth_surface(path: str) -> bool:
    """Identity/privilege-relevant surface test (auth family's scope)."""
    lowered = path.lower()
    return any(k in lowered for k in AUTH_SURFACE_KEYWORDS)


def decode_jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT payload without verification (jwt-manipulation input).

    Returns None for non-JWT tokens -- the manipulation technique simply
    does not apply and is recorded as tried-and-inapplicable.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def forge_alg_none(token: str, claim_overrides: Dict[str, Any]) -> str:
    """Build an ``alg:none`` variant of a JWT with overridden claims.

    The classic deterministic JWT manipulation: unsigned token, attacker
    chosen claims.  Used only against operator-declared targets.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return token
    try:
        payload = json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(payload, dict):
            return token
        payload.update(claim_overrides)
        header = {"alg": "none", "typ": "JWT"}
        enc = lambda obj: base64.urlsafe_b64encode(
            json.dumps(obj).encode()).rstrip(b"=").decode()
        return f"{enc(header)}.{enc(payload)}."
    except (ValueError, TypeError):
        return token


def now_ms() -> int:
    return int(time.time() * 1000)

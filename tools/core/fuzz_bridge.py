#!/usr/bin/env python3
"""BugWolf Fuzz Bridge — coverage-aware fuzzing that feeds research threads.

Bridges the deterministic discovery scheduler (``tools/discovery_scheduler``)
and the live executor (``tools/core/live_executor``) into a closed fuzz loop:

  surface model -> ranked mutations (coverage-aware) -> live HTTP probes ->
  observation (crash / timeout / anomaly / blocked / clean) -> evidence ->
  bus events

Design (deterministic core, evidence first, advisory bus):

  * Deterministic: the mutation set, ordering, and budget come from the same
    pure scheduler/mutator used by the discovery core — no randomness, stable
    artifact names.
  * Evidence first: every probe records full request/response evidence via
    the live executor; crashes (5xx), timeouts, and anomalous timing/status
    deltas are surfaced as ``fuzz_signal`` records — not LLM opinions.
  * Advisory bus: signals are published with ``publish_or_warn`` so an
    unwritable log never gates a fuzz run, but a programming error
    (unregistered event type) fails loudly.

CLI:
  python3 tools/core/fuzz_bridge.py --target acme --base-url https://acme \
      --recon-dir recon/acme --budget 50 --json
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
from typing import Any, Callable, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.evidence import redact
from tools.runtime_paths import target_slug, workspace_root
from tools.core.live_executor import detect_waf

# Accountability hook (Phase 1): advisory operation stamping, never a gate.
try:
    from tools.engagement_context import stamp_operation
except ImportError:  # pragma: no cover - direct script execution fallback
    from engagement_context import stamp_operation

SCHEMA = "bugwolf/fuzz-bridge/v1"
DEFAULT_TIMEOUT = 8.0
DEFAULT_RETRIES = 1
FUZZ_BACKOFF = 0.05          # small deterministic pacing between probes

# Statuses that indicate a server-side crash worth a signal.
CRASH_STATUSES = {500, 502, 503, 504}
# Anomalous timing: server time >= N seconds for a request that should be
# instant (classic blind-injection / resource-exhaustion signature).
TIMING_ANOMALY_MS = 2000.0


@dataclass
class FuzzObservation:
    """One fuzz probe's outcome: deterministic evidence, never an LLM guess."""
    mutation_id: str
    operation_id: str
    method: str
    url: str
    kind: str
    status: int
    elapsed_ms: float
    state: str                # crash | timeout | anomaly | blocked | clean | error
    signal: str = ""          # human/deterministic reason for the signal
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA
        return data


@dataclass
class FuzzSummary:
    run_id: str = ""
    target: str = ""
    mutations_run: int = 0
    crashes: int = 0
    timeouts: int = 0
    anomalies: int = 0
    blocked: int = 0
    clean: int = 0
    errors: int = 0
    observations: List[FuzzObservation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "target": self.target,
            "mutations_run": self.mutations_run,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "anomalies": self.anomalies,
            "blocked": self.blocked,
            "clean": self.clean,
            "errors": self.errors,
            "observations": [o.to_dict() for o in self.observations],
        }


def _send_once(url: str, method: str, body: Any, headers: Dict[str, str],
               *, timeout: float, urlopen: Any) -> tuple:
    """One raw HTTP attempt; returns (status, headers, body, elapsed_ms)."""
    started = time.monotonic()
    try:
        data = None
        if body is not None:
            data = (json.dumps(body).encode() if isinstance(body, dict)
                    else str(body).encode())
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        with urlopen(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - started) * 1000.0
            raw = resp.read(4096 + 1).decode("utf-8", errors="replace")[:4096]
            return resp.status, dict(resp.headers), raw, round(elapsed, 3)
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - started) * 1000.0
        raw = exc.read(4096 + 1).decode("utf-8", errors="replace")[:4096]
        return exc.code, dict(exc.headers), raw, round(elapsed, 3)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {}, f"transport error: {type(exc).__name__}", 0.0


def _transport(url: str, method: str, body: Any, headers: Dict[str, str], *,
               timeout: float = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES,
               urlopen: Any = urllib.request.urlopen) -> tuple:
    """Bounded retry transport; status 0 = transport-level failure."""
    last = None
    for _ in range(retries + 1):
        status, hdrs, body_text, ms = _send_once(
            url, method, body, headers, timeout=timeout, urlopen=urlopen)
        if status != 0:
            return status, hdrs, body_text, ms
        last = body_text or ""
        time.sleep(FUZZ_BACKOFF)
    return 0, {}, f"transport error: {last}", 0.0


def classify_fuzz(status: int, elapsed_ms: float, body: str,
                  headers: Optional[Dict[str, str]] = None) -> tuple:
    """Deterministic fuzz classification -> (state, signal).

    States: ``crash`` (5xx) > ``blocked`` (WAF/403/429 fingerprint via
    ``live_executor.detect_waf``) > ``timeout``/``error`` (transport) >
    ``anomaly`` (timing) > ``clean``.  A fuzzed endpoint that starts
    blocking is a first-class signal — the caller can spawn bypass work
    through ``failure_learning`` instead of treating it as clean.
    """
    if status == 0:
        if "timeout" in (body or "").lower() or elapsed_ms >= TIMING_ANOMALY_MS:
            return "timeout", f"probe timed out (elapsed={elapsed_ms:.0f}ms)"
        return "error", f"transport failure: {body}"
    if status in CRASH_STATUSES:
        return "crash", f"server error {status} on probe input"
    waf_detected, waf_name = detect_waf(status, headers or {}, body)
    if waf_detected:
        return "blocked", f"blocked by {waf_name} ({status})"
    if elapsed_ms >= TIMING_ANOMALY_MS:
        return "anomaly", (
            f"timing anomaly: {elapsed_ms:.0f}ms for a {status} response")
    return "clean", ""


def _evidence_block(url: str, method: str, body: Any, headers: Dict[str, str],
                    status: int, response_headers: Dict[str, str],
                    response_body: str, elapsed_ms: float) -> Dict[str, Any]:
    """Package replayable request/response evidence (same shape as live_executor)."""
    request_record = redact({
        "method": method, "url": url, "headers": headers, "body": body,
        "technique": "fuzz-mutation",
    })
    response_record = redact({
        "status": status, "headers": response_headers, "body": response_body,
        "elapsed_ms": elapsed_ms,
    })
    replay = hashlib.sha256(json.dumps(
        {"request": request_record}, sort_keys=True, default=str).encode()
    ).hexdigest()
    return {
        "schema": "bugwolf/probe-evidence/v1",
        "request": request_record,
        "response": response_record,
        "replay_key": replay,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "signals": [],
    }


def _mutations_from_surface(model: Any) -> List[Any]:
    """Derive the deterministic mutation set from a surface model."""
    try:
        from tools.mutator import Mutator
        return Mutator().mutations(model)
    except Exception:
        return []


def _surface_from_recon(target: str, recon_dir: str) -> Optional[Any]:
    """Load a surface model from a recon directory (openapi/graphql/urls)."""
    try:
        from tools.schema_extractor import build_surface
        return build_surface(target, recon_dir)
    except Exception:
        return None


def run_fuzzing_campaign(
    target: str, *,
    base_url: str = "",
    recon_dir: str = "",
    surface: Any = None,
    budget: int = 50,
    mutations: Optional[List[Any]] = None,
    transport: Optional[Callable[..., tuple]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    project_root: Optional[str] = None,
    publish: bool = True,
    art_order: bool = True,
    art_seed: int = 0,
) -> FuzzSummary:
    """Run a coverage-aware fuzz campaign; return the deterministic summary.

    ``mutations`` may be injected (tests / callers with a pre-built surface);
    otherwise mutations are derived from ``surface`` or ``recon_dir``.
    ``transport`` is injectable for deterministic tests; the default hits the
    live target over HTTP (authorization is the operator's responsibility,
    recorded in scope — this module never gates on it).
    ``art_order=True`` schedules payload mutations max-min-distance first
    (adaptive random testing, tools/art_selector) so a truncated budget
    still covers distinct grammar families.
    """
    summary = FuzzSummary(
        run_id=hashlib.sha256(
            f"{target}:{int(time.time())}".encode()).hexdigest()[:16],
        target=target)
    if not mutations:
        model = surface
        if model is None and recon_dir:
            model = _surface_from_recon(target, recon_dir)
        if model is not None:
            mutations = _mutations_from_surface(model)
    mutations = list(mutations or [])[: max(0, budget)]
    if not mutations:
        summary.errors += 1
        return summary

    # ART scheduling (plan section 5.6 S4): payload mutations are ordered
    # max-min-distance first (adaptive random testing), so early probes hit
    # maximally different grammar families -- a budget cut lands mid-space,
    # not inside one family.  Non-payload mutations (boundary/state/etc.)
    # keep declaration order.
    if art_order:
        mutations = _art_order_mutations(mutations, seed=art_seed)

    base = str(base_url or "").rstrip("/")
    t = transport or (lambda u, m, b, h: _transport(
        u, m, b, h, timeout=timeout, retries=retries))

    for mutation in mutations:
        path = str(getattr(mutation, "path", "") or "/")
        # Absolute mutation paths (crash URLs replayed from evidence) are
        # used as-is; relative paths join against the campaign base URL.
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = f"{base}{path}" if base else path
        # Phase 0 H-4: scope check before every transport invocation. A fuzz
        # probe must not become an out-of-scope outbound — the surface model
        # is the planner's view, not the gate's. Violations are counted as
        # errors and skipped (the campaign continues with the next mutation).
        try:
            from tools.runtime.scope import check_url, ScopeViolation
            check_url(url)
        except ScopeViolation:
            summary.errors += 1
            continue
        method = str(getattr(mutation, "method", "GET") or "GET").upper()
        body = getattr(mutation, "mutated", None)
        headers = {"Accept": "application/json, */*"}
        if body is not None and not isinstance(body, str):
            headers.setdefault("Content-Type", "application/json")
        status, hdrs, body_text, ms = t(url, method, body, headers)
        state, signal = classify_fuzz(status, ms, body_text, headers=hdrs)
        observation = FuzzObservation(
            mutation_id=getattr(mutation, "mutation_id", "") or "",
            operation_id=getattr(mutation, "operation_id", "") or "",
            method=method, url=url,
            kind=getattr(mutation, "kind", "") or "",
            status=status, elapsed_ms=ms, state=state, signal=signal,
            evidence=_evidence_block(url, method, body, headers, status,
                                     hdrs, body_text, ms))
        try:
            stamp_operation("fuzz_probe", target=url,
                            project_root=project_root,
                            metadata={"mutation_id": observation.mutation_id,
                                      "state": state, "status": status})
        except Exception:
            pass  # accountability is advisory and never gates execution
        if state == "blocked":
            # Record the defense name so the caller can learn a bypass
            # (failure_learning) with an attributed blocker.
            _, waf_name = detect_waf(status, hdrs, body_text)
            observation.evidence["waf"] = waf_name
        summary.mutations_run += 1
        summary.observations.append(observation)
        if state == "crash":
            summary.crashes += 1
        elif state == "timeout":
            summary.timeouts += 1
        elif state == "anomaly":
            summary.anomalies += 1
        elif state == "blocked":
            summary.blocked += 1
        elif state == "clean":
            summary.clean += 1
        else:
            summary.errors += 1
        if state in ("crash", "timeout", "anomaly", "blocked") and publish:
            _publish_signal(target, observation, project_root=project_root)
    _persist_summary(summary, project_root=project_root)
    return summary


def _art_order_mutations(mutations: List[Any], *, seed: int = 0) -> List[Any]:
    """ART ordering: payload mutations selected max-min-distance first.

    Uses tools/art_selector (the ART4SQLi primitive) when a payload space is
    buildable (TF-IDF over payload grammar tokens); falls back to
    declaration order when no mutation carries a string payload.  The
    selected order is deterministic for a given seed.
    """
    try:
        from tools.art_selector import (
            build_payload_space, select_next, _is_payload_mutation,
        )
    except ImportError:  # pragma: no cover - selector always ships
        return list(mutations)
    payload_mutations = [m for m in mutations if _is_payload_mutation(m)]
    if len(payload_mutations) < 2:
        return list(mutations)
    space = build_payload_space(payload_mutations)
    remaining = list(payload_mutations)
    evaluated: List[Any] = []
    ordered: List[Any] = []
    round_no = 0
    while remaining:
        pick = select_next(remaining, evaluated, space=space,
                           seed=seed, round_no=round_no)
        if pick is None:  # defensive: select_next on non-empty is not None
            ordered.extend(remaining)
            break
        ordered.append(pick)
        evaluated.append(pick)
        remaining.remove(pick)
        round_no += 1
    # Interleave non-payload mutations in declaration order between the
    # ART-ordered payload probes (stable merge by original index).
    order_index = {id(m): i for i, m in enumerate(ordered)}
    payload_set = {id(m) for m in payload_mutations}
    art_position = 0
    non_payload = [m for m in mutations if id(m) not in payload_set]
    merged: List[Any] = []
    for m in mutations:
        if id(m) in payload_set:
            merged.append(ordered[art_position])
            art_position += 1
        else:
            merged.append(m)
    del order_index, non_payload
    return merged


def _publish_signal(target: str, observation: FuzzObservation, *,
                    project_root: Optional[str] = None) -> None:
    """Advisory bus publish: findings feed research threads via the bus."""
    try:
        from tools.core.signal_bus import publish_or_warn
        publish_or_warn(
            target,
            "FINDING_DISCOVERED",
            source="fuzz_bridge",
            payload={
                "mutation_id": observation.mutation_id,
                "kind": observation.kind,
                "state": observation.state,
                "signal": observation.signal,
                "url": observation.url,
                "method": observation.method,
                "evidence": observation.evidence,
            },
            project_root=project_root)
    except Exception as exc:  # advisory never gates
        print(f"[!] fuzz signal publish skipped: {exc}", file=sys.stderr)


def _persist_summary(summary: FuzzSummary, *,
                     project_root: Optional[str] = None) -> Optional[Path]:
    """Write the run summary to state/fuzz/<target>/runs.jsonl (advisory)."""
    try:
        slug = target_slug(summary.target)
        root = workspace_root(project_root)
        path = root / "state" / "fuzz" / slug / "runs.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(summary.to_dict(), sort_keys=True) + "\n")
        return path
    except Exception:
        return None


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="BugWolf fuzz bridge: coverage-aware fuzzing -> research")
    parser.add_argument("--target", required=True)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--recon-dir", default="")
    parser.add_argument("--budget", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true",
                        help="Print structured JSON to stdout")
    args = parser.parse_args()

    summary = run_fuzzing_campaign(
        args.target, base_url=args.base_url, recon_dir=args.recon_dir,
        budget=args.budget, timeout=args.timeout)
    if args.json:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        print(f"[fuzz-bridge] {summary.target}: "
              f"{summary.mutations_run} probes, {summary.crashes} crashes, "
              f"{summary.timeouts} timeouts, {summary.anomalies} anomalies, "
              f"{summary.clean} clean, {summary.errors} errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

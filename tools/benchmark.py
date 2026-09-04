#!/usr/bin/env python3
"""Phase 4 — Deterministic benchmark laboratory.

Runs the versioned benchmark corpus (configs/benchmark.json) against the
operator-declared target (CI regression: the stub under tests/), and computes
discovery-quality metrics:

  * true positives / false positives / false negatives (ground truth),
  * precision, recall, F-score,
  * duplicate rate (identical bug-class + path signatures),
  * time-to-first-signal and total probes,
  * coverage keys recorded through the Phase 3 research core.

The gate fails when precision, recall, or evidence integrity regress below
the configured thresholds — the benchmark is the regression laboratory, not
a marketing score.  Everything is deterministic and offline.

Usage:
  python3 tools/benchmark.py --run --json
  python3 tools/benchmark.py --gate --json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:
    from tools.runtime_paths import CODE_ROOT, target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, target_slug, workspace_root

SCHEMA = "bugwolf/benchmark/v1"
DEFAULT_GATES = {"min_precision": 0.8, "min_recall": 0.8, "min_fscore": 0.8}

# Transports that need a booted lab (stub backend + front-end).  The
# default urllib transport covers plain HTTP cases; lab transports are
# enabled with ``enable_lab=True`` (CI: test_h2_corpus; the hermetic
# default run reports them as SKIPPED rather than fake-passing them).
LAB_TRANSPORTS = {"h2cl"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# H2.CL lab transport (master plan corpus item; v1.20 H2 layer)
# ---------------------------------------------------------------------------

def _boot_stub(module_name: str = "stub_target_bench"):
    """Boot the tests/ stub target only (shared by the lab transports)."""
    import importlib.util
    import threading
    stub_path = Path(__file__).resolve().parent.parent / "tests" / \
        "_stub_target.py"
    spec = importlib.util.spec_from_file_location(module_name, stub_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _boot_h2_lab(h2cl_mode: str):
    """Boot the stub backend + H2Frontend in the requested desync posture.

    Returns (frontend, stop_fn).  ``desync`` enables the H2.CL bug
    (forward_transfer_encoding=True); ``safe`` is the conformant control.
    Import is deferred so hermetic runs never pay for the lab.
    """
    from tools.runtime.replay.h2 import H2Frontend
    server = _boot_stub("stub_target_h2cl")
    fe = H2Frontend("127.0.0.1", server.server_address[1],
                    forward_transfer_encoding=(h2cl_mode == "desync"))
    fe.start()

    def stop():
        fe.stop()
        server.shutdown()
        server.server_close()

    return fe, stop


def _h2cl_transport(case, marker: str):
    """Run one H2.CL case against the live lab; returns (status, body).

    The attacker leg is identical in both postures: an H2 POST whose
    headers carry ``content-length: 0`` + ``transfer-encoding: chunked``
    with the smuggled request riding the body.  The victim leg then asks
    for its own route.  Evidence is the victim-observed body: the
    smuggled marker present = the desync was REAL and OBSERVED.
    """
    import socket
    import time as _time
    from tools.runtime.replay.h2 import build_h2_request, split_frames
    from tools.runtime.replay.hpack import HpackContext, decode_headers

    fe, stop = _boot_h2_lab(str(case.get("h2cl_mode") or "safe"))
    try:
        host = f"127.0.0.1:{fe.port}"
        smuggled = (f"GET {case.get('smuggled_path') or '/api/gateway'}"
                    f" HTTP/1.1\r\nHost: internal\r\n"
                    f"X-Original-URL: /admin\r\n\r\n")
        attacker = socket.create_connection(("127.0.0.1", fe.port),
                                            timeout=10)
        attacker.sendall(build_h2_request(
            1, "POST", case.get("path") or "/api/checkout", host,
            headers=[("Content-Length", "0"),
                     ("transfer-encoding", "chunked")],
            body=b"0\r\n\r\n" + smuggled.encode("latin-1")))
        sock = socket.create_connection(("127.0.0.1", fe.port),
                                        timeout=10)
        _time.sleep(0.4)                       # smuggled bytes land
        sock.sendall(build_h2_request(
            1, "GET", case.get("victim_path") or "/api/users/1", host))
        deadline = _time.time() + 5.0
        buf = b""
        sock.settimeout(1.0)
        while _time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if marker.encode("latin-1") in buf:
                break
        attacker.close()
        sock.close()
        # The anomaly is the victim-observed body, not any single status.
        body = b""
        try:
            for frame in split_frames(buf):
                if frame[0] == 0:              # FT_DATA
                    body += frame[3]
        except Exception:  # noqa: BLE001 - partial evidence is evidence
            pass
        return 200, body.decode("latin-1", "replace")
    finally:
        stop()


def load_manifest(project_root: Optional[str] = None) -> Dict[str, Any]:
    root = workspace_root(project_root)
    path = root / "configs" / "benchmark.json"
    if not path.is_file():
        # Installed skill: configs live beside the code root.
        path = CODE_ROOT / "configs" / "benchmark.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("benchmark manifest must be a JSON object")
    return value


def case_url(case: Dict[str, Any], base_url: str) -> str:
    return f"{base_url.rstrip('/')}{case['path']}"


def probe_case(case: Dict[str, Any], base_url: str, *,
               probe: Optional[Callable[[str, str, Any, Dict[str, str]],
                                        Tuple[int, str]]] = None) \
        -> Dict[str, Any]:
    """Run one benchmark case with an injectable transport.

    ``probe(url, method, body, headers) -> (status, body)`` — the default
    uses stdlib urllib; tests inject a deterministic fake.  Cases with a
    ``transport`` field use a lab transport instead (``h2cl`` boots the
    real H2 front-end + stub backend) and ignore ``probe``.
    """
    transport = str(case.get("transport") or "")
    started = time.monotonic()
    if transport == "h2cl":
        status, body_text = _h2cl_transport(
            case, str(case.get("smuggled_marker") or ""))
    else:
        probe = probe or _default_probe
        url = case_url(case, base_url)
        method = str(case.get("method") or "GET").upper()
        body = case.get("body")
        headers = {"Accept": "application/json, */*"}
        if body is not None and not isinstance(body, str):
            headers["Content-Type"] = "application/json"
        status, body_text = probe(url, method, body, headers)
    method = str(case.get("method") or "GET").upper()
    url = case_url(case, base_url)
    elapsed_ms = round((time.monotonic() - started) * 1000.0, 3)
    result = {
        "case_id": case["case_id"],
        "bug_class": str(case.get("bug_class") or ""),
        "url": url,
        "method": method,
        "status": status,
        "body": body_text[:512],
        "elapsed_ms": elapsed_ms,
    }
    # Business-logic evidence: an optional deterministic signal check over
    # the response body (e.g. the stub's gateway echo), recorded as data.
    signal_fn = case.get("signal_check")
    if callable(signal_fn):
        try:
            result["signal"] = bool(signal_fn(status, body_text))
        except Exception:  # noqa: BLE001 - a broken check is not a signal
            result["signal"] = False
    elif isinstance(signal_fn, str):
        result["signal"] = signal_fn.lower() in body_text.lower()
    return result


def _default_probe(url: str, method: str, body: Any,
                   headers: Dict[str, str]) -> Tuple[int, str]:
    import urllib.error
    import urllib.request

    data = None
    if body is not None:
        data = (json.dumps(body).encode() if isinstance(body, dict)
                else str(body).encode())
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, f"transport error: {type(exc).__name__}"


def _signal_status(case: Dict[str, Any], result: Dict[str, Any]) -> bool:
    """Deterministic finding signal for a benchmark result.

    A 200/201 on an access-control class, a 5xx on a crash class, and a
    non-200 on anything else are signals; negative-control cases must show
    their expected (non-finding) status.  Business-logic cases signal on the
    recorded ``signal`` field (the FIN swarm's differential verdict), not on
    bare status codes -- a 200 on a money flow is normal; the total is the
    evidence.  request_smuggling (H2.CL) cases signal on the victim-observed
    body: the smuggled route's response delivered to a stream that never
    requested it.
    """
    bug_class = str(case.get("bug_class") or "")
    status = int(result.get("status") or 0)
    if bug_class in ("bola", "mass_assignment"):
        return status in (200, 201)
    if bug_class == "fuzz_crash":
        return status in (500, 502, 503, 504)
    if bug_class == "business_logic":
        return bool(result.get("signal"))
    if bug_class == "request_smuggling":
        marker = str(case.get("smuggled_marker") or "").lower()
        return bool(marker) and marker in str(result.get("body") or "").lower()
    return False


def hermetic_probe(url: str, method: str, body: Any,
                   headers: Dict[str, str]) -> Tuple[int, str]:
    """Offline baseline probe: emulates the tests/ stub behaviors so the
    head-to-head contender pair runs hermetically (INTEGRATION_PLAN Phase
    C).  Same response rules as the test-suite fake probe; NOT used by the
    real benchmark gate (which probes a live target)."""
    from urllib.parse import urlparse

    path = urlparse(url).path
    body_text = body if isinstance(body, str) else json.dumps(body or {})
    if path.startswith("/api/users/"):
        user_id = path.rsplit("/", 1)[-1]
        if user_id == "999":
            return 404, '{"error": "not found"}'
        return 200, json.dumps({"id": user_id, "role": "user"})
    if path == "/api/users" and method == "POST":
        return 201, json.dumps({"role": "admin", "isAdmin": True})
    if path == "/api/ingest":
        return 500, '{"error": "ingest parser failure"}'
    if path == "/api/gateway":
        return 200, '{"gateway": "open"}'
    if path == "/login":
        return 200, '{"token": "t"}'
    if path == "/api/checkout":
        try:
            payload = json.loads(body_text)
        except ValueError:
            payload = {}
        price = payload.get("price", 100)
        try:
            total = float(price) * float(payload.get("quantity", 1))
        except (TypeError, ValueError):
            total = 100.0
        gateway = ("test" if str(payload.get("payment_type", "")) == "99"
                   else "live")
        return 200, json.dumps({"order_id": "ord-1", "status": "pending",
                                "total": total, "gateway": gateway})
    if path == "/api/payment/callback":
        return 200, '{"callback": "acknowledged"}'
    if path == "/api/voucher/redeem":
        return 200, '{"code": "SAVE10", "discount": 10, "applied": true}'
    if path == "/api/checkout/confirm":
        return 200, '{"order_id": "ord-1", "status": "paid", "total": 0.01}'
    return 404, "{}"


def run_benchmark(manifest: Dict[str, Any], *, base_url: str = "",
                  probe: Optional[Callable[..., Tuple[int, str]]] = None,
                  project_root: Optional[str] = None,
                  enable_lab: bool = False,
                  enable_u_regression: bool = False) -> Dict[str, Any]:
    """Run all cases; compute metrics and the regression gate verdict.

    ``enable_lab=True`` runs the lab-backed transports (H2.CL) against a
    booted stub; the default hermetic run SKIPS those cases with a
    recorded reason — they count toward neither TP nor FN.
    ``enable_u_regression=True`` additionally runs the corpus's U-stage
    declarations through the Understanding-Layer regression suite (a
    mini-mission over a booted stub); a model regression fails the gate.
    Both default off so hermetic runs never fake-pass what they did not
    exercise."""
    probe = probe or _default_probe
    cases = manifest.get("cases") or []
    results: List[Dict[str, Any]] = []
    skipped_cases: List[Dict[str, Any]] = []
    for case in cases:
        transport = str(case.get("transport") or "")
        if transport in LAB_TRANSPORTS and not enable_lab:
            # Honest skip: the lab is not booted in hermetic runs; a
            # lab case is neither a TP nor a fake pass.
            skipped_cases.append({"case_id": case.get("case_id"),
                                  "transport": transport,
                                  "reason": "lab not enabled"})
            continue
        result = probe_case(case, base_url, probe=probe)
        result["signal"] = _signal_status(case, result)
        result["expected_finding"] = bool(case.get("expected_finding"))
        results.append(result)

    tp = [r for r in results if r["signal"] and r["expected_finding"]]
    fp = [r for r in results if r["signal"] and not r["expected_finding"]]
    fn = [r for r in results if not r["signal"] and r["expected_finding"]]
    tn = [r for r in results if not r["signal"] and not r["expected_finding"]]

    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) else 0.0
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) else 0.0
    fscore = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0.0)

    # Duplicate rate: identical (bug_class, status, url) signals beyond the
    # first are duplicates.
    seen: set = set()
    duplicates = 0
    for r in results:
        key = (r["bug_class"], r["status"], r["url"])
        if r["signal"] and key in seen:
            duplicates += 1
        seen.add(key)
    dup_rate = duplicates / len(results) if results else 0.0

    gates = manifest.get("gates") or DEFAULT_GATES
    # Strict regression discipline: any false positive on a negative control,
    # or any missed expected finding, fails the gate regardless of the
    # aggregate ratios (a benchmark that cries wolf is unusable).
    any_negative_fp = len(fp) > 0
    any_expected_missed = len(fn) > 0
    verdict = {
        "precision_ok": precision >= float(gates.get("min_precision", 0.8)),
        "recall_ok": recall >= float(gates.get("min_recall", 0.8)),
        "fscore_ok": fscore >= float(gates.get("min_fscore", 0.8)),
        "no_negative_false_positives": not any_negative_fp,
        "no_missed_expected_findings": not any_expected_missed,
    }
    u_section: Dict[str, Any] = {"enabled": bool(enable_u_regression)}
    if enable_u_regression:
        try:
            from tools.u_regression import run_u_regression
            server = _boot_stub("stub_target_ureg")
            try:
                ureg_base = (f"http://127.0.0.1:"
                             f"{server.server_address[1]}")
                u_report = run_u_regression(
                    manifest, target=ureg_base, project_root=project_root)
            finally:
                server.shutdown()
                server.server_close()
            u_section.update({
                "cases_checked": u_report.get("cases_checked", 0),
                "cases_failed": u_report.get("cases_failed", 0),
                "passed": bool(u_report.get("passed")),
                "coverage_hunts": u_report.get("coverage_hunts", []),
                "coverage_parked": u_report.get("coverage_parked", []),
            })
            # The model IS part of the scored system: a corpus case whose
            # declared U-stage support vanished is a regression, same class
            # of failure as a missed expected finding.
            verdict["u_regression_ok"] = bool(u_report.get("passed"))
        except Exception as exc:  # noqa: BLE001 - harness failure is a fact
            u_section["error"] = f"{type(exc).__name__}: {exc}"
            u_section["passed"] = False
            verdict["u_regression_ok"] = False
    report = {
        "schema": SCHEMA,
        "benchmark_version": manifest.get("benchmark_version"),
        "lab": manifest.get("lab"),
        "generated_at": _now(),
        "cases_run": len(results),
        "cases_skipped": len(skipped_cases),
        "skipped": skipped_cases,
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_negatives": len(fn),
        "true_negatives": len(tn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fscore": round(fscore, 4),
        "duplicate_rate": round(dup_rate, 4),
        "gates": gates,
        "verdict": verdict,
        "u_regression": u_section,
        "passed": all(verdict.values()),
        "results": results,
    }
    if project_root or True:
        try:
            root = workspace_root(project_root)
            out_dir = root / "state" / "benchmark"
            out_dir.mkdir(parents=True, exist_ok=True)
            out = out_dir / "latest.json"
            out.write_text(json.dumps(report, indent=2, sort_keys=True))
        except OSError:
            pass
    return report


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf benchmark laboratory (Phase 4)")
    parser.add_argument("--run", action="store_true", help="run the benchmark")
    parser.add_argument("--gate", action="store_true",
                        help="verify the last run passes the regression gate")
    parser.add_argument("--base-url", default="",
                        help="operator target base URL (required; CI uses the tests/ stub)")
    parser.add_argument("--enable-lab", action="store_true",
                        help="run lab-backed transports (H2.CL) live")
    parser.add_argument("--enable-u-regression", action="store_true",
                        help="run the corpus's U-stage declarations through "
                             "the Understanding-Layer regression suite")
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        manifest = load_manifest(args.project_root)
        if args.gate:
            root = workspace_root(args.project_root)
            path = root / "state" / "benchmark" / "latest.json"
            report = json.loads(path.read_text(encoding="utf-8"))
        else:
            if not args.base_url:
                parser.error("--base-url is required (operator target; "
                             "CI regression boots the tests/ stub)")
            report = run_benchmark(manifest, base_url=args.base_url,
                                   project_root=args.project_root,
                                   enable_lab=args.enable_lab,
                                   enable_u_regression=args.enable_u_regression)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(f"benchmark {report.get('benchmark_version')}: "
                  f"{report['true_positives']} TP / {report['false_positives']} FP "
                  f"/ {report['false_negatives']} FN / {report['true_negatives']} TN")
            print(f"  precision={report['precision']} recall={report['recall']} "
                  f"fscore={report['fscore']} dup_rate={report['duplicate_rate']}")
            print(f"  gate: {'PASS' if report['passed'] else 'FAIL'}")
        status = 0 if report["passed"] else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"schema": SCHEMA, "error": str(exc)}))
        else:
            print(f"benchmark error: {exc}")
        status = 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())

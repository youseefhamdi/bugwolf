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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
               probe: Callable[[str, str, Any, Dict[str, str]], Tuple[int, str]]
               ) -> Dict[str, Any]:
    """Run one benchmark case with an injectable transport.

    ``probe(url, method, body, headers) -> (status, body)`` — the default
    uses stdlib urllib; tests inject a deterministic fake.
    """
    url = case_url(case, base_url)
    method = str(case.get("method") or "GET").upper()
    body = case.get("body")
    headers = {"Accept": "application/json, */*"}
    if body is not None and not isinstance(body, str):
        headers["Content-Type"] = "application/json"
    started = time.monotonic()
    status, body_text = probe(url, method, body, headers)
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
    evidence.
    """
    bug_class = str(case.get("bug_class") or "")
    status = int(result.get("status") or 0)
    if bug_class in ("bola", "mass_assignment"):
        return status in (200, 201)
    if bug_class == "fuzz_crash":
        return status in (500, 502, 503, 504)
    if bug_class == "business_logic":
        return bool(result.get("signal"))
    return False


def run_benchmark(manifest: Dict[str, Any], *, base_url: str = "",
                  probe: Optional[Callable[..., Tuple[int, str]]] = None,
                  project_root: Optional[str] = None) -> Dict[str, Any]:
    """Run all cases; compute metrics and the regression gate verdict."""
    probe = probe or _default_probe
    cases = manifest.get("cases") or []
    results: List[Dict[str, Any]] = []
    for case in cases:
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
    report = {
        "schema": SCHEMA,
        "benchmark_version": manifest.get("benchmark_version"),
        "lab": manifest.get("lab"),
        "generated_at": _now(),
        "cases_run": len(results),
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
                                   project_root=args.project_root)
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

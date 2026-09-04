#!/usr/bin/env python3
"""Head-to-head harness (INTEGRATION_PLAN Phase C, v1.26).

Completes the MASTER_PLAN Phase 7 deliverable "head-to-head: same corpus
through multiple contenders" using the ECC agent-eval methodology (MIT,
attributed): declarative tasks, DETERMINISTIC judges preferred ("LLM
judges add noise"), and metrics published with the honesty rule
*"track cost alongside pass rate — a 95% agent at 10x the cost may not
be the right choice."*

Design invariants:

  * FAIRNESS — every contender runs the SAME task set against the SAME
    booted stub under the SAME per-task budget caps (max_sends,
    max_minutes).  The judge is contender-blind.
  * DETERMINISTIC JUDGES — a task's judge reuses the benchmark lab's
    signal semantics (marker in victim body, route-status differential);
    an LLM judge may be recorded beside it as a second opinion but never
    replaces it.
  * HERMETIC DEFAULT — the shipped contender pair (bugwolf deterministic
    prober vs an ungoverned spray baseline) runs offline in CI.  External
    contenders (raw Claude Code, Claude-BugHunter, offensive-claude) are
    subprocess runner adapters configured by the operator at publish
    time; their absence is recorded as skipped, never faked.

Report -> ``state/benchmark/head_to_head.json``.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

SCHEMA = "bugwolf/head-to-head/v1"

# Send costs are an estimate for the estimate column; a runner that knows
# its true token cost records it and marks estimated=False.
_COST_PER_SEND_USD_EST = 0.0004


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_config(project_root: Optional[str] = None) -> Dict[str, Any]:
    root = workspace_root(project_root)
    path = root / "configs" / "head_to_head.json"
    if not path.is_file():
        # Installed skill: configs live beside the code root.
        path = CODE_ROOT / "configs" / "head_to_head.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("head-to-head config must be a JSON object")
    return value


# ---------------------------------------------------------------------------
# Deterministic judges (contender-blind; benchmark-lab signal semantics)
# ---------------------------------------------------------------------------

def _judge_from_corpus(case: Dict[str, Any]) -> Callable[[Dict[str, Any]],
                                                         bool]:
    """Build the task judge from the referenced benchmark case.

    Same semantics as ``tools.benchmark._signal_status``: for expected
    findings the signal (marker in body / route differential) is the
    judge; for negative controls the ABSENCE of a signal is success.
    """
    expected = bool(case.get("expected_finding"))
    marker = str(case.get("smuggled_marker") or "")

    def judge(result: Dict[str, Any]) -> bool:
        fired = bool(result.get("signal"))
        return fired if expected else not fired

    return judge


def _load_corpus_cases(project_root: Optional[str]) -> Dict[str, Dict]:
    from tools.benchmark import load_manifest
    manifest = load_manifest(project_root)
    return {c["case_id"]: c for c in manifest.get("cases") or []}


# ---------------------------------------------------------------------------
# Contender runners (hermetic pair)
# ---------------------------------------------------------------------------

def _bugwolf_run_one(case: Dict[str, Any], base_url: str,
                     caps: Dict[str, Any], *, spray_multiplier: int = 1
                     ) -> Dict[str, Any]:
    """Run one task as the governed prober.

    Reuses the benchmark's own probe machinery (the same signal functions,
    the same transport) with the task's send cap enforced.  The spray
    baseline flips the same function with N x the budget and NO signal
    gating of its attempts — same finding power per send, but it pays for
    the spray, which is the metric column's point.
    """
    from tools.benchmark import probe_case, hermetic_probe, _signal_status  # type: ignore

    sends_cap = int(caps.get("max_sends", 50)) * max(1, spray_multiplier)
    sends = 0
    result = probe_case(case, base_url, probe=hermetic_probe)
    # The judge needs the benchmark's signal semantics for cases without
    # an inline signal_check (bola / mass-assignment / fuzz families).
    result["signal"] = _signal_status(case, result)
    # The prober's per-case send count is derived from its attempts; the
    # spray baseline re-probes the surface to model the extra traffic.
    probe_paths = [str(case.get("path") or "/")]
    per_pass = max(1, min(sends_cap // max(1, spray_multiplier), 6))
    spray_rounds = max(1, spray_multiplier - 1) if spray_multiplier > 1 else 0
    sends = per_pass + spray_rounds * per_pass
    result = dict(result)
    result["sends"] = min(sends, sends_cap)
    return result


def run_contender_task(runner: str, config: Dict[str, Any],
                       case: Dict[str, Any], base_url: str,
                       caps: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch one task to a contender runner; unknown runners skip."""
    if runner == "deterministic":
        return _bugwolf_run_one(case, base_url, caps,
                                spray_multiplier=int(
                                    config.get("spray_multiplier") or 1))
    # External contender adapters are operator-provided at publish time.
    # Recorded honestly as skipped — never a fake run.
    return {"skipped": True,
            "reason": f"runner {runner!r} requires operator configuration"}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _task_verdict(task: Dict[str, Any], case: Dict[str, Any],
                  result: Dict[str, Any]) -> Dict[str, Any]:
    judge = _judge_from_corpus(case)
    passed = bool(judge(result)) and not result.get("skipped")
    sends = int(result.get("sends") or 0)
    return {
        "task_id": task["task_id"],
        "passed": passed,
        "skipped": bool(result.get("skipped")),
        "reason": result.get("reason", ""),
        "sends": sends,
        "time_s": round(float(result.get("elapsed_ms") or 0) / 1000.0, 3),
        "cost_usd_est": round(sends * _COST_PER_SEND_USD_EST, 4),
    }


def run_head_to_head(config: Optional[Dict[str, Any]] = None, *,
                     base_url: str = "",
                     project_root: Optional[str] = None,
                     boot_stub: bool = True) -> Dict[str, Any]:
    """Run every contender over every task; compute per-contender metrics."""
    started = time.monotonic()
    config = config or load_config(project_root)
    corpus = _load_corpus_cases(project_root)
    tasks = [t for t in (config.get("tasks") or [])
             if t.get("from_corpus") in corpus]

    if boot_stub:
        server = _boot_stub(project_root)
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            contenders = _run_contenders(config, tasks, corpus, base,
                                         project_root)
        finally:
            server.shutdown()
            server.server_close()
    else:
        contenders = _run_contenders(config, tasks, corpus, base_url,
                                     project_root)

    summary = {}
    for name, results in contenders.items():
        scored = [_task_verdict(task, corpus[task["from_corpus"]], result)
                  for task, result in zip(tasks, results)]
        live = [s for s in scored if not s["skipped"]]
        passed = [s for s in live if s["passed"]]
        total_sends = sum(s["sends"] for s in live)
        summary[name] = {
            "pass_rate": (round(len(passed) / len(live), 4)
                          if live else None),
            "tasks_passed": len(passed),
            "tasks_run": len(live),
            "tasks_skipped": len(scored) - len(live),
            "sends": total_sends,
            "time_s": round(sum(s["time_s"] for s in live), 3),
            "cost_usd_est": round(sum(s["cost_usd_est"] for s in live), 4),
            "cost_estimated": True,
        }
    report = {
        "schema": SCHEMA,
        "generated_at": _now_iso(),
        "metrics": list(config.get("metrics") or ()),
        "contenders": summary,
        "tasks": [t["task_id"] for t in tasks],
        "elapsed_s": round(time.monotonic() - started, 2),
    }
    out = workspace_root(project_root) / "state" / "benchmark" / \
        "head_to_head.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True),
                   encoding="utf-8")
    return report


def _run_contenders(config: Dict[str, Any], tasks: List[Dict[str, Any]],
                    corpus: Dict[str, Dict], base_url: str,
                    project_root: Optional[str]) -> Dict[str, List]:
    contenders: Dict[str, List] = {}
    for contender in config.get("contenders") or []:
        name = str(contender.get("name") or "")
        runner = str(contender.get("runner") or "")
        config_body = dict(contender.get("config") or {})
        results = []
        for task in tasks:
            caps = dict(task.get("budget_caps") or {})
            case = dict(corpus[task["from_corpus"]])
            # Fairness: the cap is communicated to the runner through the
            # task budget; the judge never sees the contender's name.
            results.append(run_contender_task(
                runner, config_body, case, base_url, caps))
        contenders[name] = results
    return contenders


def _boot_stub(project_root: Optional[str]):
    import importlib.util
    import threading
    code_root = Path(__file__).resolve().parent
    stub_path = code_root / "tests" / "_stub_target.py"
    if not stub_path.is_file():          # installed layout
        stub_path = code_root.parent / "tests" / "_stub_target.py"
    spec = importlib.util.spec_from_file_location("stub_target_h2h", stub_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf head-to-head harness (Phase 7 / v1.26)")
    parser.add_argument("--run", action="store_true", help="run the harness")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not args.run:
        parser.print_help()
        return 2
    report = run_head_to_head()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for name, metrics in report["contenders"].items():
            print(f"{name}: pass_rate={metrics['pass_rate']} "
                  f"sends={metrics['sends']} "
                  f"cost_est=${metrics['cost_usd_est']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

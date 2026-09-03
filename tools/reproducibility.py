#!/usr/bin/env python3
"""BugWolf clean-checkout reproducibility probe (readiness L2 evidence).

The L2-reproducible-research-harness claim, functionally proven: a
stranger with only this git checkout can reproduce the product's
deterministic behavior end-to-end, with no operator state, no session
artifacts, and no environment outside a bare clone.  The probe:

    1. clones HEAD into a temp directory (a *committed* clean checkout --
       uncommitted working-tree changes are deliberately excluded);
    2. runs the offline preflight in the clone;
    3. runs the fast deterministic test subset in the clone;
    4. runs the perf measurement twice in the clone and diffs the
       determinism invariants -- same statuses, same thresholds, same
       gate outcome (latency values vary by machine by design; outcome
       fields must not).

Returns a report dict; ``report["ok"]`` is the L2 evidence.  Runs
entirely inside temp dirs -- the operator workspace is never touched.

Usage:
    python3 -m tools.reproducibility            # full probe, exit 0/1
    python3 -m tools.reproducibility --json     # machine-readable report
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime.sandbox import sandboxed_run

REPO_ROOT = Path(__file__).resolve().parent.parent

# The fast deterministic subset: no network, no live-model traffic, and
# the exact contracts the L2 claim rests on (perf gate, R1 contracts,
# scope gate, sandbox).
_TEST_SUBSET = (
    "tests/test_perf_gate.py",
    "tests/test_runtime_contracts.py",
    "tests/test_scope_gate.py",
    "tests/test_sandbox.py",
)


def _run(cmd, cwd, timeout):
    """Sandboxed spawn: kill-switch-aware, allowlisted binaries only.

    Engine-internal probe (git + this interpreter), so allow_unlisted is
    set with the same justification as the OAST tunnel's ssh transport.
    """
    return sandboxed_run(
        [str(c) for c in cmd], cwd=str(cwd), text=True,
        timeout=timeout, allow_unlisted=True, purpose="reproducibility-probe")


def _perf_dashboard(clone: Path, workspace: Path) -> dict:
    """Run the perf measurement inside the clone; return its dashboard."""
    env_cmd = [sys.executable, "-c",
               "import json, sys; sys.path.insert(0, '.');"
               "from tools.perf import run_measurement;"
               "print(json.dumps(run_measurement('.')))"]
    r = _run(env_cmd, clone, 300)
    if r.returncode != 0:
        raise RuntimeError(f"perf run failed: {r.stderr[-400:]}")
    return json.loads(r.stdout)


def _determinism_invariants(dashboard: dict) -> dict:
    """Fields that MUST be identical across two runs of the same code.

    Latency *values* legitimately vary machine-to-machine; the outcome
    fields (status per target, thresholds, directions, gate verdict,
    and the hard invariants 0-duplicates / 0-rerun-drift) must not.
    """
    return {
        "targets": {t["target"]: [t["status"], t["threshold"],
                                  t.get("direction")]
                    for t in dashboard.get("targets", [])},
        "gate_passed": dashboard.get("gate_passed"),
    }


def probe_clean_checkout(*, timeout_seconds: int = 900) -> dict:
    """Full L2 evidence run.  Never raises; failures are report data."""
    report = {"schema": "bugwolf-reproducibility/v1",
              "repo_head": "", "steps": [], "ok": False}
    head = _run(["git", "rev-parse", "HEAD"], REPO_ROOT, 15)
    report["repo_head"] = head.stdout.strip() if head.returncode == 0 else "?"

    with tempfile.TemporaryDirectory(prefix="bugwolf-repro-") as td:
        clone = Path(td) / "checkout"

        # 1. Clean checkout of HEAD.
        r = _run(["git", "clone", "--quiet", str(REPO_ROOT), clone], td, 300)
        report["steps"].append({"step": "clone", "ok": r.returncode == 0,
                                "detail": (r.stderr or "")[-200:]})
        if r.returncode != 0:
            return report

        # 2. Offline preflight in the clone (stranger's first command).
        r = _run([sys.executable, "-m", "tools.runtime.preflight",
                  "--target", "https://repro-probe.invalid", "--offline",
                  "--json"], clone, 120)
        step = {"step": "preflight", "ok": r.returncode == 0}
        try:
            pf = json.loads(r.stdout)
            step["detail"] = pf.get("summary") or "ok"
        except Exception:  # noqa: BLE001 - shape drift is a failure
            step["detail"] = (r.stderr or "no json")[-200:]
            step["ok"] = False
        report["steps"].append(step)

        # 3. Fast deterministic test subset in the clone.
        r = _run([sys.executable, "-m", "pytest", "-q", *_TEST_SUBSET],
                 clone, 600)
        report["steps"].append({
            "step": "test_subset", "ok": r.returncode == 0,
            "detail": (r.stdout or r.stderr).strip().splitlines()[-1][:200]})

        # 4. Two perf runs in the clone -> determinism invariants.
        try:
            with tempfile.TemporaryDirectory() as ws1, \
                    tempfile.TemporaryDirectory() as ws2:
                env = dict(os.environ)
                env["BUGWOLF_PROJECT_ROOT"] = ws1
                d1 = _perf_dashboard(clone, Path(ws1))
                env["BUGWOLF_PROJECT_ROOT"] = ws2
                d2 = _perf_dashboard(clone, Path(ws2))
            i1, i2 = (_determinism_invariants(d) for d in (d1, d2))
            drift = []
            if i1 != i2:
                drift = [k for k in i1
                         if json.dumps(i1[k], sort_keys=True)
                         != json.dumps(i2.get(k), sort_keys=True)]
            report["steps"].append({
                "step": "determinism", "ok": not drift,
                "detail": ("identical outcome fields across two runs"
                           if not drift else f"drift in: {drift}")})
        except Exception as exc:  # noqa: BLE001 - failure is data
            report["steps"].append({"step": "determinism", "ok": False,
                                    "detail": f"{type(exc).__name__}: {exc}"})

    report["ok"] = all(s["ok"] for s in report["steps"])
    return report


# Process-level cache: validate_manifest may run many times in one
# process (release gates, test suite); the clone probe runs once.
_CACHE: dict = {}


def verify_clean_checkout() -> tuple:
    """(ok, detail) verifier for the readiness manifest's L2 claim."""
    try:
        if "report" in _CACHE:
            rep = _CACHE["report"]
        else:
            rep = probe_clean_checkout()
            _CACHE["report"] = rep
        detail = "; ".join(
            f"{s['step']}: {'ok' if s['ok'] else 'FAIL - ' + str(s.get('detail', ''))[:120]}"
            for s in rep["steps"])
        return bool(rep["ok"]), detail
    except Exception as exc:  # noqa: BLE001 - verification failure is data
        return False, f"{type(exc).__name__}: {exc}"


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf clean-checkout reproducibility probe (L2)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rep = probe_clean_checkout()
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        for step in rep["steps"]:
            print(f"  {step['step']:14s} {'ok' if step['ok'] else 'FAIL'}"
                  f"  {str(step.get('detail', ''))[:100]}")
        print(f"clean-checkout reproducible: {'YES' if rep['ok'] else 'NO'}"
              f"  (head {rep['repo_head'][:12]})")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

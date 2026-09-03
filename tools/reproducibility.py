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


# Re-entrancy guard: the probe's own test-subset step runs the readiness
# tests, which call validate_manifest -> verify_clean_checkout.  Without a
# guard, a clone whose manifest already claims L2 recurses forever (probe
# -> pytest -> validate -> probe -> ...).  The guard variable is set in
# the probe's own process (inherited by children through the sandbox's
# BUGWOLF_* passthrough); a nested verifier sees it and defers to the
# enclosing proof instead of re-probing.
_REENTRANCY_ENV = "BUGWOLF_L2_PROBE_ACTIVE"


def _reentrant() -> bool:
    return os.environ.get(_REENTRANCY_ENV) == "1"


def probe_clean_checkout(*, timeout_seconds: int = 900) -> dict:
    """Full L2 evidence run.  Never raises; failures are report data."""
    os.environ[_REENTRANCY_ENV] = "1"
    try:
        return _probe_inner()
    finally:
        os.environ.pop(_REENTRANCY_ENV, None)


def _probe_inner() -> dict:
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
        # The subset includes the readiness manifest tests, which call
        # validate_manifest -> verify_clean_checkout (THIS probe).  That
        # is safe only because _REENTRANCY_ENV is set in this process and
        # inherited by children (sandbox passes BUGWOLF_* through): the
        # nested verifier defers to the enclosing proof.  The guard lives
        # in committed code, so clones honor it too.
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

# Disk cache: the probe result is a function of HEAD + the code at HEAD,
# so it is stored per-commit and reused by every gate in the session
# (readiness CLI, capability manifest, CI).  A cache entry is valid only
# for the exact HEAD it was produced from and only for one day; anything
# else triggers a fresh probe.  This keeps the release gates fast without
# weakening them: the evidence still exists, bound to the commit.
_CACHE_TTL_SECONDS = 24 * 3600


def _cache_path(project_root) -> Path:
    return Path(project_root) / "state" / "release" / "l2-probe.json"


def _cached_probe(head: str, *, project_root) -> dict | None:
    import time as _time
    try:
        raw = json.loads(_cache_path(project_root).read_text("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    if raw.get("head") != head:
        return None
    age = _time.time() - float(raw.get("ts", 0))
    if age < 0 or age > _CACHE_TTL_SECONDS:
        return None
    if not isinstance(raw.get("report"), dict):
        return None
    return raw


def _store_probe(head: str, report: dict, *, project_root) -> None:
    import time as _time
    path = _cache_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"schema": "bugwolf-l2-probe-cache/v1", "head": head,
         "ts": _time.time(), "report": report}, indent=2))


def verify_clean_checkout(*, fresh: bool = False) -> tuple:
    """(ok, detail) verifier for the readiness manifest's L2 claim.

    Runs the probe once per HEAD (disk-cached in state/release/, TTL one
    day); ``fresh=True`` forces a live re-run.
    """
    try:
        if _reentrant():
            return True, ("deferred: an enclosing clean-checkout probe is "
                          "active in this process tree (re-entrancy guard); "
                          "its result is the proof for this nested check")
        from tools.runtime_paths import workspace_root
        root = Path(workspace_root())
        head_r = _run(["git", "rev-parse", "HEAD"], REPO_ROOT, 15)
        head = head_r.stdout.strip() if head_r.returncode == 0 else "unknown"

        rep = None
        if not fresh:
            cached = _cached_probe(head, project_root=root)
            if cached is not None:
                rep = cached["report"]
                source = f"cached (head {head[:12]})"
        if rep is None:
            rep = probe_clean_checkout()
            _store_probe(head, rep, project_root=root)
            source = "live probe"
        detail = f"[{source}] " + "; ".join(
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
    parser.add_argument("--fresh", action="store_true",
                        help="force a live probe even if a valid cache "
                             "entry exists for HEAD")
    args = parser.parse_args(argv)
    if args.fresh:
        rep = probe_clean_checkout()
    else:
        ok, detail = verify_clean_checkout()
        rep = {"ok": ok, "detail": detail}
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
    elif "steps" in rep:
        for step in rep["steps"]:
            print(f"  {step['step']:14s} {'ok' if step['ok'] else 'FAIL'}"
                  f"  {str(step.get('detail', ''))[:100]}")
        print(f"clean-checkout reproducible: {'YES' if rep['ok'] else 'NO'}"
              f"  (head {rep['repo_head'][:12]})")
    else:
        print(f"clean-checkout reproducible: {'YES' if rep['ok'] else 'NO'}")
        print(f"  {rep.get('detail', '')}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

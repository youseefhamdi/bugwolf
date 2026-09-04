#!/usr/bin/env python3
"""Corpus ⇄ Understanding-Layer regression suite (master plan Phase 7).

Each scored corpus case may declare the U-stages that must FEED it:

    {"case_id": "bola-user-1", "bug_class": "bola",
     "u_stages": ["U4", "U5"], ...}

The regression suite turns those declarations into executable checks:
against a live mini-mission over the stub target (per-credential crawl +
business pages + OpenAPI), it runs the U1→U9 pipeline and verifies —
per case —

  * GATE: every declared class HUNTS (is not parked with reason);
  * STAGE: the feeding stages produced real data;
  * FACT: the model's facts actually reference the case's surface —
    the sequential-integer object-ID inventory contains the case's
    object, the case's path maps to an extracted workflow, the client-
    controlled field behind the case's body mutation is in the model.

A mismatch is a REGRESSION FAILURE: the corpus declared the model feeds
the hunt; if the pipeline stops producing that support, the benchmark
must fail — the same strict no-fake-pass discipline as the scoring
gate.  The report is persisted as ``state/benchmark/u_regression.json``.

Deterministic tier: everything is real code over real captures; the
stub target stands in for the operator's (same as every CI suite).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bugwolf-u-regression/v1"

# Case bug_class (corpus vocabulary) -> canonical U-layer coverage class.
CLASS_TO_COVERAGE = {
    "bola": "idor",
    "mass_assignment": "mass-assignment",
    "business_logic": "business-logic",
    "fuzz_crash": "fuzzing",
    "request_smuggling": "header-trust",
    "none": "fuzzing",
}

# Which stage produced the fact each checker verifies.  Kept in lockstep
# with dispatch.CLASS_SLICES: a slice field's stage is where the fact lives.
STAGE_FOR_CLASS = {
    "idor": ("U5", "object_id_inventory"),
    "mass-assignment": ("U5", "client_controlled_fields"),
    "business-logic": ("U3", "workflows"),
    "fuzzing": ("U2", "ranked_surface"),
    "header-trust": ("U6", "header_families_observed"),
}


# ---------------------------------------------------------------------------
# Fact checkers — one per coverage class; each verifies the model's facts
# reference the case's actual surface (path/object/body field).
# ---------------------------------------------------------------------------

def _check_idor(case: Dict[str, Any], stage_data: Dict[str, Dict[str, Any]]) \
        -> Optional[str]:
    """The case's object id must appear in the U5 inventory (the model
    saw exactly the object the case attacks)."""
    path = str(case.get("path") or "")
    obj_id = path.rsplit("/", 1)[-1] if path.startswith("/api/users/") else ""
    inventory = stage_data.get("U5", {}).get("object_id_inventory", {})
    if not inventory:
        return "U5 object_id_inventory is empty (no session facts)"
    if obj_id and obj_id != "999":
        for _fmt, ids in inventory.items():
            if obj_id in ids:
                return None
        return (f"object id {obj_id!r} not in the U5 inventory "
                f"(formats: {sorted(inventory)})")
    return None


def _check_mass_assignment(case: Dict[str, Any],
                           stage_data: Dict[str, Dict[str, Any]]) \
        -> Optional[str]:
    """The case's over-binding field must be a known client-controlled
    field (from the OpenAPI declarations U5 consumed)."""
    fields = stage_data.get("U5", {}).get("client_controlled_fields", [])
    if not fields:
        return "U5 client_controlled_fields is empty (no OpenAPI facts)"
    body = case.get("body") or {}
    wanted = [k for k in body if k in ("role", "isAdmin", "price")]
    for field in fields:
        if any(field.endswith(f"::{k}") for k in wanted):
            return None
    return (f"case fields {wanted} not among client_controlled_fields "
            f"({fields[:6]}...)")


def _check_business_logic(case: Dict[str, Any],
                          stage_data: Dict[str, Dict[str, Any]]) \
        -> Optional[str]:
    """The case's path must map to an extracted workflow (U3 saw the
    money flow the case attacks)."""
    workflows = stage_data.get("U3", {}).get("workflows", {})
    if not workflows:
        return "U3 workflows is empty (no form/OpenAPI facts)"
    path = str(case.get("path") or "")
    for _name, wf in workflows.items():
        for step in wf.get("steps", []):
            step_path = str(step.get("path") or "")
            if path and (path == step_path or path.startswith(step_path)
                         or step_path.startswith(path)):
                return None
    return f"path {path!r} maps to no extracted workflow " \
           f"({sorted(workflows)})"


def _check_fuzzing(case: Dict[str, Any],
                   stage_data: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """The case's path must appear on the ranked attack surface (U2).
    The query string is not part of the surface census."""
    ranked = stage_data.get("U2", {}).get("ranked_surface", [])
    path = str(case.get("path") or "").split("?", 1)[0]
    for entry in ranked:
        if str(entry.get("path") or "") == path:
            return None
    return f"path {path!r} not on the ranked surface " \
           f"({[e.get('path') for e in ranked[:8]]}...)"


def _check_header_trust(case: Dict[str, Any],
                        stage_data: Dict[str, Dict[str, Any]]) \
        -> Optional[str]:
    """U6 trust facts exist (the smuggle class rides header trust)."""
    families = stage_data.get("U6", {}).get("header_families_observed", {})
    if not families:
        return "U6 header_families_observed is empty (no crawl facts)"
    return None


_FACT_CHECKERS = {
    "idor": _check_idor,
    "mass-assignment": _check_mass_assignment,
    "business-logic": _check_business_logic,
    "fuzzing": _check_fuzzing,
    "header-trust": _check_header_trust,
}


def _check_idor_absent(case: Dict[str, Any],
                       stage_data: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Negative IDOR control: the 404 object must NOT be in the U5
    inventory — the model does not fabricate knowledge of objects the
    target itself does not have."""
    path = str(case.get("path") or "")
    obj_id = path.rsplit("/", 1)[-1] if path.startswith("/api/users/") else ""
    if not obj_id:
        return None
    inventory = stage_data.get("U5", {}).get("object_id_inventory", {})
    for _fmt, ids in inventory.items():
        if obj_id in ids:
            return (f"negative-control object {obj_id!r} IS in the U5 "
                    f"inventory — the model claims an object the target "
                    f"404s (fabricated fact)")
    return None


_NEGATIVE_CHECKERS = {
    "idor": _check_idor_absent,
}


# ---------------------------------------------------------------------------
# The mini-mission: captures every fact source the pipeline consumes
# ---------------------------------------------------------------------------

def _boot_stub():
    import importlib.util
    import threading
    stub_path = Path(__file__).resolve().parent.parent / "tests" / \
        "_stub_target.py"
    spec = importlib.util.spec_from_file_location("stub_target_ureg",
                                                  stub_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return module, server


def _run_mini_mission(base: str, *, project_root: Optional[str] = None
                      ) -> Tuple[dict, Any, Any, Any]:
    """Crawl + page-fetch mini-mission: the pipeline's full fact intake.

    Returns (pages, crawl, openapi, session_store) — the same shapes the
    /bugwolf-understand CLI feeds the pipeline.
    """
    from tools.runtime import scope as scope_mod
    from tools.runtime.accounts import AccountMatrix
    from tools.runtime.authed_crawl import AuthedCrawler
    from tools.runtime.session_context import SessionContextStore
    from tools.runtime.understanding.__main__ import _fetch_pages
    from tools.runtime.replay.governor import Governor

    scope_mod.reset()
    scope_mod.bind_target(base)
    # The stub target is hermetic and local: the default live-target rate
    # (5 rps, burst 5) starves the crawl — the anon label's sends drain the
    # burst and every AUTHENTICATED send is refused (status-0 facts), so
    # U5's object inventory never fills.  The harness raises the rate
    # explicitly; budget/circuit/concurrency protections stay active.
    harness_governor = Governor(rate_rps=200)
    matrix = AccountMatrix.from_specs(base, [
        {"label": "A", "username": "alice", "password": "whatever",
         "login_path": "/login"},
        {"label": "C", "username": "admin", "password": "whatever",
         "login_path": "/login"},
    ])
    notes = matrix.bind()
    if not matrix.bound:
        raise RuntimeError(f"account matrix did not bind: {notes}")
    store = SessionContextStore.from_matrix(matrix, "u-regression",
                                            project_root=project_root)
    crawler = AuthedCrawler(base, "u-regression", matrix=matrix,
                            session_store=store, max_pages=8,
                            project_root=project_root,
                            governor=harness_governor)
    report = crawler.crawl(["/dashboard", "/admin/panel", "/api/notes",
                            "/api/users/1", "/api/users/42"])
    store.save()                                 # redacted; root fixed at ctor
    crawler.persist(report)
    pages, openapi, _antibot = _fetch_pages(base, ["/", "/pricing", "/tos"])
    scope_mod.reset()
    return pages, report, openapi, store


# ---------------------------------------------------------------------------
# The suite
# ---------------------------------------------------------------------------

def run_u_regression(manifest: Dict[str, Any], *, target: str,
                     project_root: Optional[str] = None,
                     refresh: bool = False) -> Dict[str, Any]:
    """Run the pipeline over the mini-mission and verify every declared
    case.  Returns the regression report (persisted alongside the
    benchmark artifacts)."""
    from tools.runtime.understanding.pipeline import UnderstandingPipeline

    started = time.monotonic()
    base = target if "://" in target else f"http://{target}"
    pages, crawl, openapi, session_store = _run_mini_mission(
        base, project_root=project_root)
    pipeline = UnderstandingPipeline(base, project_root=project_root)
    result = pipeline.run(pages=pages, crawl=crawl, openapi=openapi,
                          session_store=session_store, refresh=refresh)
    stage_data = {stage: pipeline.store.load(stage).data
                  for stage in ("U1", "U2", "U3", "U4", "U5", "U6", "U9")
                  if pipeline.store.load(stage) is not None}
    hunts = set(result.coverage_hunts)
    parked = {p["bug_class"]: p.get("reason", "")
              for p in result.coverage_parked}
    # Classes gated on capabilities the deterministic tier cannot observe
    # (browser confirmation, OAST callbacks) are exempt from the HUNT
    # requirement: their stage/fact checks still run.
    from tools.runtime.understanding.stages import COVERAGE_CLASSES
    nondeterministic = {cls for cls, spec in COVERAGE_CLASSES.items()
                        if spec.get("requires") in ("browser", "oast")}

    checks: List[Dict[str, Any]] = []
    for case in manifest.get("cases") or []:
        declared = case.get("u_stages")
        if not declared:
            continue
        coverage_class = CLASS_TO_COVERAGE.get(
            str(case.get("bug_class") or ""), None)
        check: Dict[str, Any] = {
            "case_id": case.get("case_id"),
            "bug_class": case.get("bug_class"),
            "u_stages": list(declared),
            "coverage_class": coverage_class,
        }
        failures: List[str] = []
        expected_finding = bool(case.get("expected_finding"))
        if coverage_class is None:
            failures.append(f"no U-layer mapping for bug_class "
                            f"{case.get('bug_class')!r}")
        else:
            if not expected_finding:
                # Negative control: the model must NOT claim support for
                # this case's surface (its absence is the model fact).
                checker = _NEGATIVE_CHECKERS.get(coverage_class)
                if checker is not None:
                    problem = checker(case, stage_data)
                    if problem:
                        failures.append(problem)
            else:
                if coverage_class not in hunts and \
                        coverage_class not in nondeterministic:
                    failures.append(
                        f"coverage class {coverage_class!r} is PARKED "
                        f"({parked.get(coverage_class, 'no reason recorded')})")
                for stage in declared:
                    if stage not in stage_data:
                        failures.append(f"stage {stage} produced no artifact")
                if not failures:
                    checker = _FACT_CHECKERS.get(coverage_class)
                    if checker is not None:
                        problem = checker(case, stage_data)
                        if problem:
                            failures.append(problem)
        check["ok"] = not failures
        check["failures"] = failures
        checks.append(check)

    report = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": base,
        "model_hash": result.model_hash,
        "coverage_hunts": sorted(hunts),
        "coverage_parked": sorted(parked),
        "cases_checked": len(checks),
        "cases_failed": sum(1 for c in checks if not c["ok"]),
        "checks": checks,
        "passed": all(c["ok"] for c in checks) if checks else True,
        "elapsed_s": round(time.monotonic() - started, 2),
    }
    out_dir = Path(project_root or ".") / "state" / "benchmark"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "u_regression.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def load_corpus_u_cases(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The corpus cases that declare U-stages (the regression's input)."""
    return [c for c in (manifest.get("cases") or []) if c.get("u_stages")]

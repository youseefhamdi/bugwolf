#!/usr/bin/env python3
"""
## Source: bugwolf Phase 1.5 (new package — cross-project port registry)
## License: bugwolf-MIT
## Port: 2026-09-05

Cross-project capability absorption library.

This package holds the 16 ported modules from sister bug-bounty projects
(Agentic-Bug-Hunter, HackGATE, BurpGPT, h1-jwt-tamper, etc.).  Each
sub-module starts with a ``## Source:`` comment block so the
:mod:`scripts.cross_project_citation_check` script can enforce citation
discipline.

Sub-phases covered:

  1.5.a  react_memory              — ReAct 3-layer memory
  1.5.b  dom_xss_harness           — DOM XSS confirmation harness
  1.5.b  waf_encoder               — 11-technique WAF bypass encoder
  1.5.c  multipart_mutator         — 10-technique multipart parser-confusion
  1.5.d  lead_board                — URL/tech -> hunt-skill routing
  1.5.e  secret_scan               — 80-pattern stdlib secret scanner
  1.5.e  h1_reference              — H1 Hacktivity prior-art fetcher
  1.5.f  scan_identifiers          — fail-closed repo-leak guard
  1.5.g  confidence_gates          — TENTATIVE / FIRM / CONFIRMED gates
  1.5.h  claude_skills_manifest    — 78-skill curated library
  1.5.i  subdomain_takeover_v20    — 20-vendor takeover catalog + JWT tamper
  1.5.j  identity_segregation      — 4-kind identity model
  1.5.k  structured_contracts      — STRUCTURED_CONTRACTS + redact_argv + exit
  1.5.l  fts5_finding_store        — 3-layer FTS5-equivalent finding store
  1.5.m  model_scorecard           — Wilson-bounded miss-rate + budget
  1.5.n  safe_subprocess_lib       — safe_subprocess + action_guard + redact
  1.5.o  yaml_workflow_dsl         — YAML workflow DSL + SARIF import
  1.5.p  santa_loop_convergence    — /santa-loop dual-review convergence

Public surface:
  * :func:`get_module(name)`     — look up a sub-module's primary class.
  * :func:`list_subphases()`     — enumerate (subphase, primary class) tuples.
  * :func:`citation_snapshot()`  — return a {module: source_block} map.
"""
from __future__ import annotations

import importlib
from typing import Dict, List, Optional, Tuple


# (module_stem, primary_class) — stable order is by sub-phase letter
_REGISTRY: Tuple[Tuple[str, str], ...] = (
    ("react_memory", "ReActMemory"),
    ("dom_xss_harness", "DOMXSSHarness"),
    ("waf_encoder", "WAFEncoder"),
    ("multipart_mutator", "MultipartMutator"),
    ("lead_board", "LeadBoard"),
    ("secret_scan", "SecretScanner"),
    ("h1_reference", "H1Reference"),
    ("scan_identifiers", "IdentifierScanner"),
    ("confidence_gates", "ConfidenceGate"),
    ("claude_skills_manifest", "SkillManifest"),
    ("subdomain_takeover_v20", "SubdomainTakeoverV20"),
    ("identity_segregation", "IdentitySegregator"),
    ("structured_contracts", "Contract"),
    ("fts5_finding_store", "FindingStore"),
    ("model_scorecard", "ModelScorecard"),
    ("safe_subprocess_lib", "safe_subprocess"),
    ("yaml_workflow_dsl", "WorkflowDSL"),
    ("santa_loop_convergence", "santa_loop"),
)


def get_module(name: str):
    """Return the loaded sub-module for ``name`` or ``None``."""
    try:
        return importlib.import_module(f"{__name__}.{name}")
    except Exception:
        return None


def get_class(name: str):
    """Return the primary class registered for ``name``."""
    mod = get_module(name)
    if mod is None:
        return None
    for stem, primary in _REGISTRY:
        if stem == name:
            return getattr(mod, primary, None)
    return None


def list_subphases() -> List[Tuple[str, str]]:
    """Return ``[(module_name, primary_class_name), ...]`` in stable order."""
    return list(_REGISTRY)


def citation_snapshot() -> Dict[str, str]:
    """Return ``{module_name: leading_docstring}`` for citation audit."""
    out: Dict[str, str] = {}
    for stem, _ in _REGISTRY:
        mod = get_module(stem)
        if mod is None:
            out[stem] = ""
            continue
        doc = getattr(mod, "__doc__", "") or ""
        out[stem] = doc.strip().splitlines()[0] if doc.strip() else ""
    return out


__all__ = [
    "get_module", "get_class", "list_subphases", "citation_snapshot",
]
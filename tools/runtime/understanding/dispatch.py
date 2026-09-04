#!/usr/bin/env python3
"""Model-slice dispatch (master plan §8.3): the model feeds the hunt.

Every dispatch prompt is augmented with the slice of the Target Model the
agent's bug class needs — a hunting agent for business-logic receives the
workflow state machines (U3) + money paths (U1); an IDOR agent receives
the object-ID inventory (U5) + roles (U4).  **No agent hunts from a blank
slate**, and the coverage gate is enforced at dispatch time: a class the
model PARKED is skipped and the skip is recorded as a fact — payloads
never fire where the model has no support.

Deterministic tier: pure reads over stored artifacts.  No model → no-op
(``None`` slices, empty prompt block) so every existing dispatch path is
byte-identical when the Understanding Layer has not run.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tools.runtime.understanding.base import ModelStore

SCHEMA = "bugwolf-model-slice/v1"

# ---------------------------------------------------------------------------
# Bug-class normalization (lanes, registry, and the U-layer use different
# vocabularies; dispatch accepts all of them).
# ---------------------------------------------------------------------------

_ALIASES = {
    "idor": "idor", "bola": "idor", "access_control": "idor",
    "authz-bypass": "authz-bypass", "authz_bypass": "authz-bypass",
    "auth_bypass": "authz-bypass", "broken-authz": "authz-bypass",
    "mass-assignment": "mass-assignment", "mass_assignment": "mass-assignment",
    "business-logic": "business-logic", "business_logic": "business-logic",
    "price-manipulation": "price-manipulation",
    "price_manipulation": "price-manipulation",
    "voucher-race": "voucher-race", "voucher_race": "voucher-race",
    "race-condition": "voucher-race",
    "jwt-confusion": "jwt-confusion", "jwt_confusion": "jwt-confusion",
    "header-trust": "header-trust", "header_trust": "header-trust",
    "waf_bypass": "header-trust", "waf-bypass": "header-trust",
    "client_side": "xss-dom", "xss-dom": "xss-dom", "xss": "xss-dom",
    "ssrf-callback": "ssrf-callback", "ssrf": "ssrf-callback",
    "fuzzing": "fuzzing", "generic": "fuzzing",
    "contract_logic": "fuzzing", "cloud_iam": "fuzzing",
    "llm_tooling": "fuzzing",
}

# Canonical class -> {stage: [fields]} (the slice each agent class needs).
CLASS_SLICES: Dict[str, Dict[str, List[str]]] = {
    "idor": {"U5": ["object_id_inventory", "object_id_format_counts"],
             "U4": ["roles"]},
    "authz-bypass": {"U4": ["authz_boundaries", "roles", "identity_matrix"],
                     "U5": ["object_id_format_counts"]},
    "mass-assignment": {"U5": ["client_controlled_fields"]},
    "price-manipulation": {"U5": ["client_controlled_fields"],
                           "U1": ["money_paths"]},
    "business-logic": {"U3": ["workflows"], "U1": ["money_paths"]},
    "voucher-race": {"U3": ["workflows"], "U1": ["money_paths"]},
    "jwt-confusion": {"U4": ["roles"]},
    "header-trust": {"U6": ["trust_points", "header_families_observed"],
                     "U2": ["ranked_surface"]},
    "xss-dom": {"U2": ["ranked_surface"]},
    "ssrf-callback": {"U2": ["ranked_surface"]},
    "fuzzing": {"U2": ["ranked_surface"]},
}


def normalize_class(bug_class: str) -> str:
    """Canonical U-layer class for any lane/registry vocabulary."""
    return _ALIASES.get(str(bug_class or "").strip().lower(),
                        str(bug_class or "").strip().lower())


# ---------------------------------------------------------------------------
# Gate + slice loading
# ---------------------------------------------------------------------------

def load_model(target: str, *, project_root=None,
               store: Optional[ModelStore] = None) -> Optional[Dict[str, Any]]:
    """The stored Target Model (U9) for a target, or None when absent."""
    store = store or ModelStore(target, project_root=project_root)
    artifact = store.load("U9")
    return dict(artifact.data) if artifact else None


def coverage_gate(bug_class: str, model: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Dispatch-time coverage gate (§8.1 U9, enforced where it matters).

    Returns {"status": hunts|parked|absent, "reason": str}.  ``absent``
    means no model exists — dispatch proceeds unchanged (the model never
    blocks a mission that never modeled; it only refuses to endorse).
    """
    canonical = normalize_class(bug_class)
    if not model:
        return {"status": "absent", "reason": "no target model stored"}
    if canonical in (model.get("hunts") or []):
        return {"status": "hunts", "reason": ""}
    for parked in model.get("parked") or []:
        if normalize_class(parked.get("bug_class", "")) == canonical:
            return {"status": "parked",
                    "reason": str(parked.get("reason", ""))}
    # Class unknown to the gate (e.g. domain lanes): dispatch, no slice.
    return {"status": "unmodeled",
            "reason": "class not in the model's coverage gate"}


def model_slice(bug_class: str, target: str, *, project_root=None,
                store: Optional[ModelStore] = None) -> Optional[Dict[str, Any]]:
    """The dispatch slice for one bug class, or None without a model.

    Shape: {"schema", "bug_class", "status", "reason", "model_type",
            "slices": {stage: {field: value}}, "hypotheses": [...],
            "capabilities": [...], "model_hash"}
    """
    store = store or ModelStore(target, project_root=project_root)
    model = load_model(target, store=store)
    gate = coverage_gate(bug_class, model)
    if gate["status"] == "absent":
        return None
    canonical = normalize_class(bug_class)
    wanted = CLASS_SLICES.get(canonical, {})

    slices: Dict[str, Dict[str, Any]] = {}
    for stage, fields in wanted.items():
        artifact = store.load(stage)
        if artifact is None:
            continue
        data = artifact.data or {}
        slices[stage] = {field: data[field] for field in fields
                         if field in data}

    hypotheses = [h for h in (model.get("hypotheses") or [])
                  if h.get("stage") in wanted]
    capabilities: List[Dict[str, Any]] = []
    u7 = store.load("U7")
    if u7 is not None:
        capabilities = (u7.data or {}).get("capabilities", [])[:10]

    return {
        "schema": SCHEMA,
        "bug_class": canonical,
        "status": gate["status"],
        "reason": gate["reason"],
        "model_type": _model_type(store),
        "slices": slices,
        "hypotheses": hypotheses,
        "capabilities": capabilities,
        "model_hash": (store.load("U9").artifact_hash
                       if store.load("U9") else ""),
    }


def _model_type(store: ModelStore) -> str:
    u1 = store.load("U1")
    return (u1.data or {}).get("model_type", "unknown") if u1 else "unknown"


# ---------------------------------------------------------------------------
# Prompt block rendering (what actually rides in the dispatch prompt)
# ---------------------------------------------------------------------------

_MAX_ITEMS = 8


def _fmt_money_paths(u1: Dict[str, Any]) -> List[str]:
    seen, out = set(), []
    for entry in (u1.get("money_paths") or [])[:_MAX_ITEMS]:
        line = f"- `{entry.get('path', '')}` — {entry.get('term', '')} " \
               f"({entry.get('kind', '')})"
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def _fmt_workflows(u3: Dict[str, Any]) -> List[str]:
    out = []
    for name, wf in list((u3.get("workflows") or {}).items())[:_MAX_ITEMS]:
        steps = " -> ".join(
            f"{s.get('path', '')}"
            f"{' (' + str(s.get('fields', 0)) + ' fields)' if s.get('fields') else ''}"
            for s in (wf.get("steps") or [])[:6])
        out.append(f"- **{name}**: {steps or '(no steps observed)'}")
    return out


def _fmt_boundaries(u4: Dict[str, Any]) -> List[str]:
    out = []
    for boundary in (u4.get("authz_boundaries") or [])[:_MAX_ITEMS]:
        statuses = ", ".join(f"{label}:{status}" for label, status in
                             sorted((boundary.get("status_by_label") or {}).items()))
        out.append(f"- `{boundary.get('path', '')}` — {statuses}")
    return out


def _fmt_object_ids(u5: Dict[str, Any]) -> List[str]:
    out = []
    inventory = u5.get("object_id_inventory") or {}
    for fmt, ids in list(inventory.items())[:4]:
        sample = ", ".join(str(i) for i in ids[:_MAX_ITEMS])
        out.append(f"- {fmt} ({len(ids)}): {sample}")
    return out


def _fmt_client_fields(u5: Dict[str, Any]) -> List[str]:
    return [f"- `{field}`" for field in
            (u5.get("client_controlled_fields") or [])[:_MAX_ITEMS]]


def _fmt_surface(u2: Dict[str, Any]) -> List[str]:
    out = []
    for row in (u2.get("ranked_surface") or [])[:5]:
        out.append(f"- `{row.get('path', '')}` (criticality "
                   f"{row.get('criticality', 0)})")
    return out


def render_prompt_block(bug_class: str,
                        slice_dict: Optional[Dict[str, Any]]) -> str:
    """The markdown block appended to a hunting agent's dispatch prompt.

    Empty string when there is no model — the prompt is byte-identical to
    the pre-U-layer form (no model, no noise).
    """
    if not slice_dict:
        return ""
    canonical = slice_dict.get("bug_class", normalize_class(bug_class))
    lines: List[str] = []
    lines.append(f"## Target Model slice — {canonical} "
                 f"[{slice_dict.get('status', 'unknown')}]")
    lines.append("")
    lines.append(f"Business model: {slice_dict.get('model_type', 'unknown')}. "
                 "Everything below is OBSERVED by the deterministic "
                 "U-layer — test it, don't re-derive it, and never hunt "
                 "from a blank slate.")
    lines.append("")
    slices = slice_dict.get("slices") or {}

    if "U1" in slices:
        lines.append("**Money paths (U1):**")
        lines.extend(_fmt_money_paths(slices["U1"]))
        lines.append("")
    if "U3" in slices:
        lines.append("**Workflows (U3) — test step order, repetition, skip:**")
        lines.extend(_fmt_workflows(slices["U3"]))
        lines.append("")
    if "U4" in slices:
        boundaries = _fmt_boundaries(slices["U4"])
        if boundaries:
            lines.append("**Authz boundaries (U4) — observed differentials:**")
            lines.extend(boundaries)
            lines.append("")
        roles = (slices["U4"].get("roles") or {})
        if roles:
            rendered = ", ".join(
                f"{label}={info.get('role') or '?'} ({info.get('role_source', '?')})"
                for label, info in list(roles.items())[:6])
            lines.append(f"**Identities (U4):** {rendered}")
            lines.append("")
    if "U5" in slices:
        ids = _fmt_object_ids(slices["U5"])
        if ids:
            lines.append("**Object IDs (U5) — enumerate neighbors across "
                         "identities:**")
            lines.extend(ids)
            lines.append("")
        fields = _fmt_client_fields(slices["U5"])
        if fields:
            lines.append("**Client-controlled fields (U5) — boundary values, "
                         "mass-assignment sets:**")
            lines.extend(fields)
            lines.append("")
    if "U6" in slices:
        families = (slices["U6"].get("header_families_observed") or {})
        if families:
            lines.append("**Header-trust families observed (U6):** "
                         + ", ".join(sorted(families)))
            lines.append("")
    if "U2" in slices:
        surface = _fmt_surface(slices["U2"])
        if surface:
            lines.append("**Highest-business-criticality surface (U2):**")
            lines.extend(surface)
            lines.append("")

    hypotheses = slice_dict.get("hypotheses") or []
    if hypotheses:
        lines.append("**Hypotheses from the Assumption Ledger — test THESE "
                     "dispro plans first:**")
        for position, hypothesis in enumerate(hypotheses[:5], start=1):
            lines.append(f"- H{position} [{hypothesis.get('stage', '?')}] "
                         f"fragility {hypothesis.get('fragility', '?')}: "
                         f"{hypothesis.get('statement', '')}")
            lines.append(f"  Dispro plan: {hypothesis.get('dispro_plan', '')}")
        lines.append("")

    if slice_dict.get("status") == "parked":
        lines.append(f"> COVERAGE GATE: this class is PARKED — "
                     f"{slice_dict.get('reason', '')} Record this fact and "
                     "do not spray payloads; expanding scope is a model "
                     "change (re-run the Understanding Layer), not a "
                     "payload change.")
        lines.append("")
    lines.append(f"_model_hash: {slice_dict.get('model_hash', '')[:16]}_")
    return "\n".join(lines).rstrip() + "\n"


def dispatch_context(bug_class: str, target: str, *, project_root=None,
                     store: Optional[ModelStore] = None) -> Dict[str, Any]:
    """One call for dispatch sites: the slice + the rendered prompt block.

    Returns {"target_model": slice-or-None, "model_prompt_block": str,
             "gate": {...}} — the ``target_model``/``model_prompt_block``
    keys drop into the existing intel payload unchanged.
    """
    slice_dict = model_slice(bug_class, target, project_root=project_root,
                             store=store)
    gate = ({"status": slice_dict["status"], "reason": slice_dict["reason"]}
            if slice_dict else
            {"status": "absent", "reason": "no target model stored"})
    return {
        "target_model": slice_dict,
        "model_prompt_block": render_prompt_block(bug_class, slice_dict),
        "gate": gate,
    }

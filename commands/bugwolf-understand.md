---
description: Run the Understanding Layer (U1–U9) on a target and print the Hunting Brief — the front door
argument-hint: "<target> [mission-id] [--refresh]"
---

# BugWolf understand

The thesis, executed: **you cannot hunt what you haven't modeled.** This
command runs the nine sequential U-stages as a real pipeline — each stage's
artifact is the next stage's mandatory input, hash-chained and incremental —
and ends with the Hunting Brief. Bug classes with no model support are
PARKED with a reason, not sprayed blindly.

## How to run it

1. Primary (native tool, available in every session):
   `bugwolf_understand` with `{"target": "<t>", "mission_id": "<id>",
   "refresh": false}` — the bridge fetches the U1 business pages through
   the replay engine (scope-gated), pulls `/openapi.json` when published,
   and consumes the mission's crawl + session artifacts when a
   `mission_id` is given.
2. Direct CLI equivalent:
   ```bash
   python3 -m tools.runtime.understanding --target <t> \
     [--paths /pricing,/tos] [--mission-id <id>] [--refresh] --json
   ```
3. Artifacts land in `state/targets/<t>/model/`:
   `u1-business.json … u7-capabilities.json`, `u8-assumptions.jsonl`
   (the zero-day seed list — hand-annotatable), `u9-target-model.json`
   (versioned, hash-chained), and **`hunting-brief.md`**.

## The sequence (enforced by construction, fail-closed)

- **U1 Business Model** → entities, monetization points, money paths,
  trust decisions, model-type classification (from the fetched pages).
- **U2 Recon Census** → surface ranked by business criticality (U1 ×
  surface), never generic severity.
- **U3 Application Logic** → workflows (auth/purchase/redemption/recovery…)
  with steps + field counts from crawl forms and the OpenAPI document;
  state-machine candidates from state verbs.
- **U4 Identity/Authz** → roles with source attribution, JWT alg/claim
  inventory, identity matrix, observed authz boundaries (differentials).
- **U5 Data & State** → object-ID inventory by format (sequential/UUID/
  encoded), client-controlled fields (the mass-assignment surface).
- **U6 Trust & Boundaries** → header/trust families observed; probe
  results from `header_trust.py` merge in when the operator ran them.
- **U7 Capability Map** → (role, object, verb, impact) ranked dollars →
  privilege → ATO/PII → business.
- **U8 Assumption Ledger** → every stage's stated assumptions with origin,
  confidence, and a dispro plan; ranked by fragility. THE ZERO-DAY SEED
  LIST. Operators may annotate statuses by hand (the pipeline accepts
  hand edits and recomputes around them).
- **U9 Synthesis & Coverage Gate** → Target Model; classes with no model
  support are PARKED WITH REASON; hypotheses ranked by U7 impact × U8
  fragility.

## The output — the Hunting Brief

Print `hunting-brief.md` to the operator: model-at-a-glance, the coverage
gate (hunts vs parked-with-reason), and the ranked hypotheses with their
dispro plans. **`/bugwolf-run` dispatches against THIS brief** — hunting
agents test dispro plans, they don't wander. Parked classes are out of
scope until the model gains support — expanding scope is a model change,
not a payload change.

Re-runs are incremental: only stages whose inputs changed recompute
(hash-chained). Use `--refresh` to force a full rebuild.

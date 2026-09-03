# BugWolf Zero-Day Research Mission Plan

**Date:** 2026-08-26  
**Version:** 1.2.10  
**Operating posture:** full-power, uncensored research execution; no authorization or scope gates added  
**Mission goal:** raise the reliability, reproducibility, observability, and zero-day research value of the existing plug-in without reducing research depth.

## Mission principles

1. Preserve unrestricted research capability and all existing domain coverage.
2. Do not claim guaranteed zero-day discovery.
3. Improve evidence quality rather than restricting hypotheses or probes.
4. Keep planning deterministic wherever possible.
5. Make failures explicit instead of silently continuing.
6. Keep research memory quarantined and provenance-bound.
7. Validate improvements with offline tests and the deterministic stub target (`tests/_stub_target.py`).
8. Avoid modifying unrelated user changes.

## Current baseline

- 915 tests currently pass.
- Python syntax and shell syntax checks pass.
- Core architecture: staged workflow, research loop, campaign engine, domain analyzers, live executor, fuzz bridge, evidence, and reporting.
- Current estimated engineering readiness: approximately 68% overall; approximately 80–85% for offline candidate discovery.
- Authorization is intentionally not a mission target and will remain unrestricted.

## Phase 1 — Capability truth and readiness telemetry

**Objective:** make support, maturity, and limitations machine-readable.

Tasks:

- Verify `configs/readiness.json` against the actual repository.
- Verify `tools/readiness.py` reports truthful capability status.
- Add or extend readiness metrics for:
  - domain coverage;
  - candidate evidence states;
  - replay rate;
  - impact-verification rate;
  - research freshness;
  - subsystem failures;
  - bundle completeness.
- Ensure unsupported or unavailable tooling is reported clearly rather than silently represented as success.

Acceptance criteria:

- Readiness output is reproducible offline.
- No output promises zero-day discovery.
- Capability claims match files actually present.

## Phase 2 — Execution reliability without authorization gates

**Objective:** retain full-power execution while preventing accidental runaway behavior.

Tasks:

- Review `tools/execution_controller.py` policy fields.
- Enforce only operational controls:
  - timeout handling;
  - request accounting;
  - maximum runtime;
  - output limits;
  - retry bounds;
  - concurrency bounds;
  - receipt completeness.
- Do not add scope or authorization rejection.
- Ensure transport errors, policy exhaustion, and operation failures are distinguishable in receipts.
- Review direct target-facing subprocess calls in `recon_engine.sh`, `fleet.py`, `infra_deploy.py`, `formal_verify.py`, and `js_ct_intel.py`.

Acceptance criteria:

- A long-running operation cannot silently exceed configured operational budgets.
- Every live operation has an auditable result state.
- Full research planning and probe generation remain unrestricted.

## Phase 3 — Evidence and candidate-state hardening

**Objective:** improve the quality of zero-day candidates and prevent false confirmation.

Tasks:

- Audit evidence schemas across `live_executor.py`, `observation.py`, `refutation.py`, `triage.py`, `state.py`, and `reporting.py`.
- Require confirmed candidates to distinguish:
  - hypothesis;
  - signal;
  - candidate;
  - reproduced;
  - impact verified;
  - human confirmed;
  - reportable.
- Ensure replay checks compare the relevant response, identity, state, and invariant evidence.
- Ensure evidence redaction occurs before persistence, logging, and egress.
- Preserve unconfirmed candidates as research objects instead of dropping them.

Acceptance criteria:

- A signal cannot be reported as a confirmed finding without replayable evidence.
- Missing impact remains visible as an open research state.
- Tampered or malformed evidence is rejected or clearly marked.

## Phase 4 — Novelty and root-cause analysis

**Objective:** improve the distinction between known patterns and potentially novel behavior.

Tasks:

- Audit `novelty.py`, `zero_day.py`, `zero_day_tracks.py`, `research_core.py`, and `adaptive_learning.py`.
- Add or verify candidate metadata for:
  - root-cause fingerprint;
  - trigger fingerprint;
  - affected boundary;
  - impact class;
  - prior-art references;
  - mutation lineage;
  - duplicate similarity;
  - confidence reason.
- Separate “novel to this campaign” from “novel to public research.”
- Preserve unknown novelty as unknown; never infer novelty from absence of local matches.

Acceptance criteria:

- Candidate output states exactly what novelty evidence exists.
- Duplicate and near-duplicate candidates are linked, not silently discarded.
- Research-derived candidates remain quarantined until reviewed.

## Phase 5 — Coverage-guided and state-aware research

**Objective:** increase the probability of discovering undocumented behavior.

Tasks:

- Audit `surface_model.py`, `mutator.py`, `discovery_scheduler.py`, `contract_discovery.py`, and `core/fuzz_bridge.py`.
- Measure coverage by:
  - endpoint/operation;
  - parameter/property;
  - role/identity;
  - state transition;
  - parser/content type;
  - protocol/version;
  - chain edge;
  - mutation family.
- Verify one-variable mutation lineage.
- Improve state-machine and differential follow-up selection.
- Keep local lab replay deterministic and bounded.

Acceptance criteria:

- Each probe can be mapped to a coverage dimension.
- Repeated dead mutations are avoided while unexplored values remain available.
- Crash/anomaly findings retain minimized reproductions.

## Phase 6 — Cross-domain chain intelligence

**Objective:** find high-impact combinations without losing provenance.

Tasks:

- Audit `deep_chain.py`, `kill_chain.py`, `chain_orchestrator.py`, `core/signal_bus.py`, and `core/campaign_orchestrator.py`.
- Verify event-to-chain propagation for domain analyzers.
- Ensure missing-link proposals identify their unproven edge.
- Ensure chain proposals do not become confirmed findings without evidence at every edge.
- Record chain refresh failures explicitly.

Acceptance criteria:

- Every chain has source findings, intermediate edges, terminal impact, and evidence status.
- Failed chain refreshes appear in campaign status.
- Candidate chains remain testable research objects.

## Phase 7 — Release and documentation truth

**Objective:** make the distributed plug-in reproducible and accurately documented.

Tasks:

- Regenerate `AUDIT.md` from repository state.
- Reconcile `DEPENDENCIES.md` with the current AST import graph.
- Verify all concrete documentation paths.
- Decide whether `dist/` bundles are generated-only or committed.
- Verify `scripts/build_skill.sh`, `scripts/ci_bundle_check.sh`, and install scripts.
- Add a dependency/tool manifest for optional Python packages and external binaries.
- Ensure lab fixtures and intentionally weak secrets are clearly marked and handled by packaging.

Acceptance criteria:

- Audit counts are generated, not manually copied.
- Bundles contain the expected files and no bytecode/build artifacts.
- A clean checkout can reproduce the bundle and test result.

## Phase 8 — Validation and readiness score

Run, in order:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q tools tests lab
bash -n tools/recon_engine.sh
bash scripts/ci_bundle_check.sh
```

Then calculate readiness across:

- offline analysis;
- recon and mapping;
- hypothesis generation;
- novelty analysis;
- live validation;
- evidence/reporting;
- operational reliability;
- release reproducibility.

The final report must provide:

1. completed mission items;
2. remaining blockers;
3. verified test results;
4. current readiness percentage;
5. explicit distinction between engineering readiness and probability of finding a zero-day.

## Definition of done

The mission is complete when:

- full-power research execution remains intact;
- operational failures are visible and bounded;
- candidate evidence states are reliable;
- novelty claims are conservative and traceable;
- cross-domain chains preserve provenance;
- release artifacts are reproducible;
- the full test and bundle checks pass;
- readiness is measured from verified evidence rather than marketing claims.

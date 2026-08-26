# Changelog

## v1.2.11 — Carlini Loop track: per-file brute-force discovery

- **`tools/carlini_loop.py` (NEW)**: applies the 2026 per-file brute-force
  zero-day discovery pattern (Carlini Loop / nano-analyzer / NOVA — see
  `ENHANCEMENT_PLAN.md`) to a local project. `enumerate_files` walks the
  project deterministically (surface extension filter, noise dirs excluded,
  size/line/file caps); `brief_file` builds a per-file security briefing
  (imports, functions, entry points, line-anchored dangerous sinks from a
  NOVA-style catalog — command exec, eval/deserialization, SQLi, SSRF, file
  write, path traversal, prototype pollution, header trust, SSTI,
  cache-key control); `build_units` emits one research unit per file with
  CTF framing for the harness to execute; `offline_scan` runs a model-free
  sink-catalog + existing surface-track floor; `register_results` intakes
  harness findings through `ZeroDayResearchEngine` (evidence + novelty
  dedup + optional chain synthesis). Repeated intake is idempotent (stable
  candidate ids filtered pre-registration; near-matches return
  `likely_variant`); candidates stay HYPOTHESIS until trigger+impact
  evidence exists; nothing is labeled a zero-day without human review.
- **Tests** (`tests/test_carlini_loop.py`, 20 tests): bounded enumeration
  (extension filters, noise exclusion, caps), briefing sink/entry-point
  extraction, one-unit-per-file dispatch with redacted briefing context,
  offline floor candidates, idempotent intake through the zero-day engine,
  near-match dedup, and a repo-wide self-scan bound check. Full suite: 940
  passing.

## v1.2.10 — Operator-approved bypass exploitation scored

- **`tools/intelligence/failure_learning.py` — `approve_candidate` (NEW)**:
  the operator gate between quarantine and reuse. Loads
  `research/<target>/learning/failure-bypass-candidates.json`, stamps the
  candidate `approved` (+`approved_by`/`approved_at`), persists back, and
  returns the updated `BypassCandidate`. Idempotent for already-approved
  candidates; raises `ValueError` for unknown ids or a missing ledger.
  `BypassCandidate` gains `approved_by`/`approved_at` fields.
- **`campaign_orchestrator.py` — `exploit_approved_bypass` (NEW)**: replays
  an operator-approved bypass payload live against a `fuzz_blocked`
  thread's blocked endpoint — the recorded request is rebuilt with the
  payload applied (`Name: value` → header, `?…` → query, else body /
  `?q=` for GET) and re-sent via `execute_exploit`; the outcome lands in
  `state/sessions/<target>/exploits.jsonl` as a `kind="bypass-approval"`
  record (`candidate_id`, `technique`, `approved_by`, `reproduced` =
  got through the defense, `demonstrated_impact`). The thread stays BLOCKED
  (the operator decision is untouched); advisory — failures never gate.
- **Self-eval Task 10 — `bypass-approval-exploited` milestone (NEW)**: the
  exploitation-phase task now scores the operator-approved bypass cycle —
  an approved candidate in the failure-learning ledger + a reproduced
  bypass-approval exploit with demonstrated impact (vacuous pass when no
  fuzz_blocked thread ever arose, mirroring Task 9's rate milestone).
- **Lab fixture**: `GET /api/gateway` — a deterministic WAF surface that
  403s fuzz-mutated `q` requests (`access denied` → akamai) unless the
  `X-Original-URL` bypass header is present, returning an admin gateway
  record (the failure-learning catalog's header-based path access
  technique).
- **Tests** (+7): `test_week6` approve-candidate unit tests (quarantine,
  approve+persist, idempotence, unknown/missing raises);
  `test_live_feedback_loop` full cycle test (blocked thread → approve →
  exploit → ledger + scored milestone) + no-approval negative test; the E2E
  deep-dive now drives the real cycle against the lab gateway (fuzz blocked
  → approve `X-Original-URL` candidate → 200 admin record) and scores the
  full 10-task eval at 100%. Bundle check seeds the approved candidate +
  blocked thread + bypass exploit so the milestone scores from inside the
  bundle. Full suite: 861 passing.

## v1.2.9 — Exploit feedback refines zero-day novelty

- **`tools/zero_day.py` — `hunt_exploit_feedback` (NEW)**: feeds a
  reproduced exploit's demonstrated impact into the novel-class hunter. The
  impact-reveal anomaly (the endpoint demonstrably returned data it should
  not) plus one candidate per derived chain-hypothesis class are generated,
  stamped with exploit provenance (`finding_id`, `replay_key`,
  `replayed_status`), confidence 0.8 (outranks fuzz crashes), severity bumped
  one tier for unlocks, and deduped per (bug_class, endpoint) so pass@k
  variants of the same finding never pile up. The novelty refinement:
  unlock candidates are built **impact-bounded** (impact half proven by the
  replay), so `NoveltyEngine.apply` promotes them into `NOVELTY_PENDING`
  with impact evidence — human-review-ready — instead of bare hypotheses;
  surfaces already in the pool come back `EXACT_DUPLICATE` and confirm the
  known candidate.
- **`campaign_orchestrator.py` — wiring**: `_feed_exploit_to_chains` now
  also calls `_feed_exploit_to_zero_day`, registering the candidates through
  the novelty engine and persisting them to
  `research/<target>/zero-day/exploit-feedback.jsonl`; the impact record
  carries `zero_day_novel` and the loop summary gains an `exploit_novel`
  counter. Advisory: feed failures never gate the exploitation phase.
- **Tests** (`tests/test_zero_day_research.py` +5,
  `tests/test_live_feedback_loop.py` +0 extended): reveal + unlock
  generation, novelty refinement to human-review-ready, skip rules
  (unreproduced / empty impact), pass@k dedup, determinism; live-loop test
  now asserts `exploit_novel` ≥ 1 and the persisted
  `exploit-feedback.jsonl` (unlocks at `novelty_pending` with impact trace).
  Full suite: 854 passing; CI bundle check 10/10.

## v1.2.8 — Exploit feedback feeds chain hypotheses

- **`tools/leads.py` — data-unlock derivation (NEW)**: deterministic
  `derive_data_unlock_classes` scans a demonstrated impact body for what it
  unlocks (role/admin → `privilege-escalation-web`, balance/amount →
  `business-logic`, email/SSN/PII → `mass-data-breach`, credentials/tokens →
  `account-takeover`/`api-key-exposure`, session/OAuth → `account-takeover`,
  SQL/shell surface → `rce`), falling back to the source class's deep-chain
  `EDGES` escalation targets when the body has no textual signal.
  `chain_hypotheses_from_exploit` builds OPEN-LEAD chain-pool records from
  those classes (stable `lead_id`, `bug_class`, `evidence_state=hypothesis`,
  source finding as chain partner, impact as trace) — pure, deterministic,
  no I/O.
- **`campaign_orchestrator.py` — exploit → chain feedback**: after a
  reproduced exploit records its `demonstrated_impact`, the loop persists the
  derived hypotheses as OPEN-LEAD records
  (`state/sessions/<target>/leads.jsonl`, `source: "exploit-feedback"`),
  rebuilds the chain graph via `chain_orchestrator.refresh_target` so the new
  classes join chain proposals, stamps `chain_hypotheses` on the impact
  record (`live_exploit` + `exploits.jsonl`), and publishes a `CHAIN_PROPOSAL`
  event. Advisory: feedback failures never gate the exploitation phase.
- **Tests** (`tests/test_leads.py` +8, `tests/test_live_feedback_loop.py`
  +1): unlock heuristics (financial/credentials/role/PII, EDGES fallback,
  determinism, cap, chain-consumable record shape) + the live loop writing
  feedback leads and rebuilding the chain graph end-to-end against the lab
  (2 exploited findings → 6 hypotheses → graph contains the new classes).
  Full suite: 849 passing; CI bundle check 10/10.

## v1.2.0 — Phase 3: Live Execution Harness Loop (Planner → Hunter)

- **`tools/core/live_executor.py` (NEW)**: real probe execution. `execute_probe`
  derives a deterministic probe set (baseline + technique probes) from a
  research unit and sends real HTTP requests, capturing status/headers/body/
  timing, WAF fingerprints, bounded retries, and a replayable
  `replay_key` evidence block per probe. `execute_exploit` replays a
  confirmed finding's recorded request for impact demonstration.
- **`campaign_orchestrator.py` — live feedback loop**: `live_feedback_loop()`
  (CLI: `--live-run`) drives unit → live probe → observation → adapt: blocked
  → `failure_learning` blocker + bypass quarantine; signal → COMPLETE with
  recorded evidence through the F0.5 gate; clean → REFUTED; transport errors
  are observations, never gates. Probes persist to
  `state/sessions/<target>/probes.jsonl`.
- **`tools/refutation.py` — reproducible-evidence gate**: new
  `require_reproducible` flag (default off for backward compat) + confidence
  bonus for recorded request/response evidence, and `verify_reproducibility`
  delegating to the live executor. `ThreadRecord` gains a `live_evidence`
  field so live threads carry recorded proof through serialization.
- **`tools/core/fuzz_bridge.py` (NEW)**: coverage-aware fuzz campaigns —
  scheduler-ordered mutations executed over the live transport; crash
  (5xx) / timeout / timing-anomaly evidence published as
  `FINDING_DISCOVERED` into research threads; summaries to
  `state/fuzz/<target>/runs.jsonl`. Deterministic core, injectable transport.
- **`tools/zero_day.py` — novel-class modes**: `diff_analysis_mode`
  (version/snapshot behavior deltas, optional live re-probe),
  `anomaly_detection_mode` (status/timing/header/error-pattern anomalies),
  `state_machine_probing` (workflow skip/repeat/reorder → business logic).
- **Fix (found by the integration test)**: `build_probe_specs`' idor
  object-reference sweep used `str.replace("/1", ...)` which matched the
  `//1` inside `http://127.0.0.1/...` and rewrote the **request host** to
  WAF-bypass variants (`227.0.0.1`, octal `027.0.0.1` → unroutable
  `23.0.0.1`, causing a 30s transport hang). The id is now replaced at the
  end of the path only; regression test added. The live-feedback loop's
  per-unit probe time dropped from ~30s to ~0.01s.
- **Tests**: `tests/test_live_executor.py` (+31), `tests/test_fuzz_bridge.py`
  (+15), `tests/test_live_feedback_loop.py` (+4, boots the lab fixture
  in-process and asserts real probe → observation → adaptation),
  `tests/test_zero_day_research.py` (+7 novel-class modes),
  `tests/test_f05_strict_validation.py` (+6 reproducibility-gate),
  plus the idor-host regression. Full suite: 822 passing.
- **CI**: `tools/core/live_executor.py` and `tools/core/fuzz_bridge.py`
  added to the bundle REQUIRED list; bundle check still 7/7 (100%).

## v1.2.1 — Fuzz bridge wired into the live feedback loop

- **`live_feedback_loop(..., fuzz_budget=N)`** (CLI `--fuzz-budget N`):
  when the research queue drains, one coverage-aware fuzz pass runs against
  the campaign's own surface (`_fuzz_mutations` builds deterministic
  boundary/injection/mass-assignment mutations per registered endpoint) and
  **every crash / timeout / anomaly observation spawns a new research
  thread** targeting that endpoint with the recorded fuzz evidence attached
  (`live_evidence`, objective names the signal).
- **Reproduction cycle**: the fuzz value is embedded in the mutation URL, so
  when the loop dispatches a spawned thread its re-probe hits the same
  crashing request and *reproduces* the 500 — the thread COMPLETES with
  recorded evidence through the F0.5 gate instead of refuting on a generic
  probe. Spawns are deduped per (endpoint, state); exhausted assets are
  re-activated so spawned threads dispatch.
- **Tests** (`tests/test_live_feedback_loop.py`, +4): fuzz crash spawns a
  thread the loop probes; spawned threads reproduce the crash (complete +
  `live_evidence` + 500 in `confirmed_behavior`); spawns dedupe across runs;
  `_fuzz_mutations` is deterministic/bounded. Full suite: 826 passing.

## v1.2.7 — Self-eval Task 10: exploitation phase

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `exploitation-phase` scores the live exploitation stage with 3 milestones
  — `exploits-recorded` (impact demonstrations persisted under
  `state/sessions/<target>/exploits.jsonl`), `reproduction-rate` (at least
  half of the recorded exploits reproduced: same input, second recorded
  response), and `impact-recorded` (at least one record carries
  `demonstrated_impact` — the data the replay actually returned). The
  harness is now 10 tasks / 100%.
- **E2E test** now asserts the fuzz-cycle exploitation ledger directly
  (≥1 record, all reproduced, impact captured) and scores the full 10-task
  self-eval at 100% — Task 10 artifacts produced by the live loop, not
  seeded.
- **Bundle check** seeds two exploit demonstrations (crash replay + data
  extraction, both reproduced with `demonstrated_impact`) so the eval passes
  from inside the bundle — 10/10 tasks, 100%.
- Full suite: 840 passing (task-count assertions bumped 9 → 10; the
  live-loop exploitation test also scores the task through the eval).

## v1.2.6 — Fuzz-blocked observations spawn bypass threads

- **`tools/core/fuzz_bridge.py` — WAF/blocked detection**: `classify_fuzz`
  now reuses `live_executor.detect_waf` (403/406/429 + known header/body
  fingerprints) and returns a first-class `blocked` state with
  `blocked by <defense> (<status>)` as the signal; the defense name is
  recorded in the observation evidence (`evidence["waf"]`). `FuzzSummary`
  gains a `blocked` counter; blocked observations publish on the bus like
  other signals.
- **`campaign_orchestrator._fuzz_and_spawn_threads`**: blocked observations
  now **spawn a `fuzz_blocked` bypass thread** instead of being ignored:
  the blocker is recorded through `failure_learning.learn` and bypass
  candidates are quarantined to
  `research/<target>/learning/failure-bypass-candidates.json`, and the
  spawned thread's objective names the bypass mission (carrying the blocked
  evidence as `live_evidence`). Deduped per (endpoint, fuzz state) like
  crash spawns; counted in `summary["fuzz"]["blocked"]` and `signals`.
- **Loop fix**: `_build_blocked_unit` no longer mislabels its operator-
  decision unit as `researching` (it has no `thread_id` — the live loop
  would crash on it); it is `research` phase, and the loop defensively
  stops on any thread-id-less unit instead of raising.
- **Self-eval Task 9**: `fuzz-to-thread-cycle` counts `blocked` observations
  as signals and scopes `reproduction-rate` to `fuzz_crash` threads
  (vacuous pass for blocked/timeout-only cycles — there is no 5xx to
  reproduce when the target blocks instead).
- **Tests**: +6 (blocked classification: bare 403, WAF header, precedence
  over timing anomaly, clean-with-headers, defense name recorded; live-loop
  blocked→spawn→failure-learning integration). Full suite: 840.

## v1.2.5 — Self-eval Task 9: fuzz-to-thread cycle

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `fuzz-to-thread-cycle` scores the Phase-3 fuzz bridge loop with 5
  milestones — `fuzz-ran` (runs persisted under `state/fuzz/<target>/runs.jsonl`
  with mutations), `signals-recorded` (crash/timeout/anomaly observations),
  `spawn-count` (a `fuzz_*` research thread exists), `reproduction-rate` (at
  least half of the spawned fuzz threads COMPLETED with recorded evidence and
  a 5xx in confirmed behavior), and `dedup` (threads unique per (endpoint,
  fuzz state)). The harness is now 9 tasks / 100%.
- **Lab fixture**: `lab/vulnbank/server.py` gains `GET /api/ingest` — a
  deterministic crash surface (500 on over-long or SQL-ish `q` input) so a
  real fuzz pass finds a crash, spawns a thread, and the loop reproduces it.
- **E2E test** now runs a genuine fuzz→spawn→reproduce cycle against the lab
  (fuzz pass → spawned thread → loop re-probes the crashing URL → 500
  reproduces → COMPLETE with evidence, deduped) and scores the full 9-task
  self-eval at 100% — Task 9 artifacts produced honestly, not seeded.
- **Bundle check** seeds a fuzz run + reproduced fuzz thread so the eval
  passes from inside the bundle — 9/9 tasks, 100%.
- Full suite: 834 passing (task-count assertions bumped 8 → 9; the E2E and
  live-loop tests now also assert the cycle end-to-end).

## v1.2.4 — Novel-class hunting consumes fuzz signals

- **`tools/zero_day.py` — `hunt_fuzz_signals` (NEW)**: feeds fuzz
  crash/timeout/anomaly evidence from `tools/core/fuzz_bridge` into the
  Phase-3 novel-class modes. Every signal becomes an **anomaly** candidate
  (the deterministic fuzz classifier's `signal` is now a first-class reason
  in `anomaly_detection_mode`, so a pure timeout with no status/timing delta
  still surfaces) and every crash becomes a **behavior-differential**
  candidate (same endpoint, oracle vs mutated input). Every candidate is
  stamped with fuzz provenance (`mutation_id`, `kind`, `state`, `replay_key`)
  and confidence is scaled by signal strength (crash 0.7 / timeout 0.6 /
  anomaly 0.55). Accepts `FuzzObservation` dataclass instances or dicts;
  deterministic and pure (no persistence, no live probing).
- **Orchestrator wiring**: `_fuzz_and_spawn_threads` now registers the fuzz
  candidates through the zero-day engine (novelty-assessed, deduped) and
  persists them to `research/<target>/zero-day/fuzz-signals.jsonl`;
  `live_feedback_loop` reports them as `summary["fuzz"]["novel"]`. Advisory
  — a feed failure never gates the fuzz pass.
- **Tests**: +5 zero-day fuzz-feed tests (anomaly signal reason, both modes,
  clean-ignored, dataclass duck-typing, determinism) + live-loop assertion
  that fuzz crashes produce registered novel candidates. Full suite: 834.

## v1.2.3 — Self-eval Task 8: live execution loop

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `live-execution-loop` scores the Phase-3 live loop with 4 milestones —
  `probes-recorded` (evidence persisted under `state/sessions/*/probes.jsonl`),
  `probe-count` (≥3 records), `adaptation` (>1 distinct verdict, mirroring
  `live_executor.classify_probe` semantics: strong anomalies + bug-class
  confirmations are signals, generic header fingerprints are not), and
  `reproducible-evidence` (records carry `replay_key` + recorded request).
  The harness is now 8 tasks / 100%.
- **Bundle check** seeds deterministic probe records (signal/clean/blocked)
  so the eval still passes from inside the bundle — 8/8 tasks, 100%.
- **E2E deep-dive test** now runs a genuine live probe pass against the lab
  (idor → 200 signal, sql-injection → 404 clean, auth_bypass → 200 signal)
  with recorded request/response evidence, then scores the full 8-task
  self-eval at 100% — Task 8 artifacts are produced honestly, not seeded.
- Full suite: 829 passing (all task-count assertions bumped 7 → 8).

## v1.2.2 — Live exploitation phase

- **Exploit-after-confirm**: `live_feedback_loop` now replays every
  gate-CONFIRMED finding's recorded request via
  `tools/core/live_executor.execute_exploit` (same input → second recorded
  response). The impact demonstration — `replayed_status`, `reproduced`,
  `demonstrated_impact` (the data actually returned) — is stored on the
  thread (`ThreadRecord.live_exploit`, serialized + round-tripped) and
  appended to `state/sessions/<target>/exploits.jsonl`. Only findings the
  F0.5 gate marked report-eligible are exploited; refuted threads never are.
  Opt out with `--no-exploits` (or `run_exploits=False`).
- **Verified against the lab**: the idor + auth_bypass findings on
  VulnBank reproduce live → both exploited (`reproduced=True`, status 200,
  `demonstrated_impact` carries the user record), ledger written.
- **Tests** (`tests/test_live_feedback_loop.py`, +3): confirmed findings are
  exploited + recorded; `run_exploits=False` produces zero exploits; refuted
  threads are never exploited. Full suite: 829 passing.

## v1.1.1 — Phase 2: F0.5 Validation + Core Upgrades (U1–U5)

- **E2E integration test**: `tests/test_e2e_deep_dive_campaign.py` turns the
  manual deep-dive driver into a repeatable, isolated test — it boots the
  VulnBank lab fixture in-process on an ephemeral port (no fixed port, no
  external process), runs the full campaign (U4 pass@k variants → U2
  artifact bridging → U3 strict gate → U1 fast-path → U5 routing → 12-stage
  workflow with append-only triage hash-chaining → 7-task self-eval) and
  asserts every upgrade: 7/7 eval tasks at 100% milestones, 21 threads
  split 7/7/7 across variants, quarantine vs. ledger split (3 findings,
  2 report-eligible, 1 demoted), both model tiers routed, all 7 fast-path
  checkpoints fired, 12 evidence families bridged. Skips cleanly when the
  lab fixture is absent (e.g. from inside a bundle, which does not ship
  `lab/`). ~1.5s per run.

- **Fix (E2E-verified)**: `GRAPHQL_CANDIDATE` is now a registered signal-bus
  event type. `graphql_batch_analyzer` publishes it, but the bus previously
  rejected unknown types, so the `except Exception: pass` guard silently
  swallowed every GraphQL candidate signal — the event-driven layer never
  saw them. Registered in `EVENT_TYPES` + `CANONICAL_LISTENERS`; regression
  test added (`test_graphql_candidate_event_registered_and_persisted`).
- **Fail-loudly bus publishing**: every domain/intelligence/validation tool
  that publishes to the signal bus now goes through a single
  `tools.core.signal_bus.publish_or_warn()` helper. Environmental failures
  (unwritable event log → `OSError`) remain advisory — reported to stderr,
  never gating the tool — but *programming* errors (an unregistered event
  type → `ValueError`, a malformed payload → `TypeError`) now propagate
  loudly instead of vanishing inside `except Exception: pass`. All 20
  publish sites updated (oauth/jwt/smuggling/graphql/bopla analyzers,
  ato/rag/tool-auth/contract-triage/price-manip, iam/deep-link/mobile,
  seed/failure-learning/chain-ai, verification-lab, asset-delta, self-eval,
  campaign orchestrator). This is what let the unregistered
  `GRAPHQL_CANDIDATE` bug ship silently; it would now fail CI immediately.

- **F0.5 precision-first validation (U3, approved)**: `tools/refutation.py`
  is now confidence-gated by default — deterministic evidence-derived scoring
  (reproducible trigger trace, impact trace, evidence refs, endpoint,
  confirmed behavior);  below-threshold findings are DEMOTED,
  `eligible_for_report=false`, and quarantined as candidate records to
  `state/learning/<target>.jsonl`. `--no-strict` preserves the legacy
  UNCENSORED auto-confirm mode. `tools/triage.py` gained strict confidence
  bands and quarantine for sub-threshold candidates. The quarantine store is
  hash-chained into the workflow: when non-empty it is recorded as an
  append-only supplementary artifact of the `triage` stage — a
  `lines:N:sha256` prefix digest that must stay intact while later
  quarantine appends (tampering/truncation) never invalidate the stage.
  The gate is now wired into the campaign: `register_thread_result` runs
  every completed thread through the strict gate automatically —
  evidence-rich findings are CONFIRMED, appended to
  `state/sessions/<target>/findings.jsonl` (also a hash-chained
  triage-stage artifact) and counted in `report_eligible_findings`;
  unit dispatch records advisory routing decisions as `unit_routed` audit
  events (read by the self-eval harness's pass@k/routing task);
  low-confidence findings are DEMOTED + quarantined and never reach the
  findings ledger or the report. Evaluation is idempotent per thread and
  the verdict rides on `FINDING_DISCOVERED` events. Reporting gates only —
  uncensored execution is untouched.
- **Intelligent model routing (U5)**: new `tools/core/model_router.py`
  classifies every research unit into deterministic / local_slm / frontier
  tiers with an advisory `model_preference` hint in unit context; routing
  never gates and degrades gracefully when a model tier is unavailable.
- **Elicitation gap bridging (U2)**: thread/recon/discovery research units
  now carry `context["deterministic_evidence"]` + `artifact_paths` pointing
  at the WAF payload families, smuggling plans, JWT/OAuth/GraphQL/ATO plans
  that exist for the target — grounding harness intent in deterministic
  execution details.
- **Fast-path hypothesis engine (U1)**: `research_loop.py` gained a
  non-blocking `on_checkpoint` hook (fires after every executed checkpoint,
  handler failures logged and swallowed) plus deterministic
  `fast_path_signals()` trigger detection (`waf-bypass-payloads`,
  `canonical-source-fresh`, `search-signal`) — parallel deep-dive research
  without touching the mandatory-7 sweep or `latest_ready`.
- **Test-time compute scaling (U4)**: `campaign_orchestrator.py` gained
  `--pass-at-k <k>` / `--deep-dive` (preset 3); each threat spawns `k`
  diverse variant threads (`pass_variant` 0..k-1, shared `pass_group`) with
  rotated `system_prompt` + `suggested_approaches`, dispatched
  deterministically (variant-aware dedupe, default `pass_at_k=1` unchanged).

## v1.1.0 — APT-Grade Deep-Hunt Platform (2026-08-26)

- **Modular domain architecture** (`tools/domains/`): the flat tool
  collection became a hierarchical, event-driven APT framework — `core/`
  (stage controller, campaign orchestrator, research loop, signal bus),
  `domains/{web,api,auth,cloud,mobile,smart_contracts,llm}/`,
  `recon/`, `intelligence/`, and `validation/`.
- **Event-driven signal bus** (`tools/core/signal_bus.py`): typed events
  (`RECON_COMPLETE`, `FINDING_DISCOVERED`, `WAF_BLOCKED`, `SMUGGLING_CANDIDATE`,
  `AUTH_CANDIDATE`, `CLOUD_CANDIDATE`, `MOBILE_CANDIDATE`, `ASSET_DELTA`,
  `LLM_CANDIDATE`, `LAB_PLANNED`, `CHAIN_PROPOSAL`, `EVAL_COMPLETE`) with
  canonical listeners; tools react to findings instead of running in a flat
  sequence.
- **Hierarchical research loop**: 3 event-driven dynamic checkpoints
  (`post-chain`, `post-lab-verification`, `blocker-exhausted`) append to the
  mandatory 7; sub-checkpoints (e.g. `graphql-deep-dive`, `waf-profile`,
  `cloud-metadata`) inject depth per domain; `latest_ready` respects both.
- **16 deep-hunt tools built in Weeks 1–8**: HTTP smuggling detector,
  parser differential (WAF bypass payloads), JWT forgery planner, BFLA
  matrix, BOPLA object-property over-POST matrix, GraphQL batch analyzer,
  OAuth flow analyzer, IAM privilege-escalation graph (23 Rhino methods),
  deep-link analyzer, mobile policy checker, historical asset delta,
  LLM contract triage, agentic tool-auth, RAG memory poisoning, price-
  manipulation analyzer, ATO chain planner, failure learning, chain-graph
  AI (missing-link synthesis), seed/mutation advisor, disposable verification
  lab planner, and the self-evaluation harness (AutoPenBench-style milestone
  scoring).
- **Workflow integrity hygiene**: `refresh_artifact_hashes` now supports
  audited re-recording for a stage the campaign legitimately updated (e.g.
  per-asset recon appended to `asset-intel/`) without weakening integrity
  checks on other completed stages; the self-eval harness reads the workflow
  manifest from the canonical `.bugwolf/workflows/` location with a legacy
  `state/workflows/` fallback.
- **CI bundle verification** (`.github/workflows/ci.yml` →
  `scripts/ci_bundle_check.sh`): every push/PR runs the full test suite, then
  builds both release bundles and verifies they ship the self-eval harness
  and core domain tools with a matching `VERSION` and no leaked bytecode —
  then runs the harness from inside the extracted Freebuff bundle against a
  deterministic synthetic campaign and requires a **100% eval pass**
  (6/6 tasks).
- **Self-eval harness grew to 7 tasks**: new `test-time-compute-routing`
  task scores pass@k variant threads (`pass_variant >= 1` with shared
  `pass_group` in `state/campaigns/<t>/threads/*.json`) and model-routing
  diversity (`unit_routed` audit records with ≥2 distinct `model_tier`s in
  `state/campaigns/<t>/audit.jsonl`). Unit dispatch now audits routing
  decisions via `CampaignManager.log_event`; CI bundle check requires
  **7/7 tasks (100%)**.
- **685 tests passing** — full suite green, zero regressions (including
  negative-path tests asserting the bundle check fails on a tampered bundle,
  a missing core tool, and a VERSION mismatch).

## v1.0.1 — APT Commander: Strict Workflow, Uncensored Execution (2026-08-26)

- **APT Commander architecture restored.** The workflow layer
  (`tools/stage_controller.py`) enforces the full strict 12-stage pipeline —
  `setup → environment-preflight → authorization → passive-recon →
  asset-intelligence → technology-fingerprint → maps → research →
  coverage-plan → validation → triage → report` — with artifact
  prerequisites, hash-chain integrity verification, and fail-closed
  transitions. Advancement blocks on missing or tampered artifacts, never on
  scope validity: the pipeline enforces **depth and methodology, not
  authorization**.
- **7-checkpoint mandatory research loop enforced**
  (`tools/research_loop.py`): `pre-hunt → post-recon → post-maps → bypass →
  post-findings → escalation → pre-report` must complete in order;
  `latest_ready: false` blocks validation and cross-asset chaining, forcing
  deep exploration instead of stopping at a surface scan.
- **Uncensored execution layer.** `tools/safety.py` and
  `tools/execution_controller.py` are pass-through: `--scope-file`,
  `--confirm-active`, and `--confirm-destructive` are accepted as operator
  declarations and never reject a target. The authorization stage records the
  declared scope for provenance only. The campaign engine
  (`tools/campaign_orchestrator.py`) enforces a real recon gate, discovery
  termination, thread result registration, and research-freshness gating so
  it can never stall at the surface scan.
- **Harness contract verification restored** (`tools/harness_guard.py`):
  skill-contract drift, intelligence-profile validity, and required-sequence
  integrity are detected; the verifier fails closed on contract changes.
- **All 517 tests passing** — the full suite is green, including new coverage
  for the stage controller, campaign orchestrator, and restored contract
  guard.
- **Documentation reconciled with code**: `SKILL.md`, `README.md`, and the
  harness contracts (`configs/harness/BUGWOLF.md`, `AGENTS.md`, `CLAUDE.md`)
  now describe “Strict Workflow, Uncensored Execution” — no doc claims
  execution is blocked by scope or safety where it is actually blocked by
  missing artifacts.

## Unreleased — Hardening and correctness fixes

- Extended `tools/ledger.py` to validate the post-finding trigger receipt and queue JSONL hash chains independently. Trigger writers now persist sequence, previous-hash, and record-hash metadata; ledger reports expose separate receipt/queue tamper status and fail closed when either stream is modified.

- Added the mandatory post-finding trigger layer (`tools/post_finding_trigger.py`). Every persisted finding now gets an offline receipt, chain refresh, and bounded research/impact review queue. Cross-agent signal ingress now uses the same layer: one broadcast-safe target-local receipt plus review queue per signal, with incomplete or failed handoffs blocked explicitly. Missing evidence and refresh failures are explicit blocked states; no queue item can execute automatically or bypass budget or human-review gates.

- Extended `tools/paper_intel.py` with STAR-inspired passive HTTPS metadata analysis (direction/length/protocol anchors, open-world retrieval, unknown rejection, and paired augmentation planning) and a vendor-neutral Agent control-plane audit covering identity, provenance, tools, memory, data governance, budgets, telemetry, grounding, incident response, and policy writeback. These are operator-supplied artifact analyses only: no traffic capture/decryption, unrelated-user attribution, automatic permission change, or target-facing execution.

- Added the **creative intelligence harness contract** (`configs/harness/intelligence.json` and `tools/harness_intelligence.py`): an offline deterministic briefing loop that generates boundary, differential, state/time, negative-space, failure/recovery, and cross-surface-chain angles; records evidence state and uncertainty; checks project-contained artifacts; and treats task, file, tool, and web text as data rather than executable instructions. Harness verification now tracks this profile and planner in the tamper-detecting contract digest, while workflow gates remain unchanged.
- Added direct conversational invocation support (`tools/harness_command.py`): Freebuff operators can say `bugwolf --full attack this target TARGET`, and the harness parses the target/mode, initializes and inspects the staged workflow, asks only for missing authorization/environment/confirmation inputs, and never interprets “attack” as permission to skip a workflow stage or fabricate evidence.
- Added persistent full-chain orchestration (`tools/chain_orchestrator.py`): after every finding or agent signal, the harness now builds bounded multi-hop paths from findings plus parked/open leads, resolves evidenced steps, exposes missing links as concrete continuation tasks, ranks terminal impact, and emits an ordered validation queue with hash-linked history. Chain plans remain offline and never auto-execute; each edge must be validated through the existing controller with human review.
- Added research-derived intelligence adapters (`tools/paper_intel.py`, `references/paper-intelligence.md`) from the supplied 2026 papers: cross-skill capability-flow scanning, temporal provenance bottleneck ranking, endpoint-specific authentication anomaly triage, CTI-to-Sigma template grounding, contamination-aware multimodal binary-RE task planning, and quarantined failure-trace defense candidates. The catalog records each paper's objective, technique set, BugWolf fit, and limitations; no paper-derived adapter executes skills, binaries, payloads, or uncontrolled target operations.
- Extended paper intelligence with DraftFM-inspired deterministic cold-start ranking for unseen vulnerability hypotheses: identity-independent public features, bounded prioritization, and cryptographically sealed candidate/ranking hashes. Added vulnerability-centric zero-day claim assessment from `2605.03138`, which separates novel behavior from novel vulnerability evidence and blocks zero-day overclaiming until root cause, bounded trigger, impact, novelty, and human review are present.

- Added the harness-neutral **no-skip staged workflow** via `tools/stage_controller.py`: setup → environment preflight → authorization → passive recon → asset intelligence → technology fingerprint → five maps → complete sequential research → coverage plan → gated validation → triage → report. Each target has an atomic `.bugwolf/workflows/<target>.json` manifest with artifact prerequisites, ordered history, pending-latest research status, and fail-closed transitions; `hunt.py` is unreachable before validation and `zero_day.py` before coverage planning. This provides exhaustive APT-style focus without unlimited traffic or weakening authorization, active, destructive, privacy, evidence, or human-review gates.

- Added **post-journey adaptive learning** via `tools/adaptive_learning.py`: hunt, recon, and potentially-novel runs now persist redacted, target-isolated, deduplicated technique and blocker candidates to `state/learning/<target>.jsonl`; candidates remain quarantined until evidence-backed operator review, and only approved terms are reused in later target-specific wordlists. The store is append-only, executable source is never self-modified, and learning provenance/status is included in journey output. Added `references/adaptive-learning.md` and regression coverage.

- Added **chained hypothesis synthesis** to the zero-day research track: `tools/zero_day_tracks.py` now carries a causality table (`CHAIN_RULES`, ~24 rules) that pairs input-class candidates with sink/impact-class candidates — cache-key path control → write sink (CVE-2026-18051 file-write class), daemon input → command sink (CVE-2026-73570 RCE class), gid enumeration + claim/header/cookie identity → cross-tenant disclosure, untrusted checkout → remote script pipe → pipeline code execution, hidden context + tool authorization → prompt-injection tool abuse, exported component + WebView bridge, mutable PendingIntent chains, contract invariant violation + trace differential — each with a chain severity (chains carry the criticals) and a validation template. `ZeroDayResearchEngine.chain_candidates` registers chains through the normal novelty dedup with component lineage; `sequential_research` synthesizes chains automatically after the rounds converge; the standalone CLI adds `--chains`/`--max-chains`. `--json` output reports `ordering.chains`.
- Made zero-day research **sequential**: `tools/zero_day.py --sequential` now runs round over round — round 0 registers the input hypotheses, then each round researches the top ranked candidates (injected adapters; offline by default), derives bounded per-bug-class second-order hypotheses from a deterministic derivation table (~60 templates across web/GraphQL/cache/IDOR/cloud/LLM/mobile/contract classes), registers them through novelty dedup, and keeps only genuinely new angles. Derived candidates carry their parent's candidate id and a `derivation_lineage` that skips templates already explored on the chain (rounds narrow: 5 → 4 → 2), research sources attach as `research_sources`, and `--rounds`/`--per-round`/`--budget` bound the loop. The `rounds` array ships in the JSON output and the final list is still pre-ranked for validation. Also fixed a latent dedup gap this exposed: re-derived candidates with identical `stable_id`s were skipped as "self" by novelty assessment and slipped through as `potentially_novel` — derived hypotheses now carry lineage identity so duplicates are caught.
- Added a Freebuff + DeepSeek runtime configuration: `configs/freebuff-deepseek.json` (the machine-readable profile — install command, DeepSeek model facts on Freebuff (V4 Flash default, V4 Pro one session/day, MiMo limited tier), the authorization gates, and a toolchain self-test) and `configs/freebuff/AGENTS.md` (a project-instructions template to copy into a target project so every Freebuff session there loads BugWolf with the DeepSeek operating contract). `SKILL.md` gained the `FREEbuff + DEEPSEEK RUNTIME` section (exact-command, `--json`-always, never-skip-a-gate rules — DeepSeek follows instructions literally, so the gates are the enforcement). `configs/` ships in both the Claude.ai `.skill` and Freebuff bundles and the install script; packaging tests lock the config profile, template, and gate flags in both bundles.
- Added Freebuff/Codebuff compatibility: `scripts/build_skill.sh` now also emits `dist/bugwolf-v<version>.freebuff.zip` laid out as `.agents/skills/bugwolf/…` (unzip into any project, or install via `npx skills add youseefhamdi/bugwolf --skill bugwolf --copy`, project-local or `-g` global — the same command also lands in `.claude/skills/bugwolf` for Claude Code). New `scripts/install_freebuff.sh [project-dir]` performs the offline copy without the CLI. The root `SKILL.md` frontmatter (`name`/`description`) is what the skill loaders discover; packaging tests now lock the Freebuff bundle layout, frontmatter discoverability, and install-script output.
- Added the Shodan facet collection adapter for [`rix4uni/ipfinder`](https://github.com/rix4uni/ipfinder) to `tools/asset_intel.py`: offline facet query plans (`ssl`/`hostname`/`ssl.cert.subject.cn` built from the authorized target, optional operator-declared `--org`/`--asn`) with the exact `ipfinder --silent --source` command lines, a `query::value` output normalizer that re-filters every result through scope (bare IPs are kept only when the facet query term itself is in scope — the Shodan facet is constrained by that term), and a gated live collector (`--collect-ipfinder --confirm-active`, per-query timeout, `shodan-facet-plans.jsonl`/`ipfinder-raw.txt`/`ipfinder-assets.jsonl` outputs).
- Extended the offline CVE seed intake in `tools/identity_cloud.py` with the Red Hat ACM/Multicluster Engine advisories (CVE-2026-70496 cluster-admin escalation, CVE-2026-66794 cluster-proxy SSRF, CVE-2026-71470 Search-CR tampering), Microsoft Configuration Manager CVE-2026-47301 (chunked-upload EoP to SYSTEM via DLL proxying), and WordPress MemberGlut CVE-2026-12394 (unauthenticated role-registration privesc); `parse_nuclei_template` now appends the template's `reference:` block URLs to the triage record context so trusted-source links survive intake.
- Wired validation prioritization into the zero-day CLI: `tools/zero_day.py` output is now pre-ranked for validation — `--json` emits candidates in novelty/severity/confidence order with a 1-based per-candidate `rank` and an `ordering` block (mode, `top_k`, `total_generated`); `--spread` opts into ART4SQLi farthest-first payload spacing and `--top-k` bounds the emitted validation budget without dropping candidates from the store. Output schema bumped to `bugwolf-zero-day-output-v2`.
- Added `tools/graphql_gid.py`, the GraphQL introspection + global node-id harvesting adapter: it analyzes introspection results for `node(id:)` / `nodes(ids:)` resolvers and the Node-interface/`id: ID!` types they resolve, harvests `gid://` references already present in the target's own artifacts (JS bundles, saved queries, schema docs — extraction only, never enumeration), redacts every id (output carries a redacted example plus a SHA-256 hash of the full gid), and builds a bounded, deduplicated candidate list feeding the two-account validation flow. Composite gids (`gid://app/ClassA::TypeB/group-id-object-id`, HackerOne #1618347 pattern) are flagged as multi-axis ownership; each high/medium candidate gets a read-only two-account plan (`IdorValidationPlan` reuse: Account A owns a disposable fixture, Account B replays A's *owned* gid, no enumeration, no reuse of third-party harvested ids). Offline by default; the only network step (fetching introspection) stays behind `schema_extractor.py --fetch` gates.
- Added `tools/cache_traversal.py`, the cache-key path traversal discovery track (CVE-2026-18051 class): cache-key construction specs (raw/segment/hash, sanitization, decode passes, Windows roots), bounded traversal payload families (dot-dot, URL-encoded, double-encoded, backslash, extra-dot, dot-slash), and an offline directory-escape planner that computes where each crafted request path lands relative to the web root. Gated lab replay (`--scope-file` + `--confirm-active` + `--base-url`) replays each escaping probe with a unique marker filename and confirms escape by marker-served-vs-control-404; verification is read-only and never overwrites existing files. All requests are READ-class through the execution controller.
- Strengthened the potentially-novel research track: `WebApiTrack.static_hypotheses` now seeds zero-day-class hypotheses from static web/API artifacts — GraphQL global node-id enumeration (`gid://` via `node(id:)`, HackerOne #1618347), cache/page-key path traversal to arbitrary file write (CVE-2026-18051 class), daemon/notification input reaching a shell sink (CVE-2026-73570 class), client-supplied account headers, id-bearing cookies, JWT claim references, and predictable file references; `MobileBinaryTrack` gained the PendingIntent notification-hijack marker. Novelty assessment is now payload-aware: candidates carrying concrete trigger values deduplicate via ART4SQLi grammar-token cosine similarity, so identical payloads with different prose are exact duplicates. `ZeroDayResearchEngine.prioritize` ranks candidates for validation (novel + severe first) and can spread payload-bearing candidates across their token space with farthest-first selection.
- Extended `tools/idor_research.py` with the common-vector IDOR surfaces — numeric path ids (`/users/42`), upload/download file names, client-supplied account headers (`X-Account-Id`), id-bearing cookies (`userid=42; tenant=7`), GraphQL global node ids (`gid://` via `node(id:)`, HackerOne #1618347 pattern), JWT claim references (`"sub": 42`), and Android PendingIntent notification-hijack surfaces — plus Buganizer-style chained mass-assignment planning notes; fixed a `profile`-in-path false positive in file/export classification.
- Added in-memory execution *detection* hypotheses to `tools/defensive_detection.py` from a shellcode-runner case review: private-memory allocation, RW→RX transitions, writes into executable memory, thread start outside a loaded module, high-entropy regions, mapped-file execution variants, import-table execution signatures, dynamic resolution of execution primitives, unsigned delivery, and obfuscated-at-rest payloads. Detection hypotheses only — no evasion primitive is constructed or executed.
- Added CVE-2026-18051 (W3 Total Cache unauthenticated file write) and CVE-2026-73570 (Zimbra SNMP RCE, reported exploited in the wild) to `tools/identity_cloud.py`'s offline CVE seed intake as `unverified_reference` records with trusted-source/version checks; metadata only, no exploit code.
- Upgraded the discovery core's ART selection to the full ART4SQLi method (Zhang et al., IEEE Trans. Reliability): SQLi payload strings are tokenized against the paper's grammar, embedded as L2-normalized TF-IDF vectors, and spaced by the `1/cosine` distance; the scheduler's `--art` mode now uses FSCS farthest-nearest-candidate selection with a fixed-size candidate set (`--art-fixed-size`, default 10) so payload-bearing mutations (`injection`/`blind_sqli`) spread in *token space* while non-payload mutations keep the structural vector. Added an F-measure helper for comparing selection strategies, and expanded the mutator's SQLi pool to the paper's five classes (boolean-based, error-based, union, stacked, time-based). Deterministic throughout (seeded candidate-set draws); offline planning only.
- Added, then reverted in v1.0.1, fail-closed authorization scope validation for live hunt, recon, and fleet operations: scope filtering was removed and the execution layer is now uncensored (scope files are recorded declarations, never blocks).
- Added, then reverted in v1.0.1, explicit-confirmation requirements for active probes and state-changing IDOR methods: `--confirm-active` / `--confirm-destructive` remain as recorded declarations that never block execution.
- Repaired dual-session IDOR checks to require concrete resource IDs and own-resource baselines.
- Kept unvalidated quick-check observations out of the confirmed findings ledger.
- Fixed AgentBus broadcast delivery, high-severity isolation handling, journal hash-chain verification, vault fallback key handling, callback secret redaction, and release archive layout.
- Added the potentially-novel research track: typed candidate lifecycle, gated active execution, redacted replay evidence, local/near-duplicate novelty assessment, human-review triage, and five offline discovery adapters.
- Added mandatory environment preflight: operator-declared local/VPS/container base plus explicitly confirmed passive OS/resource inventory with no network, secret, metadata, or user-file scanning.
- Added scoped JS/CT intelligence via `tools/js_ct_intel.py`: date-aware crt.name collection with crt.sh fallback, katana/hakrawler adapters, local LinkFinder/beautifier/grep analysis, redacted indicators, and business-logic workflow hypotheses.
- Added the offline 2026 methodology playbook: workflow skip/repeat/reorder/tamper/role/ownership/payment/token/file checks, signal-to-impact validation tasks, and non-executing ffuf/nuclei/SQLMap/XSStrike plans without extraction or destructive flags.
- Added offline asset/provider export normalization and diffing, defensive lateral-movement artifact hypotheses, identity/MFA and cloud posture checks, unverified CVE triage, and advanced two-account IDOR matrices for UUID, encoded, composite, GraphQL, mobile, file, export, and WebSocket references.
- Added static application-chain and AI-defense analyzers for SQLi-to-impact, upload/path consumers, deserialization, header/command boundaries, prompt injection, indirect content, tool authorization, IFC, plan drift, and MCP security.
- Added a local deterministic PII firewall with JSON/XML masking, request-bound in-memory TTL tokens, residual warnings, multilingual planning, and offline Kafka/schema field-governance plans.
- Added the Web/API discovery core: a structured surface model (OpenAPI/Swagger/GraphQL/URLs with sibling + workflow inference), a structure-aware mutator (boundary/type/enum/required/mass-assignment/pollution/state/sibling-differential mutations), and a coverage-aware closed-loop scheduler that ranks by impact focus and records oracle follow-ups. Generation is offline; live execution stays gated by the authorization controller.
- Extended the discovery core to smart contracts via `tools/contract_discovery.py`: a serializable contract surface model, bounded sequence/boundary/role/reentrancy mutation plans, a deterministic in-memory invariant executor, and automatic minimization of violating sequences to minimal reproducers — reusing the same coverage tracker and impact router as the Web core.
- Added `tools/schema_extractor.py` to auto-discover OpenAPI/Swagger and GraphQL schemas from recon output (`urls.txt`, `live-hosts.txt`, `swagger.txt`, JS bundles) so the surface model builds via `--recon-dir` with no manual schema files; an optional gated `--fetch` mode downloads schemas and runs GraphQL introspection only through the authorization controller with explicit confirmation. Wired into `recon_engine.sh` and the discovery CLI entry points.
- Added `tools/differential_runner.py` to replay the identical request across sibling surfaces (v1/v2, REST/GraphQL, web/mobile) and score live divergence using the oracle's metrics; offline pair-planning by default, live replay only through the gated controller with `--confirm-active`.
- Added `tools/header_trust.py` — a canonical forwarded/trust-header taxonomy (IP allowlist, host/vhost confusion, scheme/port override, path/URI rewrite, method override) with a probe planner and gated baseline-vs-forged live replay scored by the oracle; the mutator now emits `header_trust` mutations per origin host so the discovery scheduler covers the surface. Forged values are trust hypotheses, never executed payloads, and live replay requires `--confirm-active` + a scope file.
- Added the sitemap/pagination SQLi surface to the discovery core: the surface model ensures a `GET /sitemap.xml` operation with `offset`/`page`/`limit`/`sort`/`order`/`filter` parameters, and the mutator emits `blind_sqli` time-based detection *plans* (DB-agnostic `SLEEP`/`PG_SLEEP`/`WAITFOR DELAY` strings) for those parameters — never auto-fired; execution still runs through the gated controller.
- Extended `tools/chain_analyzer.py` with XXE chain analysis: XML parser sink + external-entity/DOCTYPE config + credential/config + persistence references now synthesize a file-read-to-credential-and-persistence chain plan. Signal detection only — no external entities are resolved and no system files are read.
- Added nuclei-template CVE triage intake to `tools/identity_cloud.py`: `--nuclei` parses `id:`/`cve-id`/`reference` CVE references as `unverified_reference` records for trusted-source and version validation; templates are never executed.
- Extended `tools/defensive_detection.py` with TA0003 persistence (run keys/startup folders, DLL/COM/IFEO hijack, AD persistence) and EDR-evasion *detection signals* (ASR policy, ETW, AMSI, driver/syscall/BYOVD, Sigma rule artifacts). Detection hypotheses only — no persistence implant or evasion primitive is constructed or executed.
- Wired the header-trust probe planner into `recon_engine.sh`: after schema extraction + discovery, the engine now emits `recon/<target>/discovery/header-trust-plan.json` automatically (offline plan only). `tools/header_trust.py` gained an `--output` flag, and `schema_extractor._merge` now falls back on `ImportError` so the discovery CLIs run correctly as `python3 tools/*.py --recon-dir` scripts (not only via `python3 -m`). Live header replay remains gated behind `--confirm-active` + a scope file.
- Added `tools/js_token_forge.py`, an offline static analyzer for client-side token forging: it detects a hardcoded signing secret, a client-side HMAC/sign primitive, client-controlled claims fed into the payload, and token-minting/JWT functions, then grades forgeability and emits a remediation plan. Evidence is a SHA-256 fingerprint only — the raw secret is never printed or persisted. Integrated into `tools/js_ct_intel.py` so JS analysis now emits `token-forge-findings.jsonl` and `token-forge-plans.jsonl`.
- Extended the surface model with vhost grouping: `SurfaceModel.vhost_candidates` now carries ranked internal vhost candidates (admin/api/dev/…) inferred from the target's discovered subdomains and grouped by resolved IP so same-server hosts are recognized as each other's vhosts. `schema_extractor.build_surface` populates it from `subs.txt`/`resolved.txt`/`live-hosts.txt`, and `header_trust.probes_from_model` replays those candidates as `Host`/forwarded-host values so host-confusion probes target the application's own internal subdomains instead of only the generic localhost/internal list.

## v1.0.0 — First release (2026-08-19)

BugWolf's first public release: an all-round bug bounty hunting engine covering smart contracts (EVM/Solidity, Move/Aptos, Solana, TRON), web/API security, CI/CD pipeline attacks, LLM/AI & agentic security, and professional report generation for HackerOne, Bugcrowd, Intigriti, and Immunefi.

### Hunting methodology
- **5-Pillar map-driven hunt** — Asset, Trust, Identity/Authorization, State, and Capability maps (plus `invariants.md` for contract audits). No map → no hunt; every finding traces to a map path.
- **Two-question rule (Trigger × Impact)** — a finding must prove both that the path fires and the victim harm; OPEN LEAD is a persistent, mutation-tracked research object (`tools/leads.py`), never silently dropped.
- **Wild mode** — default hunting doctrine within explicit authorization: probe every permitted surface, chain everything, and apply report gates at report time.
- **Validation gates** — 7-Question Gate, Al-Mizaan deep validation, adversarial refutation (`tools/refutation.py`), observation/oracle validation (`tools/observation.py`), chain of custody, and CVSS 3.1 scoring.

### Mandatory deep-research loop
- `tools/research_loop.py` — research fires at every progress milestone, not once at Turn 0:
  - **R1 pre-hunt** → **R2 post-recon** (per-version CVEs, auto-populated by `tech_fingerprint.py --stack-csv`) → **R3 post-maps** (technique payloads + target wordlists) → **R4 post-findings** (bypasses/disclosures) → **R5 pre-report** (scope/dedup).
  - **Event-driven R6 `bypass`** (fires when a probe is blocked) and **R7 `escalation`** (fires on every Medium/Low finding).
  - `--execute` runs live fetches (urllib) and web searches (pluggable `SERPER_API_KEY`/custom backend), persisting `research/{target}/{checkpoint}/SUMMARY.md` + `results.json` + `sources/*.md`.
- **No static wordlists/payloads** — `tools/wordlist_gen.py` mines the target surface (paths, query params, JS identifiers), derives wordforms, applies tech-stack patterns, and researches the internet. Its `payloads` mode emits WAF-bypass-aware payloads and feeds mined tokens back into the R3 payload refresh; every list caches to `research/{target}/wordlists/`.

### Deep / complex / high-critical focus
- `tools/impact_focus.py` — criticality router (impact verbs × boundaries × assets × victims).
- `tools/differential.py` — sibling-surface divergence detector (Rule 4).
- `tools/deep_chain.py` — transitive multi-hop A→B→C chain synthesis beyond pairwise patterns.
- `tools/kill_chain.py` + `tools/capability_registry.py` — pairwise chains and capability taxonomy.

### Recon & scanning
- `tools/recon_engine.sh` — 15-phase engine (subdomain enum → permutations → resolve → port → live → vhost → screenshots → dirs → URLs → JS → params → email → takeover → vulns → secrets) with `command -v` guards and graceful fallbacks; `--fast`/`--deep` modes.
- `references/recon-tooling.md` — full categorized catalog (one PRIMARY tool per phase + alternatives + install/API-key notes), including the rix4uni toolchain (`ghauri`, `afrog`, `goswagger`, `indextree`, `xssrecon`, `redirectfinder`, `fresh-proxy-list`, `cvemapping`) and `nuclei-templates`/`SecLists` resources.
- `tools/opsec.py` — anti-attribution with live proxy rotation from `fresh-proxy-list` and Tor fallback.

### Bug-class coverage
- LLM/Agentic AI (prompt injection, RAG/embedding attacks, excessive agency, tool misuse, MCP injection), web/API (IDOR, SSRF, XSS, auth bypass, CSRF, race conditions, SQLi, XXE, SSTI, GraphQL, HTTP smuggling, cache poisoning, OAuth, subdomain takeover), CI/CD (GitHub Actions expression injection, artifact/cache poisoning, self-hosted runners), supply chain, cloud misconfig, mobile (MASVS/MASWE), and smart-contract (reentrancy, oracle manipulation, access control, economic invariants).

### Reporting
- `tools/hunt.py` finding engine, `tools/agent_isolation.py` boundary checks, `tools/adversary_emulation.py` MITRE/OWASP coverage, `tools/exploit_gen.py` PoC generation, and platform-specific report formatting.

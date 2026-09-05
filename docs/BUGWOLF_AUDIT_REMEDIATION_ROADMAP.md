# BugWolf Architecture Audit & Remediation Roadmap

> **Purpose:** Consolidate the BugWolf architecture map, confirmed audit observations, capability gaps, open loops, workflow risks, and the implementation roadmap into one operational document.
>
> **Scope:** BugWolf repository architecture, orchestration, runtime contracts, scope and safety boundaries, capability routing, research/novelty pipeline, evidence, persistence, reporting, hooks, MCP integration, tests, and release workflow.
>
> **Assessment posture:** This document is evidence-based. It distinguishes confirmed implementation defects from architectural risks, capability gaps, and items that require additional runtime verification. It does not claim that BugWolf can guarantee discovery of a zero-day. “Zero-day readiness” means the ability to generate, test, reproduce, differentiate, and responsibly review potentially novel hypotheses.

---

## 1. Executive summary

BugWolf has a broad and unusually ambitious security-research surface. It includes:

- staged mission intake and task scheduling;
- scope, preflight, sandbox, and operator-control mechanisms;
- HTTP/1.1, HTTP/2, replay, mutation, browser, OAST, race, and protocol tooling;
- web/API, smart-contract, cloud/CI, mobile, LLM/agent, and cross-domain lanes;
- an Understanding Layer with U1–U9 stages;
- candidate lifecycle, novelty, evidence, reproducibility, chain, and report concepts;
- multi-agent/team dispatch and model routing;
- hooks, MCP, command prompts, and release/package checks;
- deterministic fixtures and a substantial test suite.

The primary weakness is **integration consistency**, not feature count. Several layers can make independent decisions about scope, execution, budget, task completion, state, evidence, and reporting. This creates a risk that BugWolf may produce a technically sophisticated report whose execution provenance is incomplete, whose capability was not actually exercised, or whose safety and lifecycle assumptions differed between entry points.

### Highest-priority remediation themes

1. Establish one canonical execution authority.
2. Establish one canonical scope and policy authority.
3. Make preflight, authorization, budget, cancellation, and evidence gates hard runtime invariants.
4. Make task results schema-validated and mission-scoped.
5. Close domain-routing gaps so accepted capabilities cannot silently become no-op lanes.
6. Require real evidence artifacts before promotion to confirmed findings.
7. Unify persistence, locking, resume, and corruption-recovery semantics.
8. Complete the proof/benchmark layer and measure detection, false positives, cost, and assumption-disproof rates.
9. Align documentation with the actual operating mode; do not describe incompatible safety models as if they were one product.
10. Treat all target content, tool output, web content, and model output as untrusted data.

---

## 2. Current architecture map

```text
Operator / Claude Code / Freebuff / MCP
                    │
                    ├── commands/*.md
                    ├── hooks/*
                    ├── bridge/bugwolf-mcp.py
                    ├── legacy CLIs and direct tools
                    └── runtime mission CLI
                    │
                    ▼
              Mission intake
        harness_command.py / contracts.py
                    │
                    ▼
                MissionSpec
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       Scheduler           TeamEngine
 runtime/scheduler.py   runtime/team.py
          │                   │
          ▼                   ▼
  task graph/results   team state/recomposition
          │                   │
          └─────────┬─────────┘
                    ▼
                 Preflight
          runtime/preflight.py
                    │
                    ▼
             MissionRunner / lanes
          runtime/mission_runner.py
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
   HTTP/replay   live tools    race/browser/OAST
       │            │            │
       └────────────┴────────────┘
                    ▼
             Lead / research layer
     lead_protocol.py, research_loop.py,
     novelty, chains, understanding U1–U9
                    │
                    ▼
             Candidate/evidence layer
 lifecycle, evidence, impact, triage, reporting
                    │
                    ▼
          reports / SARIF / JSON / Markdown
```

### Major overlapping execution architectures

BugWolf currently contains several partially overlapping paths:

1. **MissionRunner** — staged mission and domain-lane execution.
2. **Scheduler** — task graph, dependencies, task results, resume state.
3. **TeamEngine** — multi-agent dispatch, recomposition, model routing, team state.
4. **Legacy/direct tools** — `hunt.py`, direct domain runners, schema/discovery tools, fuzz and protocol entry points.
5. **MCP bridge** — external tool-facing status, planning, execution, leads, modes, sessions, and understanding operations.
6. **Claude Code hooks** — pre-tool scope handling, session context, evidence capture, and stop/session behavior.
7. **Stage controller and persistent modes** — setup through report workflow and research/verify/deep-dive/coverage/report modes.

These components are individually useful, but the repository needs a single authoritative lifecycle and explicit adapters for every compatibility path.

---

## 3. Audit findings and issue register

### Severity definitions

- **Critical:** Can invalidate the safety boundary, execution provenance, or correctness of campaign conclusions.
- **High:** Can cause materially false results, skipped coverage, incomplete evidence, or unrecoverable lifecycle divergence.
- **Medium:** Reduces reliability, observability, or capability and can compound with other issues.
- **Low:** Documentation, ergonomics, or maintainability issue without direct campaign impact.

### BW-001 — Split and contradictory execution/safety models

**Severity:** Critical design risk  
**Confidence:** Confirmed at architecture/documentation level; exact live reachability must remain continuously tested.

BugWolf documentation and code describe two incompatible models:

- a newer mission/runtime path with scope, preflight, sandbox, and deny-by-default controls; and
- an “uncensored” or lab-only path that intentionally places authorization, scope, active-operation, and destructive-operation responsibility outside the plugin.

Relevant surfaces include execution semantics/controllers, direct tools, legacy runners, runtime scope/preflight/sandbox modules, operator documentation, and command/MCP entry points.

**Risk:** An operator or model can enter through a path whose guarantees differ from the path assumed by the report or runbook. A report may not clearly state which policy authority controlled each request.

**Required fix:**

- Define explicit execution profiles: `governed`, `lab-uncensored`, and `offline`.
- Make the selected profile a required, immutable mission field.
- Route all active execution through one policy-aware executor.
- Make direct tools either offline-only or thin adapters over the canonical executor.
- Emit the profile, policy version, scope digest, and executor version in every evidence envelope.
- Remove ambiguous wording such as “uncensored” where it could be confused with production safety.

**Acceptance criteria:** Every entry point reports the same profile and policy decision; a governed mission cannot call an ungoverned active executor; legacy paths fail with an explicit migration message or delegate to the canonical runtime.

---

### BW-002 — Redirect destinations are not demonstrably revalidated at the central HTTP choke point

**Severity:** High  
**Confidence:** Confirmed candidate from static review; requires regression coverage for every network-capable path.

A request may be authorized using its initial URL while a redirect sends the client to a destination that was not independently checked against the mission scope and exclusions. This is especially important when different lanes use different HTTP implementations or redirect behavior.

**Risk:** Scope enforcement can be correct for the original URL but incorrect for the effective network destination. Redirects can also cross scheme, host, port, or trust boundaries.

**Required fix:**

- Centralize redirect handling in the governed HTTP client.
- Resolve and authorize every hop before following it.
- Reapply exclusions, scheme policy, port policy, DNS/IP policy, and redirect-count limits per hop.
- Record every redirect decision as a policy fact.
- Default to no automatic redirects unless the mission explicitly enables bounded redirects.
- Apply the same behavior to browser, raw socket, replay, race, OAST, and subprocess-backed paths.

**Acceptance criteria:** Tests cover in-scope → out-of-scope, wildcard → excluded host, HTTPS → HTTP, alternate port, redirect loops, relative redirects, and DNS/IP changes. Every denied hop is fail-closed and appears in the evidence ledger.

---

### BW-003 — Accepted task domains can route to no-op executors

**Severity:** High  
**Confidence:** Confirmed candidate from capability-routing review.

The contract and intake layers accept a broader domain/task vocabulary than the active mission runner implements. Some declared domains can reach a no-op lane or placeholder executor rather than a real capability implementation.

**Risk:** A mission can appear complete while a requested capability was never executed. This is a capability-truth failure and can create false confidence in coverage.

**Required fix:**

- Create a machine-readable capability registry with states: `implemented`, `planned`, `offline-only`, `optional-dependency`, `blocked`, and `unsupported`.
- Validate every task against the registry before scheduling.
- Reject unsupported tasks or mark them explicitly `BLOCKED/UNSUPPORTED`; never mark them `DONE`.
- Include capability ID and implementation version in task results.
- Add a release gate that compares documented capabilities, registry entries, dispatch routes, and tests.
- Add one positive and one negative test for every advertised lane.

**Acceptance criteria:** No accepted task can reach a silent no-op. A missing dependency produces `BLOCKED` with a reason and remediation, not a successful empty result.

---

### BW-004 — Malformed or incomplete worker output can become `DONE`

**Severity:** High  
**Confidence:** Confirmed candidate from task/result contract review.

The result-routing path does not consistently demonstrate strict schema validation before completion is recorded. Worker output that is malformed, partial, missing evidence, or missing required status fields can be interpreted as a completed result.

**Risk:** The scheduler can close a task despite missing findings, missing artifacts, missing error details, or an untrusted worker response.

**Required fix:**

- Define one versioned `TaskResult` schema.
- Validate status, mission ID, task ID, capability ID, timestamps, evidence references, error fields, and completion criteria before persistence.
- Distinguish `DONE`, `PARTIAL`, `FAILED`, `BLOCKED`, `CANCELLED`, and `BUDGET_EXHAUSTED`.
- Treat malformed output as `FAILED_CONTRACT`, never `DONE`.
- Store the raw worker output separately with a checksum and redacted view.
- Require a completion predicate per task type; “process exited zero” is not sufficient.

**Acceptance criteria:** Fuzzed, truncated, empty, wrong-task, and wrong-mission outputs all fail contract validation; completion cannot be recorded without a valid result and declared artifact set.

---

### BW-005 — Preflight rejection is recorded but may not be a hard dispatch barrier

**Severity:** High  
**Confidence:** Confirmed candidate from preflight/control-flow review.

The preflight layer can record rejection or failure, but the call graph does not consistently prove that all dispatch routes stop before work begins.

**Risk:** Work can continue after a failed environment, scope, capability, budget, or operator preflight check. This undermines both safety and result interpretation.

**Required fix:**

- Make preflight produce a signed/versioned `PreflightReceipt` with `PASS`, `BLOCKED`, or `FAIL`.
- Require the receipt in the executor API, not only in the orchestrator logic.
- Check the receipt at scheduler dispatch, team dispatch, native dispatch, direct executor, browser, replay, and subprocess boundaries.
- Make receipt invalidation automatic when mission scope, profile, credentials, target, or policy version changes.
- Add a kill-switch and cancellation check before every side effect.

**Acceptance criteria:** No network, browser, subprocess, replay, or state-mutating operation can begin without a valid passing receipt. A failed receipt remains terminal until an explicit new preflight is created.

---

### BW-006 — Task-result persistence is fragmented by task rather than canonical mission scope

**Severity:** High  
**Confidence:** Confirmed from helper/path review.

The canonical result helper claims mission-scoped storage while deriving or writing paths using task identity. This can fragment `results.jsonl` and make a mission’s result set incomplete or difficult to reconstruct.

**Risk:** Resume, reporting, task accounting, and audit queries can see different subsets of the same mission. Duplicate or missing results become likely when tasks are retried or recomposed.

**Required fix:**

- Canonicalize all mission paths under `state/orchestrator/<mission_id>/`.
- Keep task-level artifacts under a task subdirectory but keep the authoritative result journal mission-scoped.
- Store `mission_id`, `task_id`, `attempt_id`, and parent task ID in every record.
- Add an index or deterministic query layer rather than relying on path conventions.
- Add migration tooling for legacy task-scoped logs.

**Acceptance criteria:** One mission query reconstructs all attempts and final states; task retries do not create invisible result islands; report generation uses only the canonical mission journal.

---

### BW-007 — Scheduler dependency state has duplicate authorities

**Severity:** High  
**Confidence:** Confirmed from scheduler review.

Dependencies are represented in more than one location, while the runtime dependency list is not consistently populated from the canonical task graph.

**Risk:** Tasks can run too early, remain stuck, or be incorrectly considered ready. Recomposition and resume can produce a different graph interpretation than initial scheduling.

**Required fix:**

- Store dependencies only in the versioned task graph.
- Derive runtime readiness from that graph on every scheduler load.
- Persist dependency evaluation facts: satisfied, missing, failed, or unknown.
- Reject cycles and dangling task IDs at graph validation time.
- Recompute readiness after every result transition and process restart.

**Acceptance criteria:** Dependency behavior is identical across fresh run, restart, retry, recomposition, and concurrent worker completion. Graph corruption fails closed with a recoverable diagnostic.

---

### BW-008 — Budget, rate, timeout, and quota authorities are inconsistent

**Severity:** High  
**Confidence:** Confirmed architectural gap.

Budgets appear across mission policy, scheduler, live executor, replay/governor, race engine, fuzz bridge, team orchestration, subprocess wrappers, and domain lanes. The audit did not establish one universally authoritative accounting model.

**Risk:** A mission can exceed the operator’s intended request, time, process, artifact, or cost budget when work is distributed across independent counters.

**Required fix:**

- Define a canonical `BudgetLedger` per mission.
- Account for requests, bytes, subprocesses, browser actions, model calls, wall time, CPU/memory where available, artifacts, and retries.
- Make all executors consume budget tokens from the ledger.
- Reserve tokens before work and reconcile actual usage afterward.
- Emit budget events and reject work when exhausted.
- Ensure child tasks inherit a bounded allocation and cannot reset the parent budget.

**Acceptance criteria:** Parallel, resumed, retried, and recomposed tasks cannot exceed the mission cap. Budget exhaustion yields `BUDGET_EXHAUSTED`, not a generic failure or successful completion.

---

### BW-009 — Evidence records can be symbolic without a guaranteed artifact

**Severity:** High  
**Confidence:** Confirmed gap from evidence/reporting review.

Some research and reporting paths can refer to an evidence block, replay key, or symbolic observation without guaranteeing that the underlying request, response, trace, state delta, or artifact exists, is readable, and matches the candidate.

**Risk:** Findings can look reproducible while lacking decisive proof. Reports may overstate impact based on a status code, model assertion, or incomplete trace.

**Required fix:**

- Define a versioned `EvidenceEnvelope` with required artifact references and hashes.
- Separate `observation`, `hypothesis`, `reproduction`, `impact`, and `confirmation` evidence states.
- Require raw-artifact existence, size, checksum, redaction status, and replay metadata before promotion.
- Treat missing artifacts as `INCONCLUSIVE` or `BLOCKED`, never as confirmed.
- Link every finding to its exact mission/task/attempt and policy receipt.
- Add negative-control and counterexample evidence for high-impact classes.

**Acceptance criteria:** A finding cannot become `CONFIRMED` without a valid evidence envelope, replayable inputs, expected/observed outcome, and impact proof appropriate to its class.

---

### BW-010 — Multiple lifecycle and state authorities can diverge

**Severity:** High  
**Confidence:** Confirmed architectural risk.

Stage controller state, scheduler graph state, team state, lead journals, persistent modes, candidate lifecycle, evidence ledgers, and report output each maintain related but different views of mission progress.

**Risk:** One layer can say “complete” while another says “open,” leading to skipped stages, duplicate work, invalid resume behavior, or reports assembled from stale state.

**Required fix:**

- Define a canonical mission state machine and event vocabulary.
- Make all other views projections or indexes of the mission event log.
- Use monotonic event IDs and schema versions.
- Define authoritative transitions for task, lead, candidate, stage, mode, and report states.
- Add consistency checks before resume and report generation.
- Make state reconciliation explicit and auditable rather than silently repairing data.

**Acceptance criteria:** A clean replay of the mission event log reconstructs stage, task, lead, candidate, evidence, and report state. Conflicting derived views are detected before active work or report export.

---

### BW-011 — Credential resume and account binding need a single provenance contract

**Severity:** High  
**Confidence:** Requires continued verification.

BugWolf supports account matrices, session context, redaction, and resume behavior, but the architecture must guarantee that credentials are bound to the exact mission, target, scope, and account label after restart without leaking or silently rebinding.

**Risk:** A resumed run can use stale, wrong-target, wrong-role, or incorrectly redacted credentials, producing invalid authorization conclusions or sensitive-data exposure.

**Required fix:**

- Bind each credential reference to mission ID, target digest, role label, scope digest, and expiration metadata.
- Store only in-memory secrets or operator-provided secret references; never persist raw tokens in JSONL journals.
- Require explicit re-binding when target, scope, or profile changes.
- Record credential provenance without recording credential values.
- Add tests for restart, rotation, redaction, wrong-account substitution, and stale session rejection.

**Acceptance criteria:** A resumed mission cannot use an account binding whose target/scope/profile digest differs from the original mission.

---

### BW-012 — Hook, MCP, direct CLI, and runtime behavior can drift

**Severity:** Medium/High  
**Confidence:** Confirmed integration risk.

BugWolf exposes the same concepts through command prompts, hooks, MCP methods, direct Python modules, stage controllers, and legacy tools. Not every surface is guaranteed to use the same contract version, policy checks, capability registry, or evidence writer.

**Required fix:**

- Make hooks and MCP thin clients of the runtime service/API.
- Version all external commands and MCP payloads.
- Generate command/MCP capability documentation from the registry.
- Add contract tests that invoke each entry point and compare the resulting mission record.
- Reject incompatible protocol versions rather than silently adapting.

**Acceptance criteria:** Equivalent operations through CLI, MCP, and command/hook paths produce the same normalized mission events and policy receipts.

---

### BW-013 — Documentation contains incompatible operating-boundary statements

**Severity:** Medium/High  
**Confidence:** Confirmed documentation inconsistency.

The main README describes a boundary-enforced deny-by-default execution layer, while the operator runbook and zero-day research documents describe an intentionally uncensored lab mode where authorization and scope are external responsibilities.

**Risk:** Operators, model agents, and reviewers may infer safety guarantees that do not apply to the selected path.

**Required fix:**

- Rewrite documentation around explicit execution profiles.
- Put a prominent profile declaration in the first-run output and every report.
- Mark lab-only features and direct tools as such.
- Add a documentation consistency CI check for safety/profile claims.
- Ensure examples include the profile and show expected blocked behavior.

**Acceptance criteria:** No document uses “scope enforced” without naming the path/profile that enforces it. No lab-only path is presented as a production safety control.

---

### BW-014 — No single measured proof layer for “deep” or “zero-day” capability

**Severity:** Medium/High  
**Confidence:** Confirmed roadmap gap.

BugWolf has many research primitives, but the audit identified the benchmark/proof layer as the missing mechanism for proving that the combined system improves detection rather than merely increasing tool and prompt volume.

**Required fix:**

- Freeze a versioned positive/negative/duplicate/inconclusive corpus.
- Measure true positives, false positives, false negatives, requests per finding, time to first finding, cost, reproduction rate, lead promotion rate, and assumption-disproof rate.
- Compare deterministic baseline, BugWolf, and selected alternate systems under identical budgets.
- Add blind checker/rebuttal review and confidence intervals.
- Publish limitations and failed cases with every benchmark result.

**Acceptance criteria:** A release cannot claim improved zero-day readiness without reproducible benchmark artifacts and a published metric table.

---

## 4. Implementation status

This section records the remediation work implemented in the current codebase. It deliberately does not mark architectural work complete merely because a unit test exists.

### Implemented and regression-tested

- Explicit execution profiles are represented in `MissionSpec` and validated.
- Mission-scoped `results.jsonl` persistence is canonicalized; standalone records use an explicit bucket.
- Scheduler dependency readiness is derived from graph dependencies, with dangling dependencies rejected.
- A durable `BudgetLedger` uses inter-process file locking, task reservations, runtime reconciliation, and explicit exhaustion states.
- Strict preflight receipt validation binds target, mission, operation profile, scope digest, persisted artifact, and receipt hash.
- MissionRunner treats preflight rejection as a hard side-effect barrier.
- Unsupported runtime lanes return explicit `blocked` results instead of silent completion.
- Active task start failures are persisted as `agent_failed` or `budget_exhausted` results.
- Malformed active worker output becomes terminal `failed` rather than leaving a task stranded in `active`.
- Explicit evidence artifact references must resolve inside the workspace and match a declared SHA-256 before reporting.
- HTTP redirect hops in the MissionRunner HTTP client are scope-checked before following.
- Native dispatch rejects invalid/non-object/empty JSON results.
- File-queue dispatch binds results to mission/job identity, validates terminal status, expires timed-out jobs, and records late/spoofed result rejection.
- Team status exposes degraded outcome and terminal failure counts separately from workflow completion.
- Long-lived on-chain Anvil fork startup now uses the shared sandbox/reliability process path with kill-switch, binary allowlist, environment scrubbing, process-group ownership, and explicit temporary-workspace regression coverage.
- Focused verification currently covers scheduler/remediation, mission E2E, reporting/lifecycle, native/queue dispatch, team recomposition, multi-agent, research, sandbox coverage, and Web3 capability slices; compileall passes for `tools`, `hooks`, and `bridge`.

### Still open after this implementation slice

- A single event-sourced authority has not yet replaced all StageController, Scheduler, TeamEngine, LeadStore, candidate, and report projections.
- Every active client (browser, raw socket, replay, race, OAST, subprocess, and legacy/direct tools) still needs a contract-equivalence audit against the canonical policy and budget APIs.
- Scope contract lifecycle remains process/workspace based; concurrent missions require an explicit ownership/lease protocol rather than relying on one-mission-per-process assumptions.
- Capability registry entries need generated documentation and automated route/test drift checks.
- Evidence integrity is strict for explicit file references, but class-specific impact oracles and clean-state replay coverage remain incomplete.
- Benchmark/proof metrics for novelty, false positives, cost, and assumption-disproof are not a release-complete proof of zero-day readiness.

## 5. Open loops and unresolved questions

These are not all confirmed defects; they are investigation or implementation loops that must be closed.

### 5.1 Architecture closure

- Which component is the canonical mission authority: StageController, Scheduler, MissionRunner, or a new runtime service?
- Is TeamEngine a scheduler worker, a planner, or an independent orchestrator?
- Which state is authoritative after a process crash?
- Can every direct CLI be represented as a task in the canonical graph?
- Which tools are offline planners versus active executors?
- Are all active network calls, browser calls, raw sockets, OAST interactions, and subprocesses covered by one policy boundary?

### 5.2 Scope and policy closure

- Are every redirect hop and resolved destination revalidated?
- Is DNS rebinding or IP/host mismatch handled consistently across clients?
- Are wildcard matches and exclusions identical in Python, browser, raw socket, and hook implementations?
- Are scope files immutable for the duration of a mission?
- Can a capture, replay artifact, external intelligence result, or model instruction widen scope?
- Does a failed or stale scope contract block every active path?

### 5.3 Capability closure

- Which declared domains currently execute real probes, and which only create plans?
- Which optional dependencies have positive integration tests versus graceful-skip tests only?
- Can capability manifests detect accepted-but-unimplemented domains?
- Do all domain lanes emit the common candidate/evidence schema?
- Are smart-contract, mobile, cloud, LLM, and cross-domain lanes connected to the same lifecycle as web/API lanes?

### 5.4 Evidence closure

- Is every report claim linked to a raw artifact and checksum?
- Can a replay be run from a clean state without hidden local context?
- Does every impact claim have a class-specific oracle?
- Are transport errors, tool failures, and target behavior separated?
- Are browser and OAST confirmations preserved as durable evidence rather than transient facts?
- Are redactions reversible only in memory and only for the originating operator request?

### 5.5 Lifecycle closure

- Are all terminal task states explicit and mutually exclusive?
- Can a malformed worker response become `DONE`?
- Are dependency cycles and dangling references rejected before dispatch?
- Does resume re-run only necessary work and reopen all incomplete leads?
- Can recomposition create duplicate tasks or exceed budgets?
- Are report/export operations blocked when open candidates or unresolved integrity errors remain?

### 5.6 Research/intelligence closure

- Does the Understanding Layer remain fresh relative to the target and current evidence?
- Are stale model slices prevented from driving active probes?
- Are predicted chains distinguishable from observed chains in reports?
- Are learned instincts advisory and provenance-bound, never authorization or verdict inputs?
- Can external intelligence be injected as untrusted, provenance-tagged data without prompt-instruction execution?
- Is novelty classification independent from impact confirmation?

### 5.7 Release/operations closure

- Do CI jobs exercise every supported Python version and optional integration profile intended for release?
- Are long-running suites bounded and diagnosed rather than timing out without a result?
- Are generated manifests and documentation synchronized with executable registries?
- Can a release be reproduced from a clean checkout with pinned dependencies?
- Are all artifacts signed or clearly marked unsigned?
- Are state migrations tested across versions?

---

## 6. Capability truth matrix

| Capability area | Present foundation | Main limitation / missing closure | Required proof |
|---|---|---|---|
| Mission intake | MissionSpec, contracts, command/MCP surfaces | Multiple entry paths and profile ambiguity | Contract-equivalence tests |
| Scope | Runtime scope, exclusions, hooks, documented deny-by-default path | Redirect and cross-client consistency must be proven; legacy mode differs | Per-hop scope regression suite |
| Preflight | Environment/capability/preflight modules | Rejection must be a hard executor invariant | No-side-effect rejection tests |
| Scheduling | Task graph, dependencies, resume concepts | Duplicate dependency authority and fragmented results | Crash/restart/recomposition tests |
| Team dispatch | Native/team workers, model routing, recomposition | Worker output and completion contract needs strict validation | Malformed-output and wrong-task tests |
| HTTP/replay | Mutation, raw replay, protocol and browser-related surfaces | Shared policy, budget, and evidence enforcement must be universal | Cross-client golden tests |
| Browser | Playwright/browser driver and browser-confirmation concepts | Dependency absence, session provenance, scope parity | Fixture-based browser verdict tests |
| OAST | Callback attribution concepts | Durable evidence and scope binding must be mandatory | Callback lineage tests |
| Race testing | Race engine and bounded windows | Global budget/accounting and clean-state proof | Repeated schedule and negative controls |
| Web/API | Schema extraction, discovery, BOLA/auth/header/WAF/business logic lanes | Some declared lanes may be no-op or plan-only | Capability registry + positive execution tests |
| Smart contracts/Web3 | Research, adapters, fixtures, invariant concepts | External toolchain and protocol-wide economic proof | Foundry/fixture benchmark suite |
| AI/agent security | AI adapters, MCP/RAG/memory concepts, trace ideas | End-to-end action/side-effect evidence and evaluator repeatability | Pinned local model/tool fixture |
| Cross-domain chains | Chain and lineage concepts | Observed versus predicted chain semantics; complete lineage | Multi-domain fixture and graph replay |
| Novelty | Candidate lifecycle, signatures, catalogs, clustering | Novelty cannot substitute for reproduction or impact | Known/duplicate/novel corpus |
| Evidence | Hashes, replay keys, ledgers, report paths | Symbolic evidence must not satisfy confirmation | Artifact existence and replay gate |
| Reporting | Markdown/JSON/SARIF/reporting gates | Noise, stale, unsupported, and incomplete findings need explicit states | Report integrity tests |
| Learning | Research/instinct/integration plan concepts | Must remain bounded, provenance-carrying, and non-authoritative | Contradiction/TTL/scope tests |
| Hooks/MCP | Session, prompt, post-tool, stop, MCP surfaces | Contract/version drift | Entry-point equivalence tests |
| Release | CI, manifests, bundle checks, docs | Claims can outrun executable proof | Capability truth gate |

---

## 6. Target architecture: one canonical runtime

### 6.1 Proposed authority model

```text
                  ┌─────────────────────────────┐
                  │ Entry-point adapters         │
                  │ CLI · MCP · hooks · commands │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ Mission Service / API        │
                  │ intake · profile · contracts │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ Canonical Mission Event Log  │
                  │ append-only · versioned      │
                  └───────┬─────────┬────────────┘
                          │         │
             ┌────────────▼───┐ ┌───▼────────────────┐
             │ Policy service  │ │ Scheduler           │
             │ scope/preflight │ │ graph/deps/budget   │
             │ profile/limits  │ │ cancellation/resume │
             └────────────┬───┘ └───┬────────────────┘
                          │         │
                          └────┬────┘
                               ▼
                  ┌─────────────────────────────┐
                  │ Canonical Executor          │
                  │ HTTP · raw · browser · OAST │
                  │ subprocess · domain adapter │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ Evidence / Candidate layer   │
                  │ facts · hypotheses · replay  │
                  │ impact · novelty · triage    │
                  └──────────────┬──────────────┘
                                 ▼
                  ┌─────────────────────────────┐
                  │ Projections                  │
                  │ leads · modes · dashboard    │
                  │ reports · SARIF · cockpit    │
                  └─────────────────────────────┘
```

### 6.2 Design laws

1. **One mission ID, one policy receipt, one budget ledger, one event log.**
2. **Adapters may request work; only the canonical executor may perform side effects.**
3. **A task is not complete until its result contract and artifact contract pass.**
4. **A hypothesis is not a finding; a finding is not confirmed until reproduction and impact proof pass.**
5. **Predictions, learned instincts, external intelligence, and model output are advisory data.**
6. **Scope and opsec fail closed; optional capability absence is explicit and honest.**
7. **No artifact or capture widens scope.**
8. **Every state transition is replayable from the event log.**
9. **Every report claim has a provenance path to an evidence envelope.**
10. **Documentation is generated or checked against the capability registry.**

---

## 7. Prioritized remediation roadmap

### Phase 0 — Freeze truth and define profiles

**Priority:** P0  
**Goal:** Stop ambiguity before adding capabilities.

#### Deliverables

- Define execution profiles: `offline`, `governed`, `lab-uncensored`.
- Add `profile`, `policy_version`, `scope_digest`, and `executor_version` to `MissionSpec`.
- Publish one operating-boundary document and update README, runbook, zero-day plan, commands, and MCP help.
- Inventory every active entry point and mark each as `offline`, `governed`, `lab-only`, or `deprecated`.
- Add a compatibility warning for direct/legacy paths.
- Freeze the current capability manifest as the audit baseline.

#### Tests and gates

- Profile parsing and immutability tests.
- Documentation profile-consistency check.
- Entry-point inventory check.
- Governed profile cannot call lab-uncensored executor.

#### Exit criteria

No ambiguous safety claim remains in release documentation, and every active invocation reports its execution profile.

---

### Phase 1 — Canonical contracts and lifecycle state

**Priority:** P0  
**Goal:** Make execution, tasks, candidates, evidence, and missions reconstructable.

#### Deliverables

- Versioned `TaskResult` schema.
- Versioned `PreflightReceipt` schema.
- Versioned `EvidenceEnvelope` schema.
- Versioned `MissionEvent` schema.
- Canonical mission event log under `state/orchestrator/<mission_id>/`.
- Explicit task states: `PLANNED`, `READY`, `RUNNING`, `DONE`, `PARTIAL`, `FAILED`, `FAILED_CONTRACT`, `BLOCKED`, `CANCELLED`, `BUDGET_EXHAUSTED`.
- Explicit candidate states separated from task states.
- Atomic append, locking, checksums, schema versioning, and recovery markers.
- Migration tool for task-scoped result logs and legacy finding records.

#### Tests and gates

- Truncated/malformed JSON tests.
- Wrong mission/task/attempt tests.
- Crash during write and recovery tests.
- Concurrent append and lock tests.
- Event-log replay equality tests.
- State-transition property tests.

#### Exit criteria

A clean process can reconstruct the complete mission state from the canonical event log without relying on secondary files.

---

### Phase 2 — Canonical policy and execution boundary

**Priority:** P0  
**Goal:** Ensure every side effect passes the same controls.

#### Deliverables

- One policy service for scope, exclusions, redirects, schemes, ports, DNS/IP policy, active/destructive declarations, and profile rules.
- One governed executor interface for HTTP, replay, raw sockets, browser, OAST, race, and subprocess operations.
- Per-hop redirect authorization.
- Immutable mission policy receipt.
- Preflight receipt required by executor APIs.
- Cancellation and kill-switch checks at every side-effect boundary.
- Explicit adapters for lab-uncensored mode, isolated from governed mode.

#### Tests and gates

- Every executor called with failed/missing/stale receipt.
- Redirect and exclusion matrix.
- Browser/raw/replay parity tests.
- DNS/IP/host mismatch tests where supported.
- Scope contract mutation and concurrent-write tests.
- Kill-switch and process-group cleanup tests.

#### Exit criteria

No active side effect can occur without a valid policy receipt and budget reservation.

---

### Phase 3 — Scheduler, dependencies, budgets, and cancellation

**Priority:** P0  
**Goal:** Make parallel and resumed work correct and bounded.

#### Deliverables

- One canonical dependency graph.
- Cycle/dangling-reference validation.
- One mission-wide `BudgetLedger`.
- Child budget reservations and reconciliation.
- Explicit cancellation receipts.
- Retry and attempt semantics.
- Resume algorithm derived from event log, not ad hoc file scanning.
- Recomposition rules that preserve task identity, parentage, and budget.

#### Tests and gates

- Parallel budget exhaustion tests.
- Retry and duplicate-attempt tests.
- Restart during every task state.
- Recomposition with dependency changes.
- Cancellation before and during network/subprocess/browser work.
- Long-running suite with bounded timeout and diagnostic artifact.

#### Exit criteria

A mission cannot exceed its declared budget, dispatch unmet dependencies, or silently lose results after restart.

---

### Phase 4 — Capability truth and routing closure

**Priority:** P1  
**Goal:** Ensure advertised capabilities map to real implementations.

#### Deliverables

- Machine-readable capability registry.
- Registry fields: capability ID, domain, entry point, execution profile, dependency requirements, evidence type, status, test IDs, limitations, version.
- Contract validation before scheduling.
- No-op lanes removed or explicitly marked unsupported.
- Optional tools report `BLOCKED` with a reason.
- Documentation and command/MCP help generated from or checked against the registry.
- Per-domain common adapter interface.

#### Tests and gates

- Every advertised capability has an implementation or an explicit non-implemented status.
- Positive fixture and negative-control fixture per capability.
- Missing dependency tests.
- Capability registry drift check.
- Direct CLI/MCP/mission routing equivalence tests.

#### Exit criteria

The system never claims a capability executed when it only planned, skipped, or no-op’d.

---

### Phase 5 — Evidence, reproduction, and reporting integrity

**Priority:** P1  
**Goal:** Prevent unsupported or symbolic claims from becoming confirmed findings.

#### Deliverables

- Evidence envelope and artifact store.
- Raw artifact references with checksums and redaction metadata.
- Replay manifest: target/profile/scope/policy/credentials reference/tool versions/seed/input/state.
- Class-specific impact oracles.
- Negative controls and counterexamples.
- Independent verification step.
- Report gate that rejects missing, stale, mismatched, or non-replayable evidence.
- Clear distinction between `HYPOTHESIS`, `OBSERVED`, `REPRODUCED`, `IMPACT_VALIDATED`, `CONFIRMED`, `INCONCLUSIVE`, and `BLOCKED`.

#### Tests and gates

- Missing artifact and checksum mismatch tests.
- Replay from clean state.
- Status-code-only false-positive cases.
- OAST/browser evidence persistence.
- Redaction and secret non-persistence tests.
- Report claim-to-evidence lineage verification.

#### Exit criteria

Every confirmed finding is reproducible from its evidence bundle and has a class-appropriate impact proof.

---

### Phase 6 — Understanding, intelligence, and learning hardening

**Priority:** P1  
**Goal:** Make research intelligence useful without making it authoritative or unsafe.

#### Deliverables

- Target-model freshness and digest binding.
- Predicted chain versus observed chain labels.
- Provenance-tagged external intelligence records.
- Injection canaries and untrusted-content handling.
- Instinct/learning records with occurrence thresholds, contradiction handling, TTL, scope, and operator promotion.
- Model-slice dispatch with evidence of which U-stage facts were supplied.
- Pre-compact/session-context recovery without secret persistence.

#### Tests and gates

- Stale model rejection.
- Prompt-injection canary tests.
- External content treated as data rather than instructions.
- Instinct contradiction and TTL tests.
- Scope cannot be widened by learned data.
- Model-generated result cannot bypass deterministic lifecycle transitions.

#### Exit criteria

Research intelligence improves prioritization and coverage while remaining advisory, provenance-bound, and unable to bypass policy or evidence gates.

---

### Phase 7 — Domain capability completion

**Priority:** P1/P2  
**Goal:** Close real execution and validation gaps by domain.

#### Web/API

- Unified REST/GraphQL/gRPC/WebSocket surface graph.
- Stateful workflow and race scheduler.
- Cache, queue, retry, consistency, and protocol differential fixtures.
- Complete browser/OAST/session evidence.

#### Smart contracts/Web3

- Protocol state model and valid transaction grammar.
- Economic invariant runner.
- Sequence generation/minimization.
- Upgrade, oracle, bridge, account-abstraction, and L2 fixtures.
- Tool-output normalization and clean-state reproduction.

#### AI/agent

- Complete context → model → tool → argument → result → side-effect trace.
- RAG/memory/MCP poisoning fixtures.
- Safe fake tools with observable state changes.
- Pinned model/runtime metadata and evaluator agreement.

#### Cross-domain

- Document/retrieval → model → API → transaction lineage.
- Cross-domain candidate correlation and impact chains.
- Negative controls proving causal rather than coincidental linkage.

#### Exit criteria

Each advertised domain has real positive, negative, duplicate, blocked, and inconclusive fixtures using the common lifecycle and evidence schemas.

---

### Phase 8 — Measured proof and release readiness

**Priority:** P1  
**Goal:** Replace capability claims with reproducible measurements.

#### Deliverables

- Frozen benchmark corpus.
- Positive, negative, duplicate, expected-behavior, and inconclusive cases.
- Deterministic seeded runner.
- Baseline comparison.
- Metrics dashboard.
- Blind checker/rebuttal loop.
- Cost and resource measurements.
- Assumption-disproof and understanding-layer regression metrics.
- Published limitations and failed-case report.

#### Required metrics

- True-positive rate by class.
- False-positive rate by class.
- False-negative rate where ground truth exists.
- Reproduction rate.
- Impact-validation rate.
- Requests/probes per confirmed finding.
- Time to first valid finding.
- Lead-to-finding promotion rate.
- Duplicate/known-issue rejection rate.
- Assumption confirmed/refuted/disputed rate.
- Model/tool cost and wall time.
- Budget adherence and cancellation latency.
- Evidence completeness and replay success.

#### Exit criteria

A release may describe BugWolf as research-ready only when the benchmark is reproducible, artifacts are available, and limitations are explicit. No release may claim guaranteed zero-day discovery.

---

## 8. Test and verification plan

### 8.1 Fast checks on every change

```bash
python3 -m compileall -q tools hooks bridge
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tools/capability_manifest.py
python3 -m tools.readiness
```

### 8.2 Focused contract suites

Maintain dedicated tests for:

- mission contracts and task results;
- scope, exclusions, redirects, and policy receipts;
- preflight hard barriers;
- scheduler dependencies and budgets;
- team/native dispatch and malformed worker output;
- evidence envelopes and artifact existence;
- candidate lifecycle and promotion gates;
- replay from clean state;
- credential binding and redaction;
- hooks/MCP/CLI contract equivalence;
- capability registry drift;
- report claim-to-evidence lineage.

### 8.3 Adversarial tests

- Missing or stale scope contract.
- Redirect to excluded or private destination.
- Wrong mission/task result.
- Empty or malformed worker output.
- Dependency cycle.
- Duplicate task attempt.
- Budget exhaustion during parallel execution.
- Cancellation during subprocess or browser work.
- Corrupt JSONL line and partial write.
- Stale target model.
- Prompt injection in target page, schema, tool output, or external intelligence.
- Credential mismatch after resume.
- Evidence file deletion after candidate discovery.
- Tool returns a success exit code but no required artifact.
- Optional dependency absent.
- No-op capability route.

### 8.4 Release gates

A release is blocked when any of the following occurs:

- governed execution can bypass a policy receipt;
- a malformed result becomes `DONE`;
- an advertised capability routes to a silent no-op;
- a confirmed finding lacks a valid evidence envelope;
- task results cannot be reconstructed by mission ID;
- budget accounting is inconsistent across workers;
- documentation claims conflict with the selected profile;
- generated registry, manifests, and command/MCP surfaces drift;
- benchmark artifacts are missing or not reproducible.

---

## 9. Operational runbook after remediation

### Before a mission

1. Select and display the execution profile.
2. Verify the target specification, authorization basis, scope, exclusions, and ROE.
3. Generate the immutable policy receipt.
4. Run preflight and retain the receipt.
5. Verify capability availability and optional dependency status.
6. Bind account/session references to the mission digest.
7. Set request, time, artifact, subprocess, and model budgets.
8. Build or refresh the target model and confirm freshness.

### During a mission

1. Dispatch only through the canonical scheduler/executor.
2. Record every task result and policy decision in the mission event log.
3. Treat all target/tool/model/external content as untrusted data.
4. Keep hypotheses separate from observed and reproduced evidence.
5. Revalidate redirects and all effective destinations.
6. Monitor budget, cancellation, artifact, and integrity events.
7. Do not treat blocked or skipped optional integrations as successful coverage.

### Before reporting

1. Reconcile event log, task graph, candidate lifecycle, and evidence ledger.
2. Verify every finding’s artifacts, checksums, replay manifest, and impact proof.
3. Run independent replay and negative controls.
4. Check novelty/known-issue classification separately from exploitability.
5. Mark unsupported, stale, inconclusive, and blocked items explicitly.
6. Include execution profile, policy version, scope digest, tool versions, and limitations.
7. Require human review for high-impact and potentially novel findings.

### After a mission

1. Persist a clean summary and immutable artifact manifest.
2. Redact and verify no secrets entered reports or persistent logs.
3. Mine only approved facts into bounded learning/instinct state.
4. Record failures and unclosed leads for future research.
5. Verify that no background process or tunnel remains active.
6. Preserve or securely destroy artifacts according to the mission’s retention policy.

---

## 10. Definition of done

BugWolf’s architecture remediation is complete when all of the following are true:

- One canonical runtime owns mission lifecycle and active execution.
- One policy authority controls scope, profile, redirects, exclusions, and side effects.
- One mission event log reconstructs all state.
- One budget ledger accounts for all work.
- Preflight rejection is a hard dispatch barrier.
- Results are schema-validated; malformed output cannot become `DONE`.
- No accepted capability silently routes to a no-op.
- Every confirmed finding has replayable, checksummed, class-specific evidence.
- Credentials are bound to the mission and never persist as raw values.
- CLI, MCP, hooks, commands, and direct tools are contract-compatible adapters.
- Documentation accurately describes each operating profile.
- Domain lanes share a common candidate/evidence lifecycle.
- Benchmark and regression suites measure capability, cost, false positives, and limitations.
- Release gates fail closed on integrity, capability-truth, evidence, and policy failures.

---

## 11. Final prioritization

| Priority | Workstream | Why it comes first |
|---:|---|---|
| P0 | Execution profiles and safety-model unification | Prevents operators from confusing incompatible guarantees |
| P0 | Canonical contracts/event log | Makes every later fix observable and recoverable |
| P0 | Policy/preflight hard barriers | Prevents work from running outside declared controls |
| P0 | Scheduler dependencies and budget ledger | Prevents incorrect, unbounded, or incomplete campaigns |
| P1 | Capability registry and no-op closure | Prevents false claims of coverage |
| P1 | Evidence/reproduction/report gates | Prevents unsupported findings and overclaiming |
| P1 | CLI/MCP/hooks/runtime convergence | Prevents entry-point drift |
| P1 | Learning/intelligence provenance controls | Adds adaptation without allowing unsafe authority escalation |
| P2 | Domain execution depth | Expands actual research power after foundations are reliable |
| P2 | Cross-domain correlation | Requires stable common schemas and evidence first |
| P1 | Benchmark/proof layer | Measures whether improvements are real rather than rhetorical |

## Final conclusion

BugWolf does not primarily need more payloads, more agents, or more documentation. It needs a smaller number of authoritative contracts that every existing capability must obey.

The most credible path to deeper and more complex vulnerability discovery is:

```text
accurate target model
        → bounded hypothesis generation
        → deterministic execution
        → independent reproduction
        → impact proof and negative controls
        → novelty classification
        → human-reviewed report
        → measured learning from provenance-carrying facts
```

Until the P0 and P1 items are closed, BugWolf should be described as a broad, promising research harness with integration and evidence risks—not as a guaranteed autonomous zero-day generator.

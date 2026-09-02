# BugWolf OMC-Style Orchestrator Upgrade Plan

**Document status:** Proposed engineering plan  
**Date:** 2026-09-02  
**Target:** BugWolf plugin  
**Reference implementation:** oh-my-claudecode v5.1.0  
**Primary objective:** transform BugWolf from a large collection of security tools into a coherent, high-performance, Claude-native agent orchestration platform.

> This plan defines the build architecture while BugWolf is under development. It preserves maximum research capability and operator-configurable execution. The platform must not silently claim capabilities it has not implemented, and all live actions must remain attributable and observable.

---

## 1. Executive summary

BugWolf already contains the foundations of an advanced security-research engine:

- 12-stage campaign workflow;
- mandatory research checkpoints;
- parallel domain analyzers;
- live HTTP and fuzzing components;
- evidence, replay, ledger, and chain-of-custody systems;
- web/API, cloud, mobile, smart-contract, CI/CD, and AI-security coverage;
- local VulnBank fixtures and release bundles.

The main upgrade is not adding more isolated scanners. The main upgrade is creating a **single orchestration runtime** that can:

1. receive a natural-language mission;
2. decompose it into typed research tasks;
3. select specialized Claude agents and models;
4. run independent work in parallel;
5. preserve durable state across context resets;
6. route findings and blockers between agents;
7. adapt the research plan from evidence;
8. validate claims through deterministic tools and replay;
9. produce a complete, traceable final report.

The target architecture is:

```text
Claude Code / Claude Agent SDK
             ↓
BugWolf session adapter and mission intake
             ↓
Campaign orchestrator and task graph
             ↓
Planner → specialist agents → verifier → synthesizer
             ↓
Deterministic BugWolf tools and external local tooling
             ↓
Evidence, replay, findings, chains, metrics, report
```

---

## 2. Product goals and non-goals

### 2.1 Goals

- First-class Claude Code/plugin integration.
- Support current Claude models through configurable model routing rather than hard-coded names.
- OMC-style skills, agents, hooks, teams, persistent modes, and task state.
- High parallel throughput without losing evidence lineage.
- Agent specialization by security domain and task type.
- Deterministic tool execution beneath model reasoning.
- Efficient context management for large repositories and long campaigns.
- Failure recovery, retry, resumption, and orphan cleanup.
- Measurable performance and detection quality.
- Honest capability reporting and reproducible release artifacts.

### 2.2 Non-goals

- Replacing Claude Code itself.
- Treating prompts as a security boundary.
- Claiming guaranteed zero-day discovery.
- Making every task autonomous by default.
- Adding dozens of agents without measurable role separation.
- Allowing model output to directly become a confirmed finding without evidence.

---

## 3. Design principles

1. **Orchestrator over script collection.** Every tool must be callable through a common task and artifact contract.
2. **Planner/executor separation.** Models propose work; deterministic tools execute and record it.
3. **Parallel by default where independent.** Recon, static analysis, domain analysis, and research hypotheses should run concurrently.
4. **Sequential where state matters.** Authentication flows, mutation chains, replay, and impact validation must preserve ordering.
5. **Artifacts are durable truth.** JSON/JSONL artifacts, not model memory, define campaign state.
6. **Evidence before confidence.** Confidence is derived from reproducible observations, not agent enthusiasm.
7. **Full research capability, explicit operations.** Research depth should not be needlessly reduced, while external operations remain visible, bounded, and attributable.
8. **Fail visibly.** Missing tools, model failures, corrupted state, and unavailable runtimes must become explicit campaign states.
9. **Model-agnostic routing.** Model IDs and capabilities are configuration, not scattered constants.
10. **Performance is measured.** Track latency, throughput, token cost, coverage, reproduction rate, and false-positive rate.

---

## 4. Target architecture

### 4.1 Runtime layers

#### Layer A — Claude host adapter

Create a Claude-facing adapter that supports:

- Claude Code skill invocation;
- Claude Agent SDK sessions where available;
- structured tool definitions;
- session lifecycle hooks;
- model and effort configuration;
- prompt/context projection;
- compact status output;
- graceful fallback when SDK features are unavailable.

Proposed modules:

```text
bugwolf/runtime/claude_adapter.py
bugwolf/runtime/session_contract.py
bugwolf/runtime/model_router.py
bugwolf/runtime/tool_registry.py
bugwolf/runtime/hook_bridge.py
```

#### Layer B — Mission intake

Normalize conversational requests into a `MissionSpec`:

```json
{
  "mission_id": "bw-...",
  "target": "...",
  "domains": ["web_api", "cloud", "llm"],
  "objective": "...",
  "artifacts": [],
  "operation_profile": "research",
  "model_profile": "balanced",
  "budget": {
    "max_agents": 12,
    "max_parallel_tasks": 8,
    "max_runtime_seconds": 3600
  }
}
```

The intake layer must support both natural-language and direct CLI/API invocation.

#### Layer C — Task graph orchestrator

Replace ad hoc orchestration calls with a typed DAG/task graph:

- task ID and parent ID;
- task type and domain;
- required inputs;
- produced artifacts;
- dependencies;
- priority;
- model profile;
- retry policy;
- timeout;
- status and timestamps;
- evidence references;
- failure classification.

Use the existing campaign and research-thread concepts as migration sources rather than creating a second state model.

#### Layer D — Agent runtime

Standardize specialist agents around a common contract:

```text
agent receives task + bounded context
agent produces structured result + artifact references
agent never writes arbitrary campaign state directly
orchestrator validates and commits result
```

Agent roles:

- commander/planner;
- recon analyst;
- web/API analyst;
- authentication analyst;
- business-logic analyst;
- smart-contract analyst;
- cloud/IAM analyst;
- CI/CD analyst;
- LLM/agentic analyst;
- mobile analyst;
- fuzzing strategist;
- evidence verifier;
- refutation reviewer;
- report synthesizer.

#### Layer E — Tool execution plane

Create a unified execution interface for:

- Python BugWolf tools;
- local binaries;
- HTTP probe runner;
- smart-contract simulators;
- browser/emulator/chain fixtures;
- static analyzers;
- external provider adapters.

Each invocation returns a common `ToolReceipt` with command, inputs, output paths, exit state, duration, resource usage, and evidence references.

#### Layer F — State and evidence plane

Unify current state stores behind a campaign repository abstraction:

```text
campaign.json
mission.json
plan.json
 tasks/*.json
 events.jsonl
 artifacts/
 evidence/
 findings.jsonl
 chains.jsonl
 metrics.json
```

Maintain backward-compatible readers for current `.bugwolf`, `state/`, `research/`, and campaign files during migration.

---

## 5. Model routing strategy

### 5.1 Model capability profiles

Do not hard-code a single “latest” model. Define capability profiles:

| Profile | Use |
|---|---|
| `fast` | classification, extraction, simple triage, formatting |
| `balanced` | normal specialist analysis and planning |
| `deep` | complex business logic, chains, novel hypotheses |
| `reasoning` | difficult verification, invariant analysis, root cause |
| `synthesis` | final cross-agent report and campaign decisions |

Each profile maps to a configurable Claude model ID and effort level.

### 5.2 Routing rules

- Use fast models for deterministic-context transformations.
- Use balanced models for routine specialist tasks.
- Use deep/reasoning models for high-impact candidates and unresolved chains.
- Escalate based on uncertainty, not only severity.
- Cap context size per task and use artifact references instead of repeated raw files.
- Record model, temperature/effort, prompt hash, and response hash in every result.

### 5.3 Model failure handling

- Retry transient provider failures with bounded backoff.
- Re-route to a compatible fallback model.
- Preserve partial outputs as `agent_failed` or `agent_partial` artifacts.
- Never silently convert a model failure into a clean result.

---

## 6. OMC-style orchestration features

### Phase O1 — Skills and command surface

Create a concise BugWolf skill contract modeled after OMC’s reloadable session contract:

- `/bugwolf` mission entry;
- `/bugwolf-plan` planning only;
- `/bugwolf-run` execute an approved task graph;
- `/bugwolf-status` campaign status;
- `/bugwolf-review` inspect candidates;
- `/bugwolf-report` generate reports;
- `/bugwolf-stop` stop active campaign;
- `/bugwolf-resume` resume from artifacts.

Keep the contract short, deterministic, and reloadable. Move detailed methodology into reference files and machine-readable registries.

### Phase O2 — Agent registry

Create a registry containing:

- role name;
- domain;
- capabilities;
- input artifact types;
- output artifact types;
- supported model profiles;
- concurrency class;
- cost estimate;
- verification requirements;
- tool permissions as operational metadata.

The registry should replace scattered agent-selection logic.

### Phase O3 — Parallel task scheduler

Implement a bounded scheduler with:

- dependency-aware dispatch;
- priority queues;
- domain fairness;
- maximum concurrency;
- per-agent concurrency;
- cancellation propagation;
- retry and backoff;
- task deduplication;
- orphan detection;
- durable event emission.

Initial implementation can use Python threads/processes or asyncio according to existing project conventions; benchmark both before committing to a runtime model.

### Phase O4 — Shared memory and event bus

Use typed events for cross-agent communication:

```text
MissionCreated
TaskPlanned
TaskStarted
ArtifactProduced
SignalDiscovered
FindingUpdated
BlockerObserved
ResearchExpansionRequested
VerificationCompleted
ReportReady
```

Existing `signal_bus.py`, research threads, learning state, and ledgers should publish into this event model through adapters.

### Phase O5 — Persistent execution modes

Implement resumable modes analogous to OMC persistent workflows:

- `research`: continue exploring until budget or completion condition;
- `verify`: repeatedly test unresolved candidates;
- `deep-dive`: focus on one high-value chain;
- `coverage`: pursue uncovered surface dimensions;
- `report`: complete evidence and reporting artifacts.

Every mode needs a stop/resume state machine and explicit completion criteria.

### Phase O6 — Team execution

Add optional multi-agent team execution:

- planner creates lanes;
- specialists work independently;
- verifier reviews outputs;
- commander merges decisions;
- failed lanes can be restarted without restarting the campaign.

Avoid spawning a separate agent for trivial work. The scheduler should collapse small tasks into batches for performance.

---

## 7. BugWolf domain integration

### 7.1 Web/API

Integrate:

- surface model;
- schema extraction;
- BOLA/BFLA/BOPLA planning;
- GraphQL analysis;
- parser differential and smuggling research;
- authentication flow analysis;
- business-logic state machines;
- race-condition planning;
- live executor and fuzz bridge.

Output must converge into one task graph rather than separate disconnected scripts.

### 7.2 Smart contracts and DeFi

Integrate:

- contract discovery;
- invariant execution;
- formal verification bridges;
- economic analysis;
- upgradeability checks;
- LLM candidate triage;
- minimized violating sequences.

Use deterministic invariant and replay tools as the final evidence authority.

### 7.3 Cloud and CI/CD

Integrate:

- IAM capability graphs;
- IaC analysis;
- CI/CD workflow analysis;
- container and serverless posture;
- asset and identity relationships;
- chain analysis for privilege paths.

### 7.4 LLM and agentic security

Integrate:

- prompt-injection analysis;
- tool authorization flow mapping;
- MCP boundary analysis;
- memory/RAG poisoning planning;
- agent identity and privilege analysis;
- tool-call trace review.

### 7.5 Mobile

Integrate:

- manifest/plist policy analysis;
- deep-link graphing;
- WebView bridge analysis;
- PendingIntent and exported-component analysis;
- binary/static evidence references.

---

## 8. Performance engineering plan

### 8.1 Baseline measurements

Before refactoring, measure:

- time to first useful signal;
- total campaign duration;
- tasks completed per minute;
- peak concurrent agents;
- tokens per task and campaign;
- context duplication ratio;
- tool startup overhead;
- evidence write latency;
- retry rate;
- model failure rate;
- reproduction rate;
- false-positive rate on VulnBank and negative controls.

### 8.2 Performance improvements

1. **Artifact references instead of prompt duplication.** Agents receive summaries and file references, not repeated full campaign history.
2. **Incremental indexing.** Cache file hashes, schema extraction, fingerprints, and parsed artifacts.
3. **Task batching.** Batch extraction/classification work for fast models.
4. **Parallel independent analysis.** Dispatch domain agents concurrently after shared intake artifacts exist.
5. **Adaptive budgets.** Allocate more model/tool budget to high-information tasks.
6. **Early duplicate suppression.** Deduplicate tasks and candidates before model invocation.
7. **Streaming events.** Persist task events incrementally rather than waiting for campaign completion.
8. **Worker reuse.** Reuse long-lived local tool workers where startup cost is material.
9. **Bounded output.** Enforce output caps and summarize large command output.
10. **Hot-path profiling.** Profile Python orchestration, JSONL state, subprocess startup, and model calls separately.

### 8.3 Performance targets

Initial targets, to be validated against the baseline:

- first plan artifact within 5 seconds for local missions;
- first specialist task dispatched within 10 seconds;
- at least 6 independent specialist tasks concurrently available on a standard workstation;
- less than 20% duplicated context across agent prompts;
- task state durable within 1 second of each transition;
- campaign resume without re-running completed deterministic tasks;
- no unbounded memory growth in long campaigns.

---

## 9. State, evidence, and reporting contract

### 9.1 Unified result schema

Every agent result must include:

```json
{
  "task_id": "...",
  "agent_role": "web-api",
  "status": "completed",
  "summary": "...",
  "hypotheses": [],
  "observations": [],
  "artifact_refs": [],
  "evidence_refs": [],
  "next_tasks": [],
  "confidence": 0.0,
  "model": "...",
  "prompt_hash": "...",
  "created_at": "..."
}
```

### 9.2 Candidate lifecycle

```text
HYPOTHESIS
  → SIGNAL
  → CANDIDATE
  → REPRODUCED
  → IMPACT_VERIFIED
  → HUMAN_REVIEWED
  → REPORTABLE
```

The orchestrator may expand research from any state, but reporting must preserve the distinction.

### 9.3 Chain contract

Every chain records:

- source candidates;
- edge hypotheses;
- required missing links;
- verification attempts;
- terminal impact;
- confidence and uncertainty;
- evidence for every edge;
- model and tool provenance.

---

## 10. Implementation phases

### Phase 0 — Inventory and compatibility foundation

**Deliverables:**

- complete BugWolf module and CLI inventory;
- map current campaign, research, evidence, state, and event formats;
- define compatibility adapters;
- define canonical artifact directory;
- freeze baseline benchmark results;
- identify stale documentation and missing files.

**Exit criteria:**

- all current entrypoints mapped;
- no duplicate state model introduced;
- baseline tests and lab checks recorded.

### Phase 1 — Canonical runtime contracts

**Deliverables:**

- `MissionSpec`;
- `TaskSpec`;
- `TaskResult`;
- `ToolReceipt`;
- `ArtifactRef`;
- `FindingRef`;
- event types;
- JSON schemas and validators;
- model profile registry.

**Exit criteria:**

- one existing BugWolf tool can run through the new contract;
- malformed results fail explicitly;
- schemas have unit and fixture tests.

### Phase 2 — Claude adapter and model router

**Deliverables:**

- Claude Code skill adapter;
- Agent SDK integration where supported;
- configurable model profiles;
- prompt projection and context compaction;
- provider failure and fallback handling;
- model provenance recording.

**Exit criteria:**

- a local mission can create a plan and invoke one specialist agent;
- model selection is controlled by configuration;
- no model name is hard-coded in domain tools.

### Phase 3 — Task graph and scheduler

**Deliverables:**

- dependency-aware scheduler;
- parallel execution;
- task persistence;
- retries, timeouts, cancellation, resume;
- event stream;
- task status CLI.

**Exit criteria:**

- 10+ independent fixture tasks run concurrently;
- interrupted campaigns resume without duplicate completed work;
- failed tasks remain diagnosable.

### Phase 4 — Agent registry and specialist lanes

**Deliverables:**

- commander/planner;
- recon;
- web/API;
- smart-contract;
- cloud/CI;
- LLM/agentic;
- mobile;
- verifier;
- report synthesizer.

**Exit criteria:**

- each agent has explicit inputs/outputs;
- agent selection is registry-driven;
- specialists can operate independently and feed results back to the commander.

### Phase 5 — Existing BugWolf engine migration

**Deliverables:**

- adapt `campaign_orchestrator.py`;
- adapt `research_loop.py`;
- adapt `research_thread.py`;
- adapt `live_executor.py` and `fuzz_bridge.py`;
- adapt domain tools;
- adapt evidence, ledger, chain, and reporting modules;
- preserve old CLI entrypoints through compatibility wrappers.

**Exit criteria:**

- full local VulnBank campaign runs through the new orchestrator;
- existing artifacts remain readable;
- no direct tool bypasses the task/evidence contract.

### Phase 6 — Persistent modes and adaptive research

**Deliverables:**

- research/verify/deep-dive/coverage/report modes;
- blocker-to-task expansion;
- candidate-driven escalation;
- failure learning integration;
- chain graph synthesis;
- campaign resume and stop commands.

**Exit criteria:**

- a campaign can be paused, resumed, and continued after context reset;
- blockers produce explicit next tasks;
- adaptive behavior is visible in event logs.

### Phase 7 — Performance optimization

**Deliverables:**

- profiling report;
- context deduplication;
- task batching;
- worker reuse where beneficial;
- incremental artifact indexing;
- concurrency tuning;
- benchmark dashboard.

**Exit criteria:**

- performance targets measured and documented;
- no regression in evidence quality;
- resource limits and failure behavior tested.

### Phase 8 — Release hardening and documentation

**Deliverables:**

- generated capability manifest;
- updated `AUDIT.md` and `AUDIT_MAP.md`;
- installation and Claude setup documentation;
- migration guide;
- operator runbook;
- benchmark report;
- release bundle verification;
- versioned schemas.

**Exit criteria:**

- clean checkout builds reproducibly;
- all documented commands resolve to real files;
- full fixture, unit, integration, and bundle tests pass.

---

## 11. Proposed repository layout

Prefer existing directories and migrate incrementally:

```text
bugwolf/
├── runtime/
│   ├── claude_adapter.py
│   ├── model_router.py
│   ├── mission.py
│   ├── scheduler.py
│   ├── events.py
│   └── contracts.py
├── agents/
│   ├── registry.py
│   ├── commander.py
│   ├── verifier.py
│   └── specialists/
├── tools/core/
├── tools/domains/
├── tools/validation/
├── state/
│   └── schemas/
├── configs/
│   ├── models.json
│   ├── agents.json
│   └── orchestrator.json
├── tests/
│   ├── runtime/
│   ├── agents/
│   ├── integration/
│   └── benchmarks/
├── SKILL.md
└── BUGWOLF_OMC_UPGRADE_PLAN.md
```

Do not create a second independent implementation of existing campaign, evidence, or ledger functionality. New runtime modules should call existing engines through adapters until migration is complete.

---

## 12. Testing and evaluation strategy

### 12.1 Contract tests

- MissionSpec parsing;
- task dependency validation;
- result schema validation;
- event ordering;
- artifact references;
- model routing;
- cancellation and resume;
- malformed state recovery.

### 12.2 Orchestration tests

- parallel dispatch;
- task deduplication;
- retry/backoff;
- timeout handling;
- orphan worker detection;
- event replay;
- partial campaign recovery;
- agent failure isolation;
- context compaction.

### 12.3 Security research tests

Use local fixtures and controlled inputs for:

- BOLA/BFLA;
- mass assignment;
- GraphQL batching;
- WAF/parser differentials;
- JWT/OAuth analysis;
- smart-contract invariants;
- IAM graph reachability;
- prompt injection and tool misuse;
- mobile manifest/deep-link cases;
- negative controls.

### 12.4 Performance benchmarks

Measure:

- sequential versus parallel campaign time;
- model calls per confirmed candidate;
- context bytes per task;
- task throughput;
- artifact latency;
- resume speed;
- CPU/memory usage;
- first-signal latency;
- precision and reproduction rate.

### 12.5 Quality gates

A release is not complete unless:

- all canonical contracts validate;
- no task silently disappears;
- no model failure becomes a success;
- no finding is promoted without required evidence;
- fixture positives are detected;
- fixture negatives remain clean;
- campaign resume works;
- generated bundles are complete;
- documentation matches implementation.

---

## 13. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---:|---|
| Orchestrator duplicates existing state systems | High | Compatibility adapters and one canonical campaign repository |
| Parallelism creates race conditions | High | Typed events, atomic writes, per-campaign locks, deterministic reducers |
| More agents increase cost without better findings | High | Benchmark every role; adaptive routing and task batching |
| Long prompts reduce model quality | High | Artifact references, summaries, context budgets, compaction |
| Agent output becomes false findings | High | Deterministic evidence lifecycle and verifier agent |
| External tooling hangs | Medium | Timeouts, process groups, output caps, receipts |
| Provider/API failure stops campaigns | Medium | Resume state, fallback profiles, partial-result preservation |
| Model names change | Medium | Configured model registry and capability probing |
| New runtime breaks old CLI users | High | Compatibility wrappers and migration tests |
| Documentation overstates maturity | High | Generated readiness/capability manifest and benchmark publication |

---

## 14. Definition of done

BugWolf reaches the first production-quality orchestrator milestone when:

1. Claude can start a BugWolf mission from natural language or a structured command.
2. The mission becomes a durable typed task graph.
3. At least six specialist lanes can execute concurrently.
4. Every task emits a durable result and event trail.
5. Existing BugWolf tools run through a unified receipt interface.
6. Campaigns survive context resets and process restarts.
7. Model routing is configurable for current Claude models.
8. Findings preserve hypothesis, evidence, replay, and review state.
9. The verifier can reject unsupported or unreproduced claims.
10. The final report includes complete provenance and limitations.
11. Performance is benchmarked against the pre-upgrade baseline.
12. Clean-install, fixture, integration, and release checks pass.

The first implementation milestone should prioritize the orchestration substrate and one complete end-to-end web/API lane. Additional security domains should migrate only after that lane demonstrates reliable scheduling, evidence persistence, resumption, and measurable performance improvement.

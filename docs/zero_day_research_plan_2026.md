# BugWolf Zero-Day Research Capability Plan (2026)

**Status:** Architecture and implementation plan  
**Scope:** Isolated research laboratories only  
**Audience:** BugWolf engineering and security-research teams  
**Last researched:** August 2026

> **Operating mode statement**
>
> BugWolf uncensored mode intentionally does not enforce target authorization, scope membership, active-operation confirmation, or destructive-operation confirmation inside the plug-in. It is designed for isolated research environments where the operator provides the execution boundary externally. This mode must not be used as a safety boundary for production systems, third-party targets, or environments containing real credentials or data.

## 1. Objectives and non-goals

### Objectives

Build a reproducible, observable, domain-agnostic zero-day candidate research system that can:

- discover unusual behavior across Web3, Web/API, and AI-agent systems;
- distinguish novelty candidates from duplicates, known issues, and expected behavior;
- preserve complete evidence and payload lineage;
- reproduce candidates from clean state;
- combine static analysis, dynamic testing, stateful fuzzing, differential testing, and formal properties;
- triage crashes, anomalies, economic deviations, and agent action failures;
- produce researcher-reviewable SARIF, JSON, Markdown, HAR, contract-tool, and AI-trace artifacts;
- remain incrementally testable with bounded resources.

### Non-goals

- Guaranteeing discovery of a true zero-day.
- Replacing expert review, disclosure analysis, or legal judgment.
- Adding authorization or scope gates inside the plug-in.
- Running unbounded fuzzing, uncontrolled exploit automation, or unrestricted external infrastructure.
- Treating a model-generated hypothesis as a finding without reproducible evidence.

## 2. 2026 threat-landscape summary

### Web3

The highest-value research surfaces are no longer limited to isolated Solidity functions. Current work must model protocol state, economic invariants, cross-contract composition, cross-chain messaging, upgradeability, and account abstraction.

Important themes:

- Parallel stateful fuzzing is becoming practical. Trail of Bits introduced Medusa v1 in February 2025, emphasizing scalable parallel fuzzing. Echidna remains valuable for property-based testing, while Foundry invariant tests and formal tools such as Halmos provide complementary validation.
- DeFi research must cover oracle freshness and manipulation, flash-loan-assisted state transitions, MEV-sensitive ordering, cross-contract and read-only reentrancy, upgrade/admin paths, and bridge verification.
- ERC-4337-style systems add UserOperation validation, bundlers, paymasters, nonce handling, signature aggregation, sponsorship accounting, and execution-context interactions.
- L2/L3 systems introduce sequencer, forced-inclusion, finality, withdrawal-proof, message-replay, gas-accounting, and cross-domain authorization assumptions.
- Existing open-source tools are strongest on local contract properties and weaker on protocol-wide economic invariants, multi-chain state, and emergent behavior between independently correct contracts.

Relevant 2025–2026 sources:

- Trail of Bits, **Unleashing Medusa: Fast and scalable smart contract fuzzing**, 2025-02-14: <https://blog.trailofbits.com/2025/02/14/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing/>
- Recon, **Smart contract fuzzing tools compared: Echidna, Medusa, Halmos …**, 2025-04-28: <https://getrecon.xyz/blog/smart-contract-fuzzing-tools-compared>
- Ethereum.org, **Medusa**, 2026-07-30: <https://ethereum.org/developers/tools/medusa/>
- Hacken, **Top 10 Smart Contract Vulnerabilities in 2025**, 2025-12-10: <https://hacken.io/discover/smart-contract-vulnerabilities/>
- COW Protocol, **DeFi Security Explained**, 2025-08-07: <https://cow.fi/learn/de-fi-security-explained-from-transactional-threats-to-protocol-vulnerabilities-and-beyond>
- Immunefi, **The Ecosystem Vulnerability Scoreboard**, 2026-04-27: <https://immunefi.com/blog/research/the-ecosystem-vulnerability-scoreboard-6-years-of-defi-loss-data/>
- arXiv, **Blockchain Attacks and Defenses: A Layered and Cross-Domain Survey**, 2026-07-06: <https://arxiv.org/html/2607.06593v1>

### Web/API

Modern APIs are distributed state machines rather than simple request/response endpoints. Zero-day-oriented research should correlate REST, GraphQL, gRPC, WebSocket, tRPC, and edge/serverless behavior with identity, cache, retry, queue, and consistency semantics.

Important themes:

- Protocol state-machine testing matters. The 2025 MadeYouReset HTTP/2 issue demonstrates that stream-reset accounting and implementation assumptions can create availability vulnerabilities even when ordinary request tests pass.
- GraphQL testing should include resolver-level authorization, aliases, batching, recursive queries, introspection differences, persisted queries, and REST/GraphQL policy mismatches.
- Distributed race research requires coordinated requests, retry variation, idempotency-key mutation, queue timing, read-after-write checks, and state snapshots.
- Serverless and edge research should compare cold/warm execution, regional routing, cache keys, signed requests, event retries, streaming, and runtime-specific behavior.
- Supply-chain testing should combine lockfile provenance, dependency graph changes, install-script observation, package behavior, and runtime telemetry.

Relevant sources:

- F5, **CVE-2025-54500 HTTP/2 advisory**, 2025-08-13: <https://my.f5.com/manage/s/article/K000152001>
- Cloudflare, **MadeYouReset: An HTTP/2 vulnerability thwarted by Rapid Reset mitigations**, 2025-08-14: <https://blog.cloudflare.com/madeyoureset-an-http-2-vulnerability-thwarted-by-rapid-reset-mitigations/>
- Akamai, **A Coordinated Response to MadeYouReset HTTP/2 Protocol Attacks**, 2025-08-13: <https://www.akamai.com/blog/security/response-madeyoureset-http2-protocol-attacks>
- NVD, **CVE-2025-8671**, 2025-08-13: <https://nvd.nist.gov/vuln/detail/CVE-2025-8671>
- Jetty, **MadeYouReset security advisory**, 2025-08-20: <https://github.com/jetty/jetty.project/security/advisories/GHSA-mmxm-8w33-wc4h>
- Escape, **Best GraphQL Security Tools in 2026**, 2026-07-16: <https://escape.tech/blog/best-graphql-security-tools/>
- Hive Security, **JWT Attacks, OAuth Abuse, and GraphQL Exploitation**, 2026-05-07: <https://hivesecurity.gitlab.io/blog/api-security-jwt-oauth-graphql-attacks/>
- Phoenix Security, **Supply Chain Attacks 2026: npm, PyPI, VS Code, AI Agents**, 2026-06-02: <https://phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026/>
- NCSC UK, **Software supply chain attacks: check your dependencies**, 2026-06-04: <https://www.ncsc.gov.uk/blogs/software-supply-chain-attacks-check-your-dependencies>

### AI red teaming

Agentic AI expands the tested system from a model to a complete action pipeline: retrieved content, memory, model reasoning, tool selection, tool arguments, side effects, and multi-agent delegation.

Important themes:

- Direct and indirect prompt injection, RAG poisoning, citation manipulation, tool-output injection, memory poisoning, and multi-agent goal hijacking need separate test classes.
- MCP tool descriptions, resource metadata, server responses, and tool registration are part of the attack surface. Tool poisoning must be evaluated as a data-to-action transition, not only as a text-generation failure.
- Model extraction and data poisoning require canary data, output similarity analysis, membership/secret probes, and training/evaluation corpus provenance.
- Automated red-team tools can generate attacks, but BugWolf must retain complete action traces and validate actual tool-side effects.
- The largest open-source gap is end-to-end evidence linking: `input/retrieval -> model output -> selected tool -> arguments -> tool result -> state mutation -> externally observable impact`.

Relevant sources:

- arXiv, **Redefining AI Red Teaming in the Agentic Era: From Weeks to Hours**, 2026-05-05: <https://arxiv.org/html/2605.04019v1>
- Promptfoo, **Top Open Source AI Red-Teaming and Fuzzing Tools in 2025**, 2025-08-14: <https://www.promptfoo.dev/blog/top-5-open-source-ai-red-teaming-tools-2025/>
- CyberDesserts, **Prompt Injection Attacks: Examples and Defences**, 2025-12-22: <https://blog.cyberdesserts.com/prompt-injection-attacks/>
- Airia, **AI Security in 2026: Prompt Injection, the Lethal Trifecta, and How to Defend**, 2026-01-06: <https://airia.com/blog/ai-security-in-2026-prompt-injection-the-lethal-trifecta-and-how-to-defend/>
- Microsoft Security, **Securing AI agents: When AI tools move from reading to acting**, 2026-06-30: <https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/>
- Galileo, **8 Red Teaming Strategies for LLMs and Agents**, 2026-04-19: <https://galileo.ai/blog/llm-red-teaming-strategies>
- General Analysis, **Best AI Red Teaming and Adversarial Testing Tools in 2026**, 2026-05-19: <https://generalanalysis.com/guides/best-ai-red-teaming-tools>
- MDPI, **Prompt Injection Attacks in Large Language Models and AI Agents**, 2026: <https://www.mdpi.com/2078-2489/17/1/54>

## 3. Unified capability architecture

```text
                         ┌──────────────────────────────┐
                         │ Claude Code / Freebuff Agent │
                         └──────────────┬───────────────┘
                                        │ plans / observations
                         ┌──────────────▼───────────────┐
                         │ Deterministic Research Core  │
                         │ schemas · state · scheduling │
                         └───────┬───────────┬───────────┘
                                 │           │
                 ┌───────────────▼───┐   ┌───▼────────────────┐
                 │ Domain adapters    │   │ Shared evidence    │
                 │ Web3 · Web/API · AI│   │ lineage + integrity │
                 └───────┬────────────┘   └───┬────────────────┘
                         │                    │
          ┌──────────────▼──────────────┐     │
          │ Candidate pipeline           │◄────┘
          │ discover → cluster → triage  │
          │ reproduce → validate → report │
          └──────────────┬──────────────┘
                         │
       ┌─────────────────▼─────────────────┐
       │ bounded runners and lab fixtures   │
       │ Foundry/Hardhat · VulnBank · LLM   │
       └────────────────────────────────────┘
```

### 3.1 Shared lifecycle

Every domain emits a common `ResearchCandidate` record:

```text
DISCOVERED
   → NORMALIZED
   → DEDUPLICATED
   → TRIAGED
   → REPRODUCTION_PENDING
   → REPRODUCED
   → NOVELTY_PENDING
   → IMPACT_VALIDATION
   → CONFIRMED

Any state may transition to:
   REJECTED · DUPLICATE · EXPECTED · BLOCKED · INCONCLUSIVE
```

Transitions are deterministic and evidence-based. Model suggestions can add hypotheses, but cannot directly transition a candidate to `CONFIRMED`.

### 3.2 Six capability batches

#### Batch 1: Novelty pipeline

- Normalize candidate identity across domains.
- Compute stable signatures from behavior, stack trace, state delta, tool trace, and payload lineage.
- Correlate against local CVE/advisory datasets and project-known findings.
- Cluster exact and near duplicates.
- Rank novelty, impact, reproducibility, and evidence completeness separately.

#### Batch 2: Differential testing

- Compare baseline and mutation responses, state, logs, gas, events, timing, headers, and tool traces.
- Support identity, role, chain, protocol, version, region, cache, and configuration differentials.
- Require a meaningful behavioral delta before promotion.

#### Batch 3: Stateful fuzzing

- Persist a state model and valid action grammar.
- Generate bounded sequences rather than isolated inputs.
- Track preconditions, transitions, snapshots, and reset points.
- Use domain adapters to translate generic actions to HTTP requests, transactions, or agent/tool calls.

#### Batch 4: Crash and anomaly triage

- Capture process output, stack traces, HTTP/chain/agent traces, and resource state.
- Normalize signatures and deduplicate repeated crashes.
- Minimize sequences and payloads while preserving the signal.
- Distinguish infrastructure failure from target behavior.

#### Batch 5: Candidate validation

- Re-run from clean state.
- Replay exact request/transaction/tool lineage.
- Verify content/behavioral impact, not status codes alone.
- Run negative controls and counterexamples.
- Require configurable repeated reproduction before `CONFIRMED`.

#### Batch 6: Researcher observability

- UUID operation ID on every action.
- Structured JSON operation records.
- Full stdout/stderr and raw evidence references with redacted views.
- Candidate timelines, state transitions, checksums, and environment manifests.
- Search/filter by candidate ID, operation ID, target, fixture, tool, and run.

## 4. Shared infrastructure

### 4.1 Evidence envelope

Create a versioned envelope compatible with existing reliability and evidence modules:

```json
{
  "schema": "bugwolf/research-evidence/v1",
  "candidate_id": "uuid",
  "operation_id": "uuid",
  "domain": "web3|web_api|ai",
  "run_id": "uuid",
  "target": "lab-fixture",
  "environment": {
    "git_revision": "...",
    "runtime": "...",
    "tool_versions": {},
    "fixture_digest": "sha256:..."
  },
  "parent_evidence": ["relative/path"],
  "payload_lineage": [{"id": "...", "parent": "...", "mutation": "..."}],
  "request_or_action": {},
  "response_or_observation": {},
  "state_before": {},
  "state_after": {},
  "behavioral_delta": {},
  "checksums": {},
  "redaction": {"applied": true, "raw_reference": "..."},
  "created_at": "..."
}
```

Raw large artifacts remain in the local workspace. Inline records contain previews, references, sizes, and SHA-256 checksums; they must not silently truncate decisive evidence.

### 4.2 Lineage graph

Implement a small append-only lineage graph:

- node types: `input`, `mutation`, `request`, `transaction`, `tool_call`, `response`, `state_snapshot`, `candidate`;
- directed parent-child edges;
- immutable node IDs and operation IDs;
- payload mutation metadata;
- cycle detection and maximum graph depth;
- graph export to JSON and Markdown.

### 4.3 Reproducibility engine

The engine must record:

- fixture/image digest;
- source revision;
- dependency lockfile digest;
- tool versions and command lines;
- random seeds and scheduler settings;
- initial state snapshot;
- exact action sequence;
- expected and observed outcomes;
- reset procedure.

A reproduction attempt returns `reproduced`, `not_reproduced`, `environment_mismatch`, or `inconclusive` with reasons.

### 4.4 Resource and cancellation controls

Retain and extend the current reliability primitives:

- atomic writes and locked JSONL append;
- UUID operation IDs;
- bounded subprocesses and process-group cleanup;
- per-operation timeout;
- retry ceiling with deterministic backoff;
- output and artifact limits;
- disk-space and per-campaign quota checks;
- bounded worker pools and queue depth;
- maximum chain/state depth;
- cooperative cancellation and cancellation receipts;
- memory/CPU monitoring where supported.

These are operational controls, not authorization gates.

### 4.5 Reporting

Common outputs:

- `candidate.json` and `candidates.jsonl`;
- SARIF 2.1.0 for code/static findings;
- Markdown researcher packet;
- JSON evidence bundle with checksums;
- operation and lineage JSONL;
- failure/minimization report.

Domain outputs:

- Web3: Slither-compatible JSON, Foundry test reproduction, Echidna/Medusa corpus, transaction trace, call trace, event/state diff.
- Web/API: HAR, normalized HTTP trace, OpenAPI/GraphQL schema delta, WebSocket/gRPC transcript, timing/race schedule.
- AI: PyRIT trace, promptfoo result, Garak/Inspect-compatible results, retrieval corpus digest, tool-call trace, memory/state diff.

## 5. Domain-specific modules

## 5.1 Web3 module

### Inputs

- Solidity, Vyper, Move, Cairo/StarkNet, Rust/Solana source and bytecode;
- ABI/IDL, deployment metadata, proxy/implementation relationships;
- local chain snapshots and fork configuration;
- protocol roles, prices, oracles, bridges, sequencers, and governance actors.

### Integrate/wrap

- Slither for static analysis and detector output.
- Aderyn for complementary Rust-based Solidity analysis.
- Echidna for property-based fuzzing.
- Medusa for parallel stateful fuzzing.
- Foundry fuzzing, invariant tests, traces, and fork tests.
- Halmos or equivalent symbolic/formal checks where available.
- Mythril selectively for legacy symbolic analysis and comparison.
- Hardhat/Foundry local fixtures and Anvil-style forks.

### Build in BugWolf

1. **Protocol state model**
   - balances, shares, debt, collateral, prices, roles, pause states, upgrades, bridge messages;
   - valid transaction grammar;
   - reset/snapshot strategy.

2. **Economic invariant runner**
   - conservation and solvency;
   - share-price and exchange-rate bounds;
   - oracle freshness/deviation;
   - liquidation and collateralization constraints;
   - fee and accounting consistency;
   - cross-domain message uniqueness and replay resistance.

3. **Sequence generator**
   - flash-loan-like atomic action sequences in local fixtures;
   - donation/inflation and rounding sequences;
   - callback/reentrancy variants;
   - governance/upgrade sequences;
   - MEV/order permutations;
   - bridge message delay/replay permutations.

4. **Cross-implementation differential runner**
   - Solidity/Vyper/Rust/Cairo implementations of equivalent properties;
   - L1 versus L2 behavior;
   - proxy implementation versions;
   - oracle/provider configurations.

5. **Trace normalizer**
   - calls, storage writes, events, revert reasons, gas, balances, and emitted messages;
   - stable signatures for unexpected effects.

### Candidate validation

A Web3 candidate requires:

- deterministic transaction sequence;
- clean snapshot reproduction;
- state/economic delta;
- invariant violation or unauthorized state effect;
- minimized sequence;
- comparison against expected protocol behavior;
- known-issue correlation and duplicate clustering.

## 5.2 Web/API module

### Inputs

- OpenAPI, GraphQL schemas, protobuf/gRPC descriptors, WebSocket captures, HAR files;
- recon output and observed endpoint inventory;
- role/session fixtures and synthetic identities;
- deployment/runtime metadata.

### Integrate/wrap

- Existing BugWolf live executor and recon pipeline.
- Schema-driven generators for OpenAPI, GraphQL, protobuf, and WebSocket actions.
- HTTP/2 and HTTP/3-capable test clients in isolated fixtures.
- Existing API fuzzing and crawling tools only through bounded adapters.
- Dependency scanners and lockfile/provenance analyzers.

### Build in BugWolf

1. **Unified API surface graph**
   - correlate REST paths, GraphQL fields/resolvers, gRPC methods, WebSocket messages, and frontend references;
   - link identity and authorization context to each action.

2. **Behavioral oracle**
   - baseline response, content structure, headers, timing, state changes, events, queue effects, and cache behavior;
   - status code is only one signal.

3. **Stateful workflow fuzzer**
   - login/session refresh;
   - create/read/update/delete workflows;
   - payment/order/approval transitions;
   - asynchronous job polling and webhook callbacks;
   - idempotency and retry sequences.

4. **Race and consistency runner**
   - coordinated request schedules;
   - duplicate submissions;
   - conflicting updates;
   - delayed reads and queue retries;
   - cache invalidation and regional differences.

5. **Protocol differential runner**
   - HTTP/1.1 versus HTTP/2 versus HTTP/3;
   - compressed headers and stream lifecycle fixtures;
   - proxy/origin differences;
   - serverless cold/warm and edge-region comparisons.

6. **Supply-chain behavior analyzer**
   - lockfile and package provenance snapshot;
   - install-script observation in disposable environments;
   - runtime network/process/file behavior;
   - dependency update differential.

### Candidate validation

Require a complete normalized trace and a meaningful behavioral or state delta, then reproduce with:

- same role and clean state;
- alternate role or negative control;
- repeated schedule where timing matters;
- server logs or fixture state confirmation;
- minimized request sequence.

## 5.3 AI red-teaming module

### Inputs

- model/provider metadata;
- system/developer prompts under test;
- tool schemas and MCP server manifests;
- RAG corpora, indexes, retriever configuration, and memory stores;
- agent workflow graph and side-effect adapters.

### Integrate/wrap

- PyRIT for orchestrated attack strategies and traces.
- Garak for detector/probe coverage.
- Promptfoo for repeatable assertions and CI-style evaluation.
- Inspect and DeepTeam where their adapters fit the lab.
- Dreadnode-style agentic workflow concepts for multi-step testing.

### Build in BugWolf

1. **Context-source fuzzer**
   - direct prompts;
   - retrieved documents;
   - tool results;
   - MCP descriptions/resources;
   - memory entries;
   - multi-agent messages.

2. **Action-trace evaluator**
   - classify model output;
   - validate selected tool and arguments;
   - observe tool result and side effect;
   - compare intended policy with actual transition;
   - detect unauthorized or unsafe state changes in the fixture.

3. **Memory/RAG poisoning harness**
   - inject labeled canary documents;
   - vary ranking, metadata, citations, and chunk boundaries;
   - test persistence across sessions;
   - measure retrieval and action influence.

4. **MCP protocol tester**
   - tool-description mutation;
   - resource metadata mutation;
   - malformed schema and output tests;
   - tool result injection;
   - server restart and version differential;
   - confused-deputy and cross-tool composition scenarios.

5. **Model/data integrity checks**
   - model and adapter digest verification;
   - dataset/provenance manifest;
   - canary secret leakage probes;
   - output similarity and extraction indicators;
   - poisoned fine-tune regression suite.

### Candidate validation

An AI candidate requires:

- complete prompt/context/tool/memory trace;
- deterministic or statistically significant reproduction;
- actual policy-relevant action or data exposure in the lab fixture;
- negative controls and benign-context comparison;
- model/version/environment metadata;
- evaluator agreement or explicit uncertainty.

## 6. Phased implementation roadmap

Effort estimates assume one engineer familiar with the repository and one researcher contributing fixtures/review. They are approximate engineering weeks, not calendar guarantees.

### Phase 1 — Foundation and novelty pipeline

**Estimated effort:** 3–5 weeks  
**Dependencies:** Existing reliability/evidence/state modules  
**Deliverables:**

- versioned evidence envelope;
- candidate schema and lifecycle state machine;
- lineage graph and payload IDs;
- novelty signature and exact/near-duplicate clustering;
- local advisory/CVE correlation interface;
- reproducibility manifest;
- SARIF/JSON/Markdown exporters;
- migration support for existing findings/exploit records;
- operation dashboard/query CLI.

**Test strategy:**

- schema validation and legacy migration fixtures;
- duplicate/near-duplicate golden cases;
- lineage cycle/depth tests;
- atomic/locked concurrent writes;
- checksum and corruption recovery;
- deterministic signature tests;
- cancellation and quota tests.

### Phase 2 — Web/API module

**Estimated effort:** 4–6 weeks  
**Dependencies:** Phase 1; existing live executor and VulnBank  
**Deliverables:**

- unified API surface graph;
- OpenAPI/GraphQL/gRPC/WebSocket adapters;
- behavioral oracle and baseline/mutation evidence;
- stateful workflow and race scheduler;
- HTTP/2/HTTP/3 differential fixtures;
- serverless/edge simulation fixtures;
- dependency behavior analyzer;
- HAR and normalized protocol reports.

**Test strategy:**

- extend VulnBank with GraphQL, WebSocket, race, queue, cache, and HTTP/2 fixtures;
- deterministic request-sequence replay;
- clean-state reset between candidates;
- known-vulnerability regression cases;
- false-positive corpus for expected status/content changes;
- bounded load/race schedules.

### Phase 3 — Web3 module

**Estimated effort:** 5–8 weeks  
**Dependencies:** Phase 1; Foundry/Hardhat fixture toolchain  
**Deliverables:**

- contract-source/ABI/bytecode ingestion;
- Slither/Aderyn/Echidna/Medusa/Foundry adapters;
- local invariant and state-model framework;
- transaction sequence generation and minimization;
- trace/state/economic-delta normalization;
- L1/L2 bridge and account-abstraction fixtures;
- contract-tool report converters.

**Test strategy:**

- local Hardhat/Foundry projects with intentionally vulnerable and safe contracts;
- ERC-4337-style UserOperation fixtures;
- oracle, flash-loan, reentrancy, upgrade, bridge, and replay scenarios;
- L1/L2 message and finality fixtures;
- deterministic fuzz seeds and minimized counterexamples;
- differential tests across compiler/tool versions.

### Phase 4 — AI red teaming module

**Estimated effort:** 5–8 weeks  
**Dependencies:** Phase 1; local model and tool sandbox  
**Deliverables:**

- PyRIT/Garak/Promptfoo/Inspect adapters;
- context-source and indirect-injection generators;
- RAG/memory poisoning fixture;
- MCP/tool-description and result tester;
- action-trace evaluator;
- model/data digest and leakage checks;
- PyRIT-compatible traces and AI researcher reports.

**Test strategy:**

- local deterministic or pinned model sandbox;
- fake tools with observable side effects;
- poisoned and benign retrieval corpora;
- MCP fixture servers;
- multi-agent delegation fixture;
- evaluator agreement and repeatability tests;
- no real secrets or external side effects.

### Phase 5 — Cross-domain correlation

**Estimated effort:** 4–6 weeks  
**Dependencies:** Phases 1–4  
**Deliverables:**

- common candidate graph across domains;
- AI agent → Web/API → Web3 transaction correlation;
- shared identity/session/wallet lineage;
- cross-domain impact chain model;
- campaign-level evidence and report synthesis;
- cross-domain duplicate and novelty ranking.

**Test strategy:**

- local dApp with API and agent controller;
- agent tool invokes API that submits local-chain transaction;
- injected retrieval content changes tool arguments;
- API race changes contract state;
- complete lineage from document to transaction and final state;
- negative controls for benign agent behavior.

## 7. Tool integration matrix

| Capability | Wrap/integrate | Build in BugWolf | Initial phase |
|---|---|---|---|
| Static Solidity analysis | Slither, Aderyn | Result normalization and candidate correlation | 3 |
| Property/state fuzzing | Echidna, Medusa, Foundry | Campaign scheduler, seeds, lineage, minimization | 3 |
| Symbolic/formal checks | Halmos, Mythril selectively | Property registry and dynamic confirmation | 3 |
| EVM fixtures | Foundry, Hardhat, Anvil-style local nodes | Fixture lifecycle and trace adapter | 3 |
| OpenAPI testing | Existing schema tooling | Unified surface graph and stateful workflows | 2 |
| GraphQL testing | Schema introspection/parsers | Resolver/alias/batch differential model | 2 |
| gRPC/WebSocket | Protocol clients | Cross-protocol behavioral oracle | 2 |
| HTTP/2/HTTP/3 | Capable local test clients | Stream-state differential fixtures | 2 |
| Dependency analysis | npm/PyPI/cargo metadata/scanners | Behavioral install sandbox and provenance | 2 |
| LLM attack generation | PyRIT, Garak, Promptfoo | Common candidate/evidence adapter | 4 |
| Agent evaluation | Inspect, DeepTeam | Action-trace and side-effect validator | 4 |
| MCP testing | MCP client/server tooling | Tool metadata/result mutation harness | 4 |
| Novelty correlation | NVD/advisory feeds and local corpora | Versioned normalization, signatures, clustering | 1 |
| Reporting | SARIF/JSON/Markdown/HAR serializers | Cross-domain report composition | 1 |

### Integration rules

- Pin tool versions in fixture manifests.
- Execute tools only through bounded subprocess wrappers.
- Capture command, stdout, stderr, exit code, duration, resource usage, and artifact checksums.
- Treat tool output as untrusted data and validate it before processing.
- Never allow a third-party tool to directly mutate campaign state without an adapter.
- Keep integrations optional so the core test suite runs without every external binary installed.

## 8. Test and fixture strategy

### Repository test layers

1. **Unit tests:** schemas, signatures, parsers, minimizers, state transitions, serializers.
2. **Component tests:** each adapter against deterministic fake output and local fixtures.
3. **Integration tests:** real local tools where installed, skipped with explicit diagnostics otherwise.
4. **End-to-end tests:** complete candidate lifecycle from discovery to report.
5. **Regression corpus:** known expected behavior, known vulnerabilities, duplicates, crashes, and rejected candidates.
6. **Reliability tests:** timeout, cancellation, corruption, concurrent writers, disk quota, output cap, restart/resume.

### Web fixture

Extend local VulnBank with:

- REST and GraphQL equivalents;
- role/session differences;
- idempotency and race-sensitive endpoints;
- asynchronous queue and webhook behavior;
- cache-key and protocol variants;
- intentional state and content anomalies;
- safe HTTP/2/HTTP/3 local protocol cases.

### Web3 fixture

Create local Foundry/Hardhat projects containing:

- oracle and stale-price variants;
- flash-loan-like atomic accounting;
- reentrancy and read-only reentrancy;
- upgrade and initialization mistakes;
- bridge message replay and domain confusion;
- ERC-4337-style validation/paymaster behavior;
- L2 message and withdrawal simulations;
- safe controls with equivalent interfaces.

### AI fixture

Create a local model/tool sandbox containing:

- pinned model or deterministic fake model;
- RAG corpus with benign and poisoned documents;
- fake MCP servers and tool descriptions;
- tools with observable but harmless state changes;
- memory store with session boundaries;
- multi-agent delegation graph;
- evaluator fixtures with expected labels.

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Unrestricted execution escapes the lab | External network/process boundary, disposable fixtures, no real credentials, isolated workspace |
| False zero-day claims | Separate candidate from confirmed finding; require reproducibility, novelty correlation, and expert review |
| Model hallucinated payloads | Validate all model JSON; deterministic scheduler; payload lineage; no direct model state transitions |
| Prompt injection changes orchestration | Treat project files, tool output, web content, and retrieved data as untrusted; deterministic core owns transitions |
| Fuzzing exhausts resources | Timeouts, bounded queues/pools, output/artifact caps, quotas, cancellation, disk checks |
| Large evidence is lost | Store raw local artifacts with references and checksums; retain previews only inline |
| Tool output parser compromise | Strict schemas, size limits, subprocess isolation, defensive parsing |
| Duplicate or looping chains | Stable candidate signatures, deduplication, maximum chain depth, visited-set tracking |
| State corruption | Atomic writes, file locks, checksums, append-only recovery, schema migration |
| Timing-only false positives | Repeat schedules, negative controls, fixture logs, state confirmation, statistical thresholds |
| Known issue mislabeled as novel | Local advisory/CVE/project corpus correlation and explicit `KNOWN_OR_DUPLICATE` states |
| Economic exploit overclaim | Local economic invariant and balance/state delta evidence; no status-only conclusions |
| AI privacy leakage | Synthetic canaries, redacted views, raw artifacts confined to disposable workspace |
| Supply-chain contamination | Pinned dependencies, disposable install environment, provenance and digest verification |
| Legal/ethical misuse | Document isolated-lab-only operation; external operator boundary; prohibit production/third-party use |

## 10. Definition of done

A phase is complete only when:

- its schemas and state transitions are documented;
- its adapters are optional and bounded;
- its fixtures include positive, negative, duplicate, and inconclusive cases;
- candidate evidence is complete, checksummed, and replayable;
- restart/resume and cancellation are tested;
- full relevant tests pass;
- reports are generated in the required formats;
- no model output can bypass deterministic validation;
- documentation states the uncensored operating boundary accurately.

The overall program is ready for controlled lab beta when all five phases have independently passing fixture suites and at least one cross-domain candidate can be traced end to end without missing lineage or unverifiable claims.

## 11. Recommended first implementation slice

Start with Phase 1 and keep it independent from live execution behavior:

1. Add `ResearchCandidate`, `EvidenceEnvelope`, and `LineageNode` schemas.
2. Add lifecycle transition validation and migration for existing findings/exploit records.
3. Add stable signatures, exact duplicate detection, and a small near-duplicate similarity layer.
4. Add advisory-correlation provider interfaces with a local fixture database first.
5. Add reproducibility manifests and report serializers.
6. Add tests before integrating domain tools.

This creates the evidence and novelty foundation needed to judge whether Web3, API, or AI anomalies are genuinely new, reproducible, and impactful—without weakening the current uncensored execution semantics or reliability primitives.

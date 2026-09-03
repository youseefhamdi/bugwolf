# BugWolf Private Cybersecurity Lab Upgrade Plan

**Version:** 1.0  
**Status:** Proposed  
**Scope:** Private, isolated cybersecurity laboratory  
**Operating model:** Unrestricted execution inside an externally contained lab environment  
**Current release baseline:** `1.2.11`

## 1. Objective

Upgrade BugWolf from an experimental, human-supervised research engine into a stronger private-lab platform for high-coverage vulnerability research and potentially novel vulnerability discovery.

The upgrade does **not** add target-authorization gates inside the plugin. The lab boundary remains external and is responsible for containment, network isolation, disposable credentials, resource limits, and cleanup.

The goal is not to guarantee zero-day discovery. The goal is to improve:

- vulnerability coverage
- signal quality
- reproducibility
- stateful testing
- cross-domain chaining
- model effectiveness
- novelty assessment
- lab realism
- measurable research progress

## 2. Design principles

1. **Maximum LLM research freedom inside the lab.**
2. **No authorization or scope gates in the private-lab execution profile.**
3. **Containment belongs to the lab infrastructure, not the plugin.**
4. **Deterministic code owns evidence, state, and verdicts.**
5. **LLM reasoning generates hypotheses and strategies, not proof.**
6. **Every candidate remains traceable to source, input, operation, and evidence.**
7. **Potentially novel is never automatically labeled a zero-day.**
8. **Every capability must have a local fixture or reproducible test.**
9. **Research depth should be measured rather than assumed.**
10. **Failed or blocked research must remain visible and reusable.**

## 3. Target architecture

```text
Private Lab Infrastructure
├── Isolated VM/container network
├── Vulnerable Web/API applications
├── Multi-tenant identity fixtures
├── OAuth/OIDC/SAML identity provider fixtures
├── Browser and mobile automation fixtures
├── Smart-contract node/fork and protocol fixtures
├── Mock cloud/IAM/storage services
├── LLM/RAG/MCP tool fixtures
├── Native parser and binary fixtures
├── Disposable databases and queues
└── Evidence and telemetry storage

BugWolf Research Engine
├── Harness contract and campaign workflow
├── Asset and surface discovery
├── Domain analyzers
├── Stateful research threads
├── Mutation and differential schedulers
├── Live executor and fuzz bridge
├── Observation/oracle layer
├── Candidate lifecycle and novelty engine
├── Chain and impact analysis
├── Model routing and pass@k evaluation
├── Evidence/custody/persistence
└── Reporting and benchmark evaluation
```

## 4. Workstreams

### Workstream A: Lab containment and lifecycle

**Purpose:** Provide a reliable external boundary for unrestricted execution.

Deliverables:

- Disposable lab network profile
- VM/container lifecycle manager
- Per-campaign filesystem workspace
- Automatic fixture startup and teardown
- Network topology manifest
- Resource quotas for CPU, memory, disk, and request volume
- Disposable credentials and reset scripts
- Lab health checks
- Emergency process termination and workspace cleanup
- No route from the lab network to production networks by default

Acceptance criteria:

- A campaign can be created, reset, and destroyed deterministically.
- Fixtures are reachable only through declared lab interfaces.
- A failed campaign cannot leave long-running processes behind.
- Cleanup is tested after success, timeout, and exception paths.

### Workstream B: Realistic vulnerable application fixtures

**Purpose:** Improve runtime validation and reduce dependence on synthetic one-request examples.

Fixtures to add:

- Multi-tenant SaaS application
- Admin/user/support role hierarchy
- File upload and import/export workflows
- Password reset and email-change flows
- OAuth/OIDC provider and relying-party pair
- GraphQL API with node IDs, batching, aliases, and field-level authorization
- WebSocket application with authorization boundaries
- Payment, coupon, refund, and idempotency workflows
- CI/CD dashboard and artifact service
- Mock cloud metadata and storage services
- RAG application with tenant-separated memory
- MCP server with OAuth scopes and tool metadata

Each fixture should provide:

- Docker/VM startup configuration
- seeded test accounts
- reset mechanism
- known vulnerability manifest
- negative-control cases
- OpenAPI/GraphQL/schema artifacts
- expected evidence shape
- benchmark task definitions

Acceptance criteria:

- Every major BugWolf domain has at least one stateful local fixture.
- Each fixture includes both vulnerable and safe variants.
- Regression tests verify that known vulnerabilities remain detectable.

### Workstream C: Stateful browser and identity testing

**Purpose:** Cover vulnerabilities that cannot be validated with raw HTTP alone.

Deliverables:

- Browser automation adapter
- Persistent browser session abstraction
- Two-account and multi-role workflow runner
- OAuth/OIDC authorization-code flow runner
- PKCE/state/redirect URI test harness
- Email inbox fixture
- Password-reset token fixture
- Session rotation and cookie observation
- CSRF and browser-origin checks
- Screenshot and DOM evidence capture

Acceptance criteria:

- A complete login → action → logout → reset workflow is replayable.
- Account A/B ownership tests run automatically against fixture data.
- OAuth findings include authorization request, callback, token, and session evidence.

### Workstream D: Smart-contract and DeFi validation

**Purpose:** Expand from static/local sequence analysis to protocol-level economic testing.

Deliverables:

- Foundry/Anvil fixture integration
- Chain snapshot and reset support
- Multi-account protocol harness
- Invariant and state-transition registry
- Reentrancy and callback fixtures
- Oracle manipulation fixture
- Flash-loan simulation fixture
- Share-price/inflation attack fixture
- Governance and role-transition fixture
- Token-decimal and rounding differential tests
- Gas/resource exhaustion tests
- Minimized transaction-sequence reproducers

Acceptance criteria:

- A failing invariant produces a minimal reproducible transaction sequence.
- State snapshots can be restored before each candidate.
- Economic impact is calculated from fixture balances and protocol state.
- Static findings are not marked confirmed without executable local evidence.

### Workstream E: Mobile and native analysis

**Purpose:** Add runtime validation for Android, iOS, and native parsers.

Deliverables:

- Android emulator fixture
- iOS analysis/import boundary where available
- APK/IPA artifact ingestion
- Deep-link automation
- Exported component tests
- PendingIntent tests
- WebView bridge tests
- Local storage and backup analysis
- Native parser fuzzing adapter
- Crash corpus and minimization support
- Symbol, stack, and artifact provenance tracking

Acceptance criteria:

- Mobile static findings can be connected to an executable emulator test where applicable.
- Native crashes are deduplicated by stable signatures.
- Crash inputs are minimized and stored with reproducible metadata.

### Workstream F: LLM, RAG, and MCP laboratory

**Purpose:** Test agentic security behavior under controlled conditions.

Deliverables:

- Local model adapter abstraction
- Prompt and system-context fixture registry
- RAG corpus with tenant boundaries
- Memory persistence and expiry fixture
- MCP server fixture with configurable OAuth scopes
- Tool argument authorization matrix
- Indirect prompt-injection corpus
- Model-output-to-action harness
- Plan-drift and excessive-agency tests
- Data-exfiltration canaries
- Model pass@k and consistency measurements

Acceptance criteria:

- Prompt injection is only considered impactful when it crosses a real data/tool boundary.
- Tool calls are recorded with arguments, identity, authorization context, and result.
- RAG and memory tests prove or disprove cross-tenant access using fixture accounts.
- Model behavior is reproducible enough to compare runs statistically.

### Workstream G: Research coverage and mutation intelligence

**Purpose:** Increase the number of meaningful paths explored per campaign.

Deliverables:

- Unified surface model for HTTP, browser, GraphQL, WebSocket, mobile, cloud, and contracts
- State-machine extraction from fixtures and observed workflows
- Coverage counters for endpoints, parameters, roles, states, transitions, and sinks
- Mutation lineage tracking
- Adaptive mutation selection
- Differential testing across versions, roles, methods, and protocols
- Failure-learning feedback loop
- Blocker and bypass corpus
- Cross-domain chain proposals
- Research budget allocation by information gain

Acceptance criteria:

- Every probe has a stable mutation and lineage identifier.
- Coverage reports show tested and untested dimensions.
- Repeated campaigns avoid exact duplicates while preserving new variants.
- Blocked paths create actionable follow-up research units.

### Workstream H: Novelty and knowledge system

**Purpose:** Improve potentially novel vulnerability identification without overclaiming.

Deliverables:

- Local disclosed-finding corpus
- Advisory/CVE/GHSA ingestion with provenance
- Near-duplicate clustering
- Behavior-based candidate signatures
- Cross-campaign candidate comparison
- Research-source quality scoring
- Version-aware novelty analysis
- Human review queue
- Candidate lineage visualization
- Explicit distinction between:
  - known pattern
  - likely variant
  - behaviorally distinct candidate
  - potentially novel
  - human-reviewed novel finding

Acceptance criteria:

- Novelty decisions include source references and similarity explanations.
- No candidate is labeled zero-day automatically.
- Repeated intake is idempotent.
- Near matches remain visible as variants instead of being silently discarded.

### Workstream I: Evidence and reproducibility

**Purpose:** Make every important result replayable and auditable.

Deliverables:

- Unified evidence schema across all domains
- Request/response/trace/transaction/browser evidence adapters
- Raw-vs-redacted evidence separation
- Evidence encryption for raw artifacts
- Hash-linked manifests
- Replay fixture generation
- Exact environment/fixture version capture
- Deterministic reset-before-replay support
- Evidence retention and cleanup policy
- Evidence export validator

Acceptance criteria:

- A confirmed candidate can be replayed from a clean fixture state.
- Evidence includes enough context to reproduce the result.
- Sensitive values are excluded from reports and model prompts unless explicitly required by the lab workflow.
- Tampered evidence fails verification.

### Workstream J: Model performance and orchestration

**Purpose:** Measure and improve LLM effectiveness instead of relying on qualitative impressions.

Deliverables:

- Model router telemetry
- Pass@k campaign execution
- Per-domain model comparison
- Prompt/version lineage
- Tool-call success/failure statistics
- False-positive and false-negative benchmark labels
- Human-review outcome ingestion
- Cost/time/token metrics
- Context-size and truncation telemetry
- Automatic research-unit prioritization

Metrics:

- vulnerable cases found
- safe cases correctly rejected
- confirmed finding precision
- candidate recall
- mean time to reproducible evidence
- mean time to impact validation
- duplicate rate
- unresolved hypothesis rate
- coverage per unit budget
- pass@k improvement

Acceptance criteria:

- Every campaign produces machine-readable evaluation metrics.
- Model changes can be compared against a fixed benchmark corpus.
- Prompt or tool changes are traceable to performance changes.

### Workstream K: Packaging, release, and operational quality

**Purpose:** Make private-lab deployments repeatable.

Deliverables:

- Reproducible release bundles
- Dependency and environment manifest
- SBOM generation
- Clean-install smoke test
- Fixture compatibility matrix
- Versioned benchmark corpus
- Automatic dependency graph generation
- Documentation consistency checks
- Migration tooling for state schemas
- Upgrade and rollback procedures

Acceptance criteria:

- A new lab host can install and run the benchmark from a clean workspace.
- Bundle contents, version, and generated documentation agree.
- State migrations are tested against representative historical artifacts.

## 5. Proposed implementation phases

### Phase 1: Foundation and containment

Focus:

- external lab lifecycle
- reset/teardown
- resource accounting
- unified evidence schema
- dependency-map generation
- documentation cleanup

Exit criteria:

- disposable campaign environment works end-to-end
- all operations have stable IDs
- evidence and state can be reset and verified

### Phase 2: Stateful Web/API laboratory

Focus:

- multi-tenant fixture
- browser workflows
- OAuth/OIDC
- GraphQL
- WebSocket
- file and payment workflows

Exit criteria:

- authenticated two-account testing works
- browser and HTTP evidence are joined
- known Web/API benchmark cases pass

### Phase 3: Research coverage engine

Focus:

- unified surface model
- state-machine extraction
- mutation lineage
- adaptive scheduling
- differential testing
- blocker learning

Exit criteria:

- coverage gaps are explicit
- repeated runs explore new variants
- blocked probes produce useful next units

### Phase 4: Smart-contract and cloud expansion

Focus:

- Foundry/Anvil fixtures
- DeFi invariants
- IAM graph execution against mocks
- cloud metadata/storage fixtures
- CI/CD artifact and workflow fixtures

Exit criteria:

- economic and cloud findings have local proof paths
- sequence minimization is reliable
- chain impacts are measurable

### Phase 5: LLM/agentic laboratory

Focus:

- RAG and memory fixtures
- MCP OAuth/tool fixtures
- indirect prompt injection
- model-output action boundaries
- pass@k measurements

Exit criteria:

- agentic findings require demonstrated boundary impact
- tool calls and data flows are fully recorded
- model performance is benchmarked

### Phase 6: Mobile/native and novelty system

Focus:

- emulator integration
- native parser fuzzing
- local knowledge corpus
- near-duplicate clustering
- human novelty review

Exit criteria:

- mobile/native candidates have reproducible evidence where supported
- novelty reports explain why a candidate differs from known findings
- no automatic zero-day claims are emitted

### Phase 7: Release hardening

Focus:

- full regression suite
- fixture matrix
- bundle validation
- migration tests
- performance baselines
- operator runbooks

Exit criteria:

- clean installation passes
- benchmark regression passes
- all supported lab profiles are documented
- release status can be upgraded from experimental only after review

## 6. Benchmark expansion

Create a versioned benchmark corpus containing:

- vulnerable Web/API cases
- negative controls
- authorization and IDOR cases
- OAuth/ATO cases
- GraphQL cases
- race-condition cases
- cache/proxy cases
- CI/CD cases
- cloud/IAM cases
- smart-contract invariant cases
- DeFi economic cases
- mobile cases
- LLM/RAG/MCP cases
- native crash cases
- multi-step chains

Each benchmark case should define:

```json
{
  "case_id": "stable-id",
  "domain": "web_api",
  "fixture": "fixture-name",
  "bug_class": "idor",
  "difficulty": "medium",
  "expected_surface": ["endpoint", "role", "object"],
  "expected_evidence": ["request", "response", "account_a", "account_b"],
  "expected_impact": "cross-tenant data access",
  "known_answer": "vulnerable",
  "negative_control": false
}
```

Required benchmark reports:

- precision
- recall
- pass@1/pass@k
- time to signal
- time to confirmation
- duplicate rate
- coverage achieved
- unresolved leads
- false-positive classes

## 7. Success definition

The upgrade is successful when BugWolf can run inside a disposable private lab and:

1. map a complete fixture surface;
2. exercise anonymous, authenticated, privileged, and service identities;
3. test state transitions and cross-domain chains;
4. produce deterministic, replayable evidence;
5. distinguish signals from confirmed impact;
6. avoid repeating exact prior work;
7. identify behaviorally distinct candidates against a local knowledge corpus;
8. quantify model and tool performance;
9. recover cleanly from failed operations;
10. preserve all provenance needed for human review.

## 8. Non-goals

This plan does not promise:

- guaranteed zero-day discovery;
- complete vulnerability coverage;
- autonomous correctness;
- automatic novelty certification;
- safe operation outside the isolated lab;
- production authorization enforcement inside the unrestricted plugin;
- replacement of expert security review.

## 9. Immediate next actions

1. Add a disposable multi-tenant Web/API fixture with two accounts and an OAuth provider.
2. Define the unified evidence schema and migration adapters.
3. Build a fixture lifecycle/reset command.
4. Add coverage counters for endpoints, roles, parameters, and state transitions.
5. Extend the benchmark manifest with Web/API, GraphQL, OAuth, cloud, and contract cases.
6. Generate the dependency graph automatically from AST imports.
7. Add raw-evidence encryption and explicit redacted-export validation.
8. Add pass@k campaign metrics to the self-evaluation harness.
9. Create a local disclosed-finding corpus and behavior-based near-duplicate index.
10. Run the complete upgrade against the deterministic stub target (`tests/_stub_target.py`) before adding external lab fixtures.

## 10. Final readiness target

The desired end state is:

```text
Private lab platform
+ unrestricted in-lab execution
+ realistic stateful fixtures
+ broad domain analyzers
+ deterministic evidence
+ coverage-guided research
+ reproducible impact validation
+ novelty comparison
+ measurable model performance
+ human-reviewed conclusions
```

This should be described as a **high-coverage private-lab vulnerability research platform**, not as a guaranteed zero-day discovery system.

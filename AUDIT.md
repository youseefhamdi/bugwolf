# BugWolf v1.0.0 — Full Audit, Capability & Structure Map

> Report generated from a full repository audit. Repo state: `main` @ `49bc657`
> ("feat: self-driven campaign orchestration engine", Aug 23 2026).
> Audit date: 2026-08-26.

---

## Executive Summary

BugWolf is an "all-round bug bounty hunter" security-research skill/plugin
distributed as a Claude Code skill, a Claude.ai `.skill` file, and a
Freebuff/Codebuff bundle. It is a **harness-neutral orchestration platform**:
the model (any harness) provides the reasoning, and ~74 deterministic Python
tools provide recon, discovery, hunting, validation, chain-building, reporting,
and defensive analysis.

**Scale:** 74 Python tools + 1 shell engine · 53 reference docs · 22
hacking-agent guides · 8 attack-vector catalogs · 43 test modules (515 tests) ·
5 config files · 3 install/build scripts · 12+ runtime state directories.

**Critical issue (unchanged from earlier audit):** the latest commit
(`49bc657`) stripped the authorization/safety enforcement layer from 13+
tools ("UNCENSORED" pass-through stubs) while documentation, harness contracts,
and parts of the test suite still describe a gated tool. The test suite is
broken (1 import error + 27 failures) and internally contradictory. See
**Section 9**.

---

## 1. Multi-Harness Support Map

BugWolf is harness-neutral by design: instead of relying on model memory of a
long skill prompt, it installs a short project-local contract into the target
project and reloads it after every context compaction or agent handoff.

| Harness | Install path / method | Contract files loaded | Native support |
|---|---|---|---|
| **Claude Code** | `~/.claude/skills/bugwolf` or `npx skills add youseefhamdi/bugwolf --skill bugwolf --copy` | `CLAUDE.md`, `AGENTS.md`, `BUGWOLF.md` | Native skills load at startup; code-execution enables local tooling (nmap/ffuf/sqlmap orchestration) |
| **Freebuff / Codebuff** | `.agents/skills/bugwolf/` (npx skills, `scripts/install_freebuff.sh`, or unzip of `dist/*.freebuff.zip`) | `AGENTS.md`, `BUGWOLF.md` + `configs/freebuff-deepseek.json` runtime profile | Native `.agents/skills/` loader; ships a DeepSeek operating contract (exact CLI lines, mandatory `--json`) |
| **Claude.ai (web/app)** | Upload `dist/*.skill` via Customize → Skills; enable code execution | `SKILL.md` + `BUGWOLF.md` | Partial (no local tooling unless code execution enabled) |
| **Codex / Cursor / Windsurf / Copilot** | Manual copy of `configs/harness/BUGWOLF.md` + `AGENTS.md` into project root | `AGENTS.md`, `BUGWOLF.md` | Loads via project-instruction files; **no install script targets their native rule files** (`.cursor/rules/*.mdc`, `.windsurfrules`, `.github/copilot-instructions.md` are named in the pre-strip guard's `INSTRUCTION_NAMES` but never installed — see Finding 2) |
| **DeepSeek (model)** | Via Claude CLI env vars (`ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic`, `ANTHROPIC_MODEL=deepseek-v4-pro`) | `configs/freebuff-deepseek.json` | Freebuff default model is DeepSeek V4 Flash; profile documents gates + toolchain self-test |

### Harness machinery ("the multi-harness glue")

| Component | Role |
|---|---|
| `tools/harness_guard.py` | Offline contract verifier every session must run (`--verify --json`); docs say stop on `ready: false`. *(stripped at HEAD — always ready)* |
| `tools/harness_command.py` | Parses direct conversational invocations (`bugwolf --full attack this target https://X`) into **non-executing** plans; never runs anything itself |
| `tools/harness_intelligence.py` + `configs/harness/intelligence.json` | Offline "creative reasoning" brief (11 exploration angles, 7 evidence states, stop conditions, handoff fields) for consistency across model hosts |
| `scripts/install_harness_contract.sh` | Installs contract into any project from a source checkout |
| `scripts/install_freebuff.sh` | Installs `.agents/skills/bugwolf/` layout (offline, CLI-free) |
| `scripts/build_skill.sh` | Builds both `dist/*.skill` (Claude.ai) and `dist/*.freebuff.zip` (Freebuff/Codebuff) |

---

## 2. Complete File Structure

```
bugwolf/  (repo root)
├── SKILL.md                     # Main orchestrator / skill prompt (harness entry point)
├── README.md                    # Usage, install, flags, collaboration credits
├── CHANGELOG.md                 # Release notes (Unreleased + v1.0.0)
├── VERSION                      # 1.0.0
├── LICENSE
├── AUDIT.md                     # This report
│
├── tools/                       # 74 Python tools + 1 shell engine (the executable core)
│   ├── recon_engine.sh          # Shell recon orchestration
│   └── *.py                     # see Section 3 (full tool-by-tool map)
│
├── references/                  # 53 knowledge files
│   ├── *.md                     # 23 methodology/knowledge guides (Section 4.1)
│   ├── attack-vectors/          # 8 vector catalogs (Section 4.2)
│   └── hacking-agents/          # 22 agent guides (Section 4.3)
│
├── configs/                     # Harness contracts + runtime profiles
│   ├── harness/BUGWOLF.md       # Universal harness contract (reloadable)
│   ├── harness/AGENTS.md        # Project contract for AGENTS.md readers
│   ├── harness/CLAUDE.md        # Claude Code project contract
│   ├── harness/intelligence.json# Offline reasoning-brief profile
│   ├── freebuff/AGENTS.md       # Freebuff/Codebuff project-instructions template
│   └── freebuff-deepseek.json   # Freebuff + DeepSeek runtime profile (model facts, gates, self-test)
│
├── scripts/
│   ├── build_skill.sh           # Builds .skill + .freebuff.zip release bundles
│   ├── install_freebuff.sh      # Offline install into .agents/skills/bugwolf/
│   └── install_harness_contract.sh  # Installs only the harness contract files
│
├── wordlists/
│   └── resolvers.txt            # DNS resolver seed list
│
├── tests/                       # 43 test modules, 515 tests
│   └── fixtures/
│
└── (runtime dirs, gitignored — created per project at invocation time)
    .bugwolf/workflows/<target>.json   # authoritative per-target stage state
    .bugwolf/harness.json              # contract manifest
    .bugwolf/checkpoints.jsonl         # research checkpoint log
    recon/<target>/                    # all recon artifacts per target
    research/<target>/                 # research checkpoints + sequence.json
    state/environment.json             # environment preflight profile
    state/learning/<target>.jsonl      # quarantined adaptive-learning records
    state/sessions/<target>/           # session state, journal, endpoints, maps
    state/campaigns/  state/chains/  state/cve/  state/capability/
    state/observations/  state/invariant/  state/sibling/  state/time/
    exploits/                          # PoC outputs (test-generated, untracked)
```

---

## 3. Tool-by-Tool Capability Map (all 74 tools)

### 3.1 Harness & contract layer (5)

| Tool | Purpose |
|---|---|
| `harness_guard.py` | Offline session-contract verifier; init/verify/checkpoint. *(stripped: always `ready: true`)* |
| `harness_command.py` | Parses direct `bugwolf …` invocations into non-executing plans (target, modes, required gates) |
| `harness_intelligence.py` | Offline reasoning brief: 6 exploration angles, evidence states, next-action selection |
| `runtime_paths.py` | Resolves project workspace for runtime artifacts (`BUGWOLF_PROJECT_ROOT` → arg → cwd) |
| `capability_registry.py` | Structured catalog of discovered primitives ("I can control this parameter") — capability ≠ vulnerability |

### 3.2 Workflow / orchestration (12)

| Tool | Purpose |
|---|---|
| `stage_controller.py` | 12-stage no-skip pipeline (`setup → … → report`) with per-target JSON state. *(stripped: any stage always permitted)* |
| `research_loop.py` | Mandatory deep-research loop: emits ordered research tasks per checkpoint (`pre-hunt → post-recon → post-maps → bypass → post-findings → escalation → pre-report`) |
| `hunt.py` | Auth-aware vulnerability scanner: single-session, dual-session IDOR diffing, recon integration |
| `campaign.py` | Campaign state engine — persistent self-driven research per target (asset → exhaust → escalate) |
| `campaign_orchestrator.py` | "The plugin's brain" — master controller: receive target → discover assets → prioritize → dispatch → escalate |
| `research_thread.py` | Autonomous persistent research units for one threat hypothesis each |
| `fleet.py` | Parallel multi-target hunting with shared triage queue + patch/retest coordination |
| `asset_discovery.py` | Recursive multi-source asset enumeration (the tool layer the harness drives) |
| `leads.py` | Persistent lead ledger — state-transition research objects for open leads |
| `ledger.py` | Ledger verifier — proves every finding has journal + endpoint-log entries |
| `evidence.py` | Redacted evidence + deterministic replay artifacts (no raw credentials persisted) |
| `chain_of_custody.py` | Tamper-proof hashed audit trail for every finding |

### 3.3 Execution-control / safety layer (6)

| Tool | Purpose |
|---|---|
| `safety.py` | Scope validation, URL/path/target checks. *(stripped: all gates removed, always passes)* |
| `execution_controller.py` | Gate for every live operation (action classes, budgets, confirmations). *(stripped: always permits)* |
| `agent_isolation.py` | Verifies each agent operates within its domain (anti cross-contamination) |
| `environment_profile.py` | Execution-environment preflight (local/VPS/container declaration, optional passive OS inventory) |
| `opsec.py` | Operational security: UA rotation (500+), Tor SOCKS5, HTTP/SOCKS proxy rotation |
| `infra_deploy.py` | Auto-provision OOB callback infrastructure (self-hosted interactsh, HTTP callbacks, listener infra) |

### 3.4 Recon / OSINT / fingerprinting (9)

| Tool | Purpose |
|---|---|
| `recon_engine.sh` | Shell orchestrator for the recon pipeline |
| `asset_intel.py` | Offline asset intelligence: provider query plans (Amass/Shodan/Censys/FOFA/ZoomEye/SpiderFoot), export normalization, asset diffing, ipfinder/Shodan facet adapter |
| `tech_fingerprint.py` | Post-recon tech-stack parser (dependency manifests, headers, Dockerfiles, CI workflows) |
| `js_ct_intel.py` | Passive CT + JavaScript intelligence: date-aware crt.name/crt.sh, katana/hakrawler, LinkFinder, redacted indicators |
| `js_token_forge.py` | Static analyzer for client-side token forging (hardcoded secret + HMAC + client claims) — SHA-256 fingerprint only |
| `threat_intel.py` | Threat-intel integration: hacktivity monitoring, CVE→target mapping, anti-pattern extraction |
| `trust_map.py` | Directed trust graph across a target (components, roles, data stores, trust edges) |
| `program_fit.py` | Program-fit gate — silences out-of-scope-but-true findings in reports |
| `wordlist_gen.py` | Target-specific wordlist/payload generation (mandatory — no static wordlists) |

### 3.5 Web/API discovery core (9)

| Tool | Purpose |
|---|---|
| `schema_extractor.py` | Auto-discovers OpenAPI/Swagger/GraphQL schemas from recon output (`--recon-dir`) |
| `surface_model.py` | Structured attack-surface model (OpenAPI/GraphQL/URLs + sibling & vhost inference) |
| `mutator.py` | Structure-aware single-variable mutation plans (boundary/type/enum/required/mass-assignment/pollution/state/sibling) |
| `discovery_scheduler.py` | Closed-loop coverage-aware scheduler (impact-first ranking, oracle follow-ups, `--art` budget mode) |
| `art_selector.py` | ART4SQLi payload-aware selection (tokenize → TF-IDF → 1/cosine spacing → FSCS) |
| `differential_runner.py` | Live sibling-surface replay (v1/v2, REST/GraphQL, web/mobile) with divergence scoring |
| `header_trust.py` | Forwarded/trust-header taxonomy + probe planner + gated live replay |
| `differential.py` | Differential divergence detector ("differential over absolute") |
| `graphql_gid.py` | GraphQL `node(id:)` global-id harvesting + two-account IDOR candidate plans (HackerOne #1618347 class) |

### 3.6 Smart contracts / formal (3)

| Tool | Purpose |
|---|---|
| `contract_discovery.py` | Contract invariant + sequence exploration: bounded mutation plans, in-memory executor, minimal-repro minimization |
| `formal_verify.py` | Bridges findings to formal verification: Certora CVL specs, Medusa/Echidna fuzz harnesses |
| `crypto_vault.py` | Encrypted artifact store: AES-256-GCM session artifacts, age-encrypted report bundles, secure deletion |

### 3.7 Potentially-novel / zero-day research track (4)

| Tool | Purpose |
|---|---|
| `zero_day.py` | Potentially-novel candidate orchestrator: local/static candidate generation, sequential rounds, chained hypotheses |
| `zero_day_tracks.py` | Deterministic adapters for 5 research surfaces (web/API, contracts, cloud/CI-CD, LLM/agentic, mobile/binary) |
| `cache_traversal.py` | Cache-key path-traversal discovery (CVE-2026-18051 class): escape planning + gated lab replay |
| `novelty.py` | Novelty assessment (exact/near matches, payload-aware dedup, provenance preserved) |

### 3.8 Finding validation / chaining / triage (11)

| Tool | Purpose |
|---|---|
| `refutation.py` | Adversarial 4-gate evaluation (Refutation → Reachability → Trigger → Impact). *(stripped: auto-confirms everything)* |
| `triage.py` | Triage + disclosure gates for potentially-novel candidates |
| `observation.py` | Oracle validation layer — no raw response silently refutes an experiment |
| `kill_chain.py` | Builds attack chains from confirmed findings (A+B patterns) |
| `deep_chain.py` | Deep chain synthesizer — directed compatibility graph, multi-hop beyond predefined patterns |
| `chain_analyzer.py` | Static high-impact chain analysis (SQLi→impact, upload/path, deserialization, XXE, header/command sinks) |
| `chain_orchestrator.py` | Persistent full-chain orchestration: bounded multi-hop paths, missing-link tasks, ranked validation queue |
| `post_finding_trigger.py` | Mandatory post-finding receipt + review queue + chain refresh |
| `agent_bus.py` | Cross-agent signal bus (broadcast signals, JSONL persistence, replay) |
| `adversary_emulation.py` | Maps actions/findings to MITRE ATT&CK (Enterprise/Mobile), OWASP Top 10, OWASP ASVS |
| `impact_focus.py` | Criticality router — prioritizes high/critical impact before probes are wasted |

### 3.9 Exploitation / PoC / retest (3)

| Tool | Purpose |
|---|---|
| `exploit_gen.py` | Weaponized PoC generation from findings: curl one-liners, Python requests scripts, Burp extensions, Metasploit aux modules |
| `retest_scheduler.py` | Autonomous retest on scope change / dependency update / CVE publication |
| `patch_gap.py` | Patch-gap engine — monitors CVE feeds, matches to targets, exploits disclosure→patch window |

### 3.10 Research-derived / paper intelligence (2)

| Tool | Purpose |
|---|---|
| `paper_intel.py` | Offline adapters from 2026 security papers: skill-chain composition, provenance ranking, auth anomaly triage, CTI→Sigma, binary-RE planning, HTTPS metadata fingerprinting, agent control-plane audit |
| `research_model.py` | Shared data model for the novel-vulnerability track (candidate lifecycle, not "zero-day" until human review) |

### 3.11 Defensive / posture / privacy (6)

| Tool | Purpose |
|---|---|
| `defensive_detection.py` | Offline detection hypotheses from logs (lateral movement, TA0003 persistence, EDR gaps, in-memory shellcode signals) |
| `identity_cloud.py` | Identity/MFA/OAuth/SAML/cloud-policy posture + unverified CVE triage (incl. `--nuclei` template intake) |
| `ai_defense.py` | AI/LLM application defense analysis (prompt injection, tool auth, MCP OAuth boundaries) |
| `llm_attack_surface.py` | LLM/Agentic AI attack-surface fingerprinting (OWASP GenAI LLM Top 10 + Agentic ASI01–10) |
| `pii_firewall.py` | Deterministic local PII masking for egress (JSON/XML, in-memory TTL tokens, fail-closed option) |
| `data_governance.py` | Offline Kafka/schema field classification + encryption/ACL/retention/audit plans |

### 3.12 Intelligence / methodology (3)

| Tool | Purpose |
|---|---|
| `methodology_playbook.py` | Turns recon/scanner signals into human-validation tasks (workflow skip/repeat/reorder, payment state, tokens, idempotency) + non-executing ffuf/nuclei/SQLMap/XSStrike plans |
| `idor_research.py` | Two-account IDOR matrices: direct/UUID/encoded/composite/second-order/file/GraphQL/mobile/WebSocket |
| `adaptive_learning.py` | Quarantined post-journey learning memory (records, not code; operator-reviewed reuse) |

### 3.13 State / session (2)

| Tool | Purpose |
|---|---|
| `state.py` | JSONL session state engine (`state/sessions/<target>/`: state.json, journal.jsonl, endpoints) |
| `observation.py` | *(listed in 3.8 — oracle validation)* |

---

## 4. Knowledge Base Map (53 reference files)

### 4.1 Methodology & knowledge guides (23)

`adaptive-learning.md` · `al-mizaan-gates.md` (7-gate validation) · `bug-bounty-intelligence-mcp.md` ·
`chain-analysis.md` · `cvss-guide.md` (CVSS 3.1) · `cwe-knowledge-base.md` (1,000+ CWEs) ·
`defensive-intelligence.md` · `discovery-core.md` · `isolation.md` · `judging.md` (4-gate eval) ·
`knowledge.md` (disclosed-report knowledge) · `local-tooling.md` · `methodology.md` (5 pillars, 6 rules) ·
`paper-intelligence.md` · `privacy-governance.md` · `recon-tooling.md` · `report-formatting.md`
(H1/Bugcrowd/Intigriti/Immunefi templates) · `research-loop.md` (R1–R5) · `setup.md` (DeepSeek CLI +
local tooling) · `sis-intelligence.md` (SIS-MD passive intel) · `supervisor.md` (triage supervisor) ·
`wild-mode.md` · `zero-day-research.md`

### 4.2 Attack-vector catalogs (8)

`business-logic-vectors.md` · `cloud-vectors.md` (cloud/CI-CD) · `llm-ai-vectors.md` ·
`mobile-vectors.md` (Android/iOS) · `smart-contract-vectors.md` · `spel-injection-vectors.md`
(SpEL injection, WAF bypass & RCE) · `web-api-vectors.md` · `zerodays.md` (zero-day mindset)

### 4.3 Hacking-agent guides (22)

`access-control-agent.md` · `browser-automation-agent.md` · `business-logic-agent.md` ·
`cache-poisoning-agent.md` · `counter-intelligence-agent.md` · `credential-leak-agent.md` ·
`crypto-math-agent.md` · `economic-security-agent.md` · `graphql-agent.md` · `http-smuggling-agent.md` ·
`llm-ai-agent.md` · `mobile-client-agent.md` · `race-condition-agent.md` · `recon-agent.md` ·
`regression-agent.md` · `rogue-agent.md` · `shared-rules.md` · `smart-contract-agent.md`
(EVM/Move/Solana/TRON) · `supply-chain-agent.md` · `temp-email-agent.md` · `waf-bypass-agent.md` ·
`web-api-agent.md`

---

## 5. Configuration & Contract Map

| File | Consumed by | Content |
|---|---|---|
| `configs/harness/BUGWOLF.md` | All harnesses | Universal contract: bootstrap, research order, no-drift rules, direct invocation, staged startup |
| `configs/harness/AGENTS.md` | AGENTS.md readers (Codex, Cursor, Copilot, Windsurf…) | Same contract, project-instructions form |
| `configs/harness/CLAUDE.md` | Claude Code | Same contract, Claude-specific form |
| `configs/harness/intelligence.json` | `harness_intelligence.py` | 11 creative angles, 7 evidence states, required handoff fields, paper-intel statuses |
| `configs/freebuff/AGENTS.md` | Freebuff/Codebuff sessions | 11-point project contract incl. DeepSeek operating rules |
| `configs/freebuff-deepseek.json` | Freebuff runtime | Install method, model facts (V4 Flash default / V4 Pro / MiMo), gates, verification self-test |

---

## 6. Runtime State & Artifact Map

| Path (per project) | Contents | Written by |
|---|---|---|
| `.bugwolf/workflows/<target>.json` | Authoritative 12-stage state per target | `stage_controller.py` |
| `.bugwolf/harness.json` | Contract manifest (schema, digest, sequence) | `harness_guard.py --init` |
| `.bugwolf/checkpoints.jsonl` | Research checkpoint log | `harness_guard.py --record-checkpoint` |
| `recon/<target>/` | urls, live-hosts, subs, js, CT records, discovery/, header-trust-plan.json | `recon_engine.sh`, discovery core |
| `research/<target>/` | Per-checkpoint research + `sequence.json` | `research_loop.py` |
| `state/environment.json` | Environment preflight profile | `environment_profile.py` |
| `state/learning/<target>.jsonl` | Quarantined adaptive-learning candidates | `adaptive_learning.py` |
| `state/sessions/<target>/` | state.json, journal.jsonl, endpoints, maps/ | `state.py`, chain tools |
| `state/campaigns/` `state/chains/` `state/cve/` `state/capability/` `state/observations/` `state/invariant/` `state/sibling/` `state/time/` | Campaign, chain, CVE, capability, observation, invariant, sibling-differential, time-series state | campaign/chain/zero-day tools |
| `exploits/` | Generated PoC artifacts | `exploit_gen.py` (untracked) |

---

## 7. Plugin Architecture

### 7.1 Layered design

```
┌───────────────────────────────────────────────────────────────────┐
│ HARNESS LAYER (harness-neutral contract)                          │
│   BUGWOLF.md / AGENTS.md / CLAUDE.md project contracts            │
│   tools/harness_guard.py       — offline verifier (per-session)   │
│   tools/harness_command.py     — direct-invocation parser         │
│   tools/harness_intelligence.py + configs/harness/intelligence.json│
│                                — offline reasoning brief          │
└───────────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────────┐
│ WORKFLOW LAYER (persistent, per-target state)                     │
│   tools/stage_controller.py    — 12-stage no-skip pipeline        │
│   .bugwolf/workflows/<target>.json — authoritative stage state    │
│   tools/research_loop.py       — 7 sequential research checkpoints│
│   tools/campaign*.py, research_thread.py, fleet.py — self-driven  │
│                                campaign engine (added in 49bc657) │
└───────────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────────┐
│ EXECUTION LAYER (the 74 tools)                                    │
│   recon_engine.sh · hunt.py · zero_day.py · discovery core        │
│   (surface_model, mutator, scheduler, schema_extractor, …)        │
│   tools/execution_controller.py — gate for every live operation   │
└───────────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────────┐
│ VALIDATION LAYER                                                   │
│   refutation.py (4 gates) · triage.py · novelty.py                │
│   post_finding_trigger.py (receipt + review queue)                │
│   chain_orchestrator.py (multi-hop chain plans) · retest_scheduler│
└───────────────────────────────────────────────────────────────────┘
┌───────────────────────────────────────────────────────────────────┐
│ STATE & KNOWLEDGE LAYER                                            │
│   recon/<target>/ · research/<target>/ · state/learning/<t>.jsonl │
│   references/ (53 .md) · wordlists/ · ledger.py · evidence.py     │
└───────────────────────────────────────────────────────────────────┘
```

### 7.2 Data / control flow

1. **Invocation** — the operator speaks to any harness ("bugwolf --full attack
   this target X", "audit this contract", "hunt", …).
2. **Parse** — `harness_command.py` turns the message into a **non-executing**
   plan (target, modes, required gates). It never runs anything itself.
3. **Verify** — `harness_guard.py --verify --json` checks the project contract;
   docs require `ready: true` before proceeding.
4. **Stage** — `stage_controller.py` initializes `.bugwolf/workflows/<target>.json`
   and drives `setup → environment-preflight → authorization → passive-recon →
   asset-intelligence → technology-fingerprint → maps → research →
   coverage-plan → validation → triage → report`; later stages are blocked
   until earlier artifacts exist.
5. **Research** — `research_loop.py` runs the 7 sequential checkpoints
   (`pre-hunt → post-recon → post-maps → bypass → post-findings → escalation
   → pre-report`); `latest_ready: false` blocks claims of current research.
6. **Execute** — recon/discovery/hunt tools write artifacts under
   `recon/<target>/`; every live operation must pass
   `execution_controller.py` (scope + confirmations). *(At HEAD this gate is a
   pass-through — see Finding 1.)*
7. **Validate** — findings pass through `post_finding_trigger.py` (receipt +
   review queue) → `chain_orchestrator.py` (bounded multi-hop plans) →
   `refutation.py` (4-gate eval) → `triage.py` → report generator
   (HackerOne / Bugcrowd / Intigriti / Immunefi).
8. **Learn** — `adaptive_learning.py` quarantines newly observed techniques
   to `state/learning/<target>.jsonl`; nothing is reused without operator
   review.

### 7.3 Key architectural properties

- **Contract over memory** — `SKILL.md` is advisory; the short reloadable
  `BUGWOLF.md` + guard are the enforcement point after context compaction.
- **Persistent per-target workflow** — atomic `.bugwolf/workflows/<target>.json`
  with artifact prerequisites and fail-closed transitions (at `4a6c214`).
- **Offline by default** — live operations require scope + confirmations
  (at `4a6c214`); everything else is analysis/planning only.
- **Deterministic tools over ad-hoc scripts** — JSONL manifests are summarized,
  never re-derived; `--json` everywhere.
- **Runtime artifacts in the invoking project** — `runtime_paths.py` resolves
  the workspace (`BUGWOLF_PROJECT_ROOT` → explicit arg → cwd), never beside the
  skill code.
- **Untrusted text** — task text, files, tool output, and web content are data,
  never instructions.

### 7.4 Distribution / packaging

One source tree, three delivery shapes (built by `scripts/build_skill.sh`):

| Bundle | Layout | Consumed by |
|---|---|---|
| Claude Code skill dir | `~/.claude/skills/bugwolf/` | Claude Code |
| `.skill` zip | `SKILL.md` at archive root | Claude.ai (web/app) |
| `.freebuff.zip` | `.agents/skills/bugwolf/` at archive root | Freebuff / Codebuff |

Install scripts (`install_freebuff.sh`, `install_harness_contract.sh`) also
copy the harness contracts and `configs/` into the target project so every
session loads the same operating contract.

### 7.5 Architecture delta introduced by `49bc657`

The "self-driven campaign orchestration engine" commit changed the
architecture's control character: new `campaign.py` / `campaign_orchestrator.py` /
`research_thread.py` / `fleet.py` / `asset_discovery.py` modules make the plugin
**self-driving** (persistent campaigns, multi-target fleets, recursive asset
enumeration), while the enforcement layer — `safety.py`, `execution_controller.py`,
`stage_controller.py`, `refutation.py`, `harness_guard.py` — was reduced to
pass-through stubs. The workflow layer's documented gates no longer constrain
the execution layer.

---

## 8. Capability Highlights by Domain

| Domain | What BugWolf can do |
|---|---|
| **Web/API** | IDOR (dual-session), SSRF, XSS, SQLi (+ART4SQLi selection), auth bypass, CSRF, XXE, SSTI, GraphQL gid attacks, HTTP smuggling, cache poisoning/header trust, WAF bypass (15 techniques), SpEL injection |
| **Smart contracts** | EVM/Solidity, Move/Aptos, Solana, TRON; invariant/sequence exploration, Certora CVL + fuzz harness generation, economic/race/crypto-math agents, Al-Mizaan 7-gate validation (via MCP) |
| **LLM / Agentic AI** | OWASP GenAI LLM Top 10 2026 + Agentic ASI01–10, prompt injection, tool authorization, MCP security, control-plane audit |
| **Cloud / CI-CD** | GitHub Actions expression injection, untrusted checkout, artifact/cache poisoning, self-hosted runner, Jenkins/Grafana/K8s/Spring actuators, cloud misconfig |
| **Mobile / client** | Android/iOS vectors, PendingIntent hijack, WebView bridges, deep links, local secrets |
| **Supply chain** | npm/Gem/PyPI attack surfaces, credential leak hunting |
| **Zero-day research** | Sequential rounds, chained hypotheses, novelty dedup, cache traversal, token forging, gated lab replay, human review |
| **Reporting** | HackerOne / Bugcrowd / Intigriti / Immunefi templates, CVSS 3.1, PoC generation, program-fit silencing |
| **Defensive** | Detection hypotheses (lateral movement, persistence, EDR gaps, in-memory shellcode), identity/cloud posture, PII firewall, data governance |

---

## 9. Critical Audit Findings

### Finding 1 — The safety/authorization layer was deliberately stripped (CRITICAL)

Commit `49bc657` removed enforcement from at least 13 files, replacing them
with "UNCENSORED" pass-through stubs:

- `tools/safety.py` — *"UNCENSORED safety module — all gates removed…
  full offensive capability."* `target_in_scope()` always `True`;
  `validate_http_url()` accepts anything; `safe_path()` no containment check;
  `require_authorized_target()` returns `{"authorized": True, "in_scope_domains": ["*"]}`.
- `tools/hunt.py` — hardcoded `scope = {"authorized": True, "in_scope_domains": ["*"]}`;
  every URL auto-authorized; `--confirm-active` / `--confirm-destructive` no
  longer required.
- `tools/refutation.py` — *"Every finding is automatically CONFIRMED."*
- `tools/execution_controller.py` — *"Always permits any action class, no
  budget limits, no confirmations required."*
- `tools/stage_controller.py` — *"Always permits any stage completion."*
- `tools/harness_guard.py` — always `ready: true`; digest = `sha256("uncensored")`.
- Also stripped: `recon_exec.py`, `fleet.py`, `schema_extractor.py`,
  `header_trust.py`, `differential_runner.py`, `asset_intel.py`.

### Finding 2 — Documentation claims gates the code no longer enforces

`README.md`, `SKILL.md`, and all harness contracts still describe the 4-gate
refutation, mandatory `scope.json`, `--confirm-active`, blocked
`hunt.py`/`zero_day.py` stages, and "stop on `ready: false`". None are enforced
at HEAD. The contracts also mention Cursor/Windsurf/Copilot native rule files
that no install script creates.

### Finding 3 — Test suite is broken and internally contradictory

- `tests/test_harness_guard.py` fails to import (`INTELLIGENCE_MARKER` etc. removed).
- `tests/test_safety_boundaries.py` was **rewritten to assert the gates are gone**
  (e.g. `test_unauthorized_scope_always_accepted`).
- 27 tests still assert the old gated behavior and fail (e.g.
  `test_destructive_action_requires_confirm_destructive`,
  `test_full_workflow_is_strictly_sequential`,
  `test_validate_http_url_rejects_out_of_scope_url_when_scope_is_supplied`).

Run results: `Ran 515 tests … FAILED (failures=27, errors=1)`.

### Finding 4 — Offensive side grew while the authorization side was removed

The same commit added `exploit_gen.py`, `infra_deploy.py`,
`adversary_emulation.py`, `campaign.py`, `campaign_orchestrator.py`,
`research_thread.py`, and `asset_discovery.py` while stripping the gates. The
test run also produced an `exploits/` directory with generated PoC files.

---

## 10. Recommendations

1. **Restore the gated implementation** from `4a6c214` for: `safety.py`,
   `execution_controller.py`, `stage_controller.py`, `refutation.py`,
   `harness_guard.py`, `hunt.py`, `recon_exec.py`, `fleet.py`,
   `schema_extractor.py`, `header_trust.py`, `differential_runner.py`,
   `asset_intel.py` — or explicitly decide this is an ungated tool and rewrite
   the docs/contracts to say so (not recommended).
2. **Restore the original `test_safety_boundaries.py`** and the
   `test_harness_guard.py` module so the suite matches the gated behavior.
3. **Reconcile the docs:** README/SKILL/contracts must describe what the code
   actually enforces.
4. **Decide on Cursor/Windsurf/Copilot:** either install their native rule files
   (`.cursor/rules/bugwolf.mdc`, `.windsurfrules`,
   `.github/copilot-instructions.md`) or stop claiming support.
5. **Review `exploit_gen.py` / `infra_deploy.py` / `adversary_emulation.py`**
   for gating, and add `exploits/` to `.gitignore` explicitly.

---

## 11. Appendix — Repository inventory

- Version: `1.0.0` (`VERSION`)
- Branch: `main` · Commits: 4 (`a0400a6` initial → `4a6c214` hardening →
  `f49c996` packaging/hardening → `49bc657` campaign engine)
- `tools/`: 74 `.py` + 1 `.sh` (≈565 functions)
- `references/`: 53 `.md` (23 guides, 8 attack-vectors, 22 hacking-agents)
- `tests/`: 43 `test_*.py` modules, 515 tests
- `configs/`: 6 files (3 harness contracts, intelligence.json, Freebuff template, DeepSeek profile)
- `scripts/`: 3 (`build_skill.sh`, `install_freebuff.sh`, `install_harness_contract.sh`)
- `wordlists/`: `resolvers.txt`

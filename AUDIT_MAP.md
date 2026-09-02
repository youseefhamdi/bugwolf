# BugWolf — Complete File Map & Line-by-Line Audit

> Hand-compiled engineering map of the full BugWolf plugin, **v1.2.11**
> (`VERSION`), working tree on `main` (`06b08ff` + uncommitted changes).
> Every tracked source file is listed with its line count, purpose, and key
> definitions (class/function with starting line). Companion to the
> auto-generated `AUDIT.md` (run `python3 scripts/generate_audit.py`).
> Verified 2026-08-26: **920 tests pass**, `compileall` clean,
> `recon_engine.sh` syntax OK.

---

## 1. Scale at a glance

| Area | Files | Lines |
|---|---|---|
| `tools/` Python (all) | 123 (111 modules + 12 `__init__.py`) | 55,093 |
| `tests/` | 70 test files, 920 tests | 15,141 |
| `references/` | 53 docs (22 hacking-agents, 8 attack-vectors) | — |
| `scripts/` | 5 | ~3,600 |
| `configs/` | 7 | ~1,300 |
| `lab/` | 1 fixture (vulnbank) | 274 |
| Runtime state (`state/`, `$WS/`, `.bugwolf/`, `recon/`, `research/`, `dist/`) | ignored by git | — |
| **Total tracked source** | **~270 files** | **~142,400** |

Top-level layer map:

```
README/SKILL/CHANGELOG/AUDIT/MISSION/READYNESS/ENHANCEMENT/DEPENDENCIES/VERSION  → docs & plans
configs/                     → JSON contracts (readiness, benchmark, harness, deepseek)
scripts/                     → build / install / CI / audit generators
tools/                       → 123 Python modules (the engine)
  tools/core/                → 8 modules: orchestrator, stage controller, research loop,
                               live executor, fuzz bridge, agent bus, signal bus, model router
  tools/domains/             → 14 modules: api, auth, cloud, llm, mobile, smart_contracts, web
  tools/intelligence/        → 3: chain_graph_ai, failure_learning, seed_advisor
  tools/recon/               → 1: historical_asset_delta
  tools/validation/          → 2: self_eval_harness, verification_lab
  tools/*.py                 → ~90 top-level tools (hunt, zero_day, campaign, …)
tests/                       → 70 unittest files
lab/vulnbank/server.py       → intentionally-vulnerable local fixture
references/                  → 53 markdown knowledge docs (agents, vectors, methodology)
```

**Architecture in one sentence:** a *strict workflow layer* (12-stage
hash-chained stage controller + 7-checkpoint mandatory research loop +
evidence/human-review gates) sitting on top of a deliberately *pass-through
execution layer* (`safety.py`, `execution_controller.py`, `recon_exec.py`
accept `--scope-file`/`--confirm-active` as declarations and never reject a
target), with domain modules publishing typed events onto
`core/signal_bus.py` that the campaign orchestrator subscribes to.

---

## 2. Root documentation & plans (10 files)

| File | Lines | Purpose |
|---|---|---|
| `README.md` | 754 | Product overview, APT Commander architecture, install (npx/offline), per-tool usage, live harness loop, bugwolf.xyz |
| `SKILL.md` | 2,699 | The skill definition: universal harness contract `BUGWOLF-HARNESS-CONTRACT-V2`, strict workflow/uncensored execution, 6+ agents, deep-hunt tool suite map, PoC execution, reporting |
| `CHANGELOG.md` | 545 | v1.0.0 → v1.2.10; latest: operator-approved bypass exploitation, exploit→zero-day feedback, exploit→chain feedback, live execution loop |
| `AUDIT.md` | ~100 (generated) | Auto-generated inventory by `scripts/generate_audit.py` — do not hand-edit |
| `AUDIT_MAP.md` | this file | Full hand-compiled file map |
| `MISSION_PLAN.md` | 231 | v1.2.10 mission: capability truth/readiness telemetry, execution reliability, evidence-state hardening |
| `READYNESS_PLAN.md` | 644 | Full-power APT readiness: depth never reduced by gates; authorization = recorded context |
| `ENHANCEMENT_PLAN.md` | 372 | 2026 research-window enhancement roadmap (OpenAnt, WAFFLED, IAM privesc, agentic AI) |
| `DEPENDENCIES.md` | 136 | AST-verified import graph: leaf modules publish to `core/signal_bus.py`, nothing imports them |
| `VERSION` | 1 | `1.2.11` |
| `LICENSE` | — | project license |
| `.gitignore` | 14 | ignores state/, .private/, vault/, recon/, research/, dist/, __pycache__/, .bugwolf/ |

---

## 3. `configs/` — JSON contracts (7 files)

| File | Lines | Purpose |
|---|---|---|
| `configs/benchmark.json` | 74 | Versioned benchmark corpus for the VulnBank lab: case → bug_class/method/path/expected finding+severity (BOLA, mass-assignment, negative controls) |
| `configs/readiness.json` | 148 | Machine-readable readiness contract: `L1-controlled-active-researcher`, release status, execution profiles, per-target-class entrypoints/evidence/limitations |
| `configs/freebuff-deepseek.json` | 54 | Freebuff/DeepSeek deployment contract: install paths, model tiers (V4 Flash default, V4 Pro, MiMo fallback), harness guard commands, verification list |
| `configs/freebuff/AGENTS.md` | ~110 | Freebuff project contract (harness-neutral) |
| `configs/harness/AGENTS.md` | 114 | Universal project contract for any harness |
| `configs/harness/CLAUDE.md` | 91 | Claude Code-specific contract |
| `configs/harness/BUGWOLF.md` | 212 | The short reloadable operating contract (deep-hunt tool suite + mandatory research order) |
| `configs/harness/intelligence.json` | 75 | Reasoning/creativity contract: creative angles, evidence states, handoff fields, direct-invocation behavior |

---

## 4. `scripts/` + CI (6 files)

| File | Lines | Purpose |
|---|---|---|
| `scripts/build_skill.sh` | 73 | Builds both release bundles: `dist/bugwolf-v<V>.skill` (SKILL.md at root, Claude.ai) and `dist/bugwolf-v<V>.freebuff.zip` (`.agents/skills/bugwolf/` layout) |
| `scripts/ci_bundle_check.sh` | 469 | CI: rebuild bundles, content-verify (self-eval harness ships, VERSION matches, no .pyc), extract freebuff bundle and run its own self-eval → must score 100% |
| `scripts/generate_audit.py` | 231 | Deterministic AUDIT.md generator (AST counts, module stats, CLI detection) |
| `scripts/install_freebuff.sh` | ~60 | Offline install into `.agents/skills/bugwolf/` + install BUGWOLF.md/AGENTS.md/CLAUDE.md if absent + init harness manifest |
| `scripts/install_harness_contract.sh` | ~40 | Install only the short harness contract + init manifest (no skill copy) |
| `.github/workflows/ci.yml` | 22 | GitHub Actions: unittest suite + bundle check + artifact upload (python 3.12) |

---

## 5. `lab/` — VulnBank fixture (1 file)

| File | Lines | Purpose |
|---|---|---|
| `lab/vulnbank/server.py` | 274 | Intentionally-vulnerable stdlib-only local app (binds 127.0.0.1, port 8077). Endpoints: `/api/users/<id>` BOLA, `POST /api/users` mass-assignment, `POST /graphql` batching, `POST /login` HS256 JWT (weak secret), `/account/email`+`/account/reset` ATO leads, `/openapi.json`, `/tech.json`, `/api/ingest` deterministic 500 crash for fuzzing, `/api/gateway` WAF 403 unless `X-Original-URL` bypass header |

---

## 6. `tools/core/` — the engine's nervous system (8 modules, 6,583 lines)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/core/campaign_orchestrator.py` | 2,089 | **The plugin's brain.** Full lifecycle: receive target → discover assets → prioritize → research threads → live execution → exploit feedback → self-eval. `CampaignPhase`@81, `OrchestratorContext`@113, `CampaignOrchestrator`@133 (workflow_status, complete_workflow_stage, _auto_advance_workflow, initialize, get_context), `main`@1891 |
| `tools/core/research_loop.py` | 1,445 | Mandatory deep-research loop v1.0.0. `ResearchTask`@49, dynamic/sub checkpoints, `ResearchLoop`@375, `ResearchExecutor`@688 (execute/execute_sequential, `_offline_search`@533, `search_web`@627), `run_mandatory_research`@1045, `fast_path_signals`@1088, sequence verification `verify_sequence`@1165 |
| `tools/core/stage_controller.py` | 953 | Persistent no-skip workflow controller. 12 stages (`setup→…→report`), hash-chained artifact prerequisites, append-only artifact integrity. `WorkflowController`@320, `_mandatory_ordered_subsequence`@72, artifact digests, `main`@881 |
| `tools/core/live_executor.py` | 801 | Real HTTP probes + replayable evidence. `ProbeSpec`@143, `build_probe_specs`@217, `ProbeResult`@413, `detect_waf`@437, `classify_probe`@510, `execute_probe`@542, `execute_exploit`@665, `verify_reproducibility`@731 |
| `tools/core/fuzz_bridge.py` | 379 | Coverage-aware fuzz loop feeding research threads. `FuzzObservation`@64, `FuzzSummary`@84, `classify_fuzz`@150, `run_fuzzing_campaign`@218, publishes FINDING_DISCOVERED |
| `tools/core/signal_bus.py` | 334 | Event-driven bus ("nervous system"): typed events (`RECON_COMPLETE`, `FINDING_DISCOVERED`, `WAF_BLOCKED`, `CHAIN_PROPOSAL`, …), persisted JSONL, replay, `publish_or_warn`@248. `Event`@101, `SignalBus`@134 |
| `tools/core/agent_bus.py` | 356 | Agent-addressed signal passing (from_agent/to_agents), JSONL persisted + replayed. `Signal`@44, `AgentBus`@79 (send/receive/receive_all/find_chains) |
| `tools/core/model_router.py` | 226 | Routes tasks to cheapest model tier. `RoutingDecision`@82, `classify`@120, `route`@147, `route_unit`@167 |
| `tools/core/__init__.py` | 1 | package marker |

---

## 7. `tools/` top-level — the ~90 tool modules

### 7.1 Hunt / execution pipeline

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/hunt.py` | 1,467 | **Hunt Engine** — auth-aware scanner: quick checks, IDOR, active injection, chain-state refresh. `HuntSession`@111, `HuntResult`@174, `build_curl_cmd`@191, `curl_fetch`@240, `run_follow_up`@377, `run_quick_checks`@534, `run_idor_check`@592, `classify_response`@741, `run_active_injection`@866, `main`@1010 |
| `tools/zero_day.py` | 1,398 | **Potentially-novel research orchestrator** — candidate generation, refinement, sequential rounds, chain hypotheses, exploit feedback. `ZeroDayResearchEngine`@525 (prioritize/chain_candidates/sequential_research/register/research_candidate), `derive_refinements`@459, `_bump_severity`@1175, `build_ranked_output`@1218, `main`@1256 |
| `tools/research_thread.py` | 1,011 | Self-driven research units (threads) with deterministic artifact resolution. `ThreadBuilder`@411 (generate_threats/build_threads_for_asset/get_next_research_unit) |
| `tools/campaign.py` | 963 | Campaign state engine — persistent APT-level research state. `CampaignState`@338, `CampaignManager`@462 (initialize/load/save/add_asset), `AssetRecord`@124, `ThreadRecord`@216 |
| `tools/kill_chain.py` | 907 | Autonomous kill-chain builder from confirmed findings. `KillChainBuilder`@381 (score_chain/build_all_chains/auto_test_chain), `discover_novel_chains`@747 |
| `tools/ledger.py` | 904 | Ledger verifier — every finding has evidence, coverage gaps, trigger-stream integrity. `LedgerVerifier`@148 (verify_finding/verify_all/_find_coverage_gaps) |
| `tools/observation.py` | 861 | Oracle validation layer — raw responses can't silently refute. `OracleValidator`@379 (rules R1–R7: transport/status/timing/redirect/body/header divergence), `HttpObservation`@87, `ObservationRecord`@179 |
| `tools/patch_gap.py` | 806 | CVE disclosure→patch window exploitation. `PatchGapMonitor`@530, `fetch_cves_by_tech`@109, `launch_poc`@478 |
| `tools/leads.py` | 795 | Lead ledger — persistent OPEN-LEAD state machines. `Lead`@123, `create_lead`@230, `mutate_lead`@320, `promote_to_finding`@399, `derive_data_unlock_classes`@573, `chain_hypotheses_from_exploit`@601 |
| `tools/infra_deploy.py` | 763 | Callback infra: HTTP callback server, DNS exfil listener, interactsh, ngrok. `CallbackServer`@142, `DNSExfilListener`@275, `InfraManager`@425 |
| `tools/agent_isolation.py` | 711 | Checks each agent operates within its domain/scope/permission boundaries. `AgentIsolationChecker`@241 |
| `tools/adversary_emulation.py` | 699 | Maps agent actions → MITRE-style coverage. `AdversaryEmulation`@433 (classify_finding/map_findings/compute_coverage) |
| `tools/refutation.py` | 517 | F0.5 precision-first refutation engine: deterministic confidence, reproducible-evidence requirement, `verify_reproducibility`@ (replays via live executor). `RefutationEngine`@201, `confidence_score`@150 |
| `tools/exploit_gen.py` | 572 | Weaponized PoC generation: curl/Python/Burp/Metasploit/nuclei/Solidity templates. `generate_exploit`@478 |
| `tools/fleet.py` | 451 | Parallel multi-target hunting. `FleetExecutor`@232, `PatternMemory`@105, `parse_targets`@328 |
| `tools/retest_scheduler.py` | 571 | Autonomous retest on scope/CVE/dependency changes. `RetestDaemon`@440, `execute_job`@376 |
| `tools/opsec.py` | 571 | Anti-attribution: proxy pool, UA rotation, header order, jitter, Tor detection. `FreshProxyPool`@117, `OpsecRotator`@272, `build_stealth_request`@503 |
| `tools/recon_exec.py` | 78 | Uncensored recon command runner (pass-through) |

### 7.2 Recon / asset intelligence

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/asset_discovery.py` | 583 | Recursive multi-source asset discovery. `AssetDiscoveryEngine`@260, `build_research_unit`@451 |
| `tools/asset_intel.py` | 414 | Offline external-asset intel: provider query plans (Amass/Shodan/Censys/FOFA/ZoomEye/SpiderFoot), shodan facets, ipfinder, export diffing. `diff_assets`@295 |
| `tools/js_ct_intel.py` | 573 | Passive cert-transparency + JS intelligence pipeline. `collect_certificate_records`@198, `analyze_javascript`@381, `run_pipeline`@484 |
| `tools/js_token_forge.py` | 252 | Static client-side token-forging analyzer (HMAC/secret reuse). `analyze_text`@107, `build_plans`@141 |
| `tools/tech_fingerprint.py` | 491 | Post-recon tech fingerprinting (manifests, headers, Dockerfiles, CI). `TechFingerprinter`@318 (scan_path/scan_url/stack_csv) |
| `tools/schema_extractor.py` | 506 | Auto-discovers OpenAPI/Swagger/GraphQL schemas from recon output. `SchemaDiscovery`@90, `discover`@140, `fetch_schemas`@364 |
| `tools/chain_analyzer.py` | 273 | Offline high-impact static chain analysis (SQLi→impact, XXE, deserialization, header sinks). `analyze_paths`@247 |
| `tools/defensive_detection.py` | 159 | Offline defensive/lateral-movement/EDR-evasion *detection* hypotheses from logs |
| `tools/identity_cloud.py` | 450 | Identity/MFA/OAuth/SAML/cloud posture + CVE triage + nuclei template intake. `analyze_paths`@386 |
| `tools/ai_defense.py` | 141 | AI/MCP defense analysis (prompt injection, tool auth, IFC, MCP OAuth). `analyze_paths`@115 |
| `tools/paper_intel.py` | 2,096 | **Largest module** — offline adapters from 2026 security papers: skill-chain risk, provenance bottleneck, CTI→Sigma, binary RE planning, STAR HTTPS metadata privacy, agent control-plane audit. 20+ analyzers (`scan_skill_chain`@348, `investigate_provenance`@471, `ground_cti_to_sigma`@622, `analyze_https_fingerprint`@948, `assess_agent_control_plane`@1102, `match_cve_candidates`@1433, …) |
| `tools/threat_intel.py` | 659 | HackerOne hacktivity fetch, CVE→target mapping, ransomware mentions. `ThreatIntel`@443, `IntelMonitor`@543 |
| `tools/recon_engine.sh` | 718 | Bash recon engine: subdomain/DNS/port/tech collection + research hooks (NOT Python; shell syntax verified) |
| `tools/trust_map.py` | 720 | Directed trust graph across target. `TrustMap`@126 (add_node/add_edge/attach_capability), `bootstrap_from_recon`@539 |
| `tools/recon/historical_asset_delta.py` | 460 | Passive-DNS/CRT churn tracker. `compute_delta`@238, `ingest_historical`@322 |

### 7.3 Discovery core (Web/API)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/surface_model.py` | 869 | Structured Web/API attack-surface model from OpenAPI/GraphQL/URLs. `SurfaceModel`@132, `parse_openapi`@331, `parse_graphql`@410, `parse_urls`@487, `infer_vhost_candidates`@736 |
| `tools/mutator.py` | 468 | Structure-aware mutation plans (one variable at a time). `Mutator`@199 (_boundary/_mass_assignment/_pollution/_injection/_state_mutations) |
| `tools/discovery_scheduler.py` | 419 | Coverage-aware, impact-ranked scheduling of mutations + oracle loop. `DiscoveryScheduler`@140 (rank/allocate/follow_up_step/run) |
| `tools/art_selector.py` | 630 | ART4SQLi payload selection (Zhang et al.): TF-IDF token vectors, `1/cosine` spacing. `PayloadSpace`@225, `select_next`@407, `f_measure`@519 |
| `tools/differential.py` | 198 | Differential divergence detector (rule 4). `DifferentialDetector`@72 |
| `tools/differential_runner.py` | 366 | Live sibling-differential replay (v1/v2 surfaces). `DifferentialRunner`@149, `score_divergence`@82 |
| `tools/header_trust.py` | 679 | Forwarded/trust-header taxonomy + probe planner + live replay. `HeaderTrustRunner`@490, `build_probes`@336, `build_host_confusion_probes`@373 |
| `tools/contract_discovery.py` | 588 | Smart-contract state-space exploration (invariants, sequences, minimization). `ContractDiscoveryScheduler`@406, `ContractExecutor`@301 |
| `tools/cache_traversal.py` | 521 | Cache-key path-traversal track (CVE-2026-18051 class). `TraversalRunner`@333, `build_plan`@235, `classify_replay`@304 |
| `tools/graphql_gid.py` | 455 | GraphQL `node(id:)` global-id harvesting + bounded candidates. `analyze_introspection`@115, `harvest_gids`@184, `build_candidates`@244 |

### 7.4 Research / candidate track

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/research_core.py` | 537 | Coverage-guided state-aware research substrate: `CoverageTracker`@74, `CorpusManager`@158, `CrashRegistry`@254, `StateCoverage`@372 |
| `tools/research_model.py` | 208 | Shared candidate data model: `ResearchCandidate`@103 (stable_id/transition/add_evidence/has_impact_evidence) |
| `tools/research_sources.py` | 237 | Provenance-bound research registry: `SourceRegistry`@112, `strip_instructions`@67 |
| `tools/zero_day_tracks.py` | 571 | Deterministic adapters for 5 surfaces: `WebApiTrack`@228, `SmartContractTrack`@407, `CloudCicdTrack`@465, `LlmAgenticTrack`@499, `MobileBinaryTrack`@531, `synthesize_chains`@155 |
| `tools/novelty.py` | 279 | Novelty assessment (exact/near matches, never claims zero-day). `NoveltyEngine`@126 (assess/apply/research_sequential/parallel) |
| `tools/impact_focus.py` | 284 | Criticality router — focus on high/critical first. `CriticalityRouter`@175 |
| `tools/impact_validation.py` | 299 | Candidate evidence-state machine (hypothesis→signal→candidate→reproduced→…). `CandidateStateMachine`@127 |
| `tools/triage.py` | 205 | Triage + disclosure gates. `CandidateTriage`@63 (evaluate/quarantine/enter_review/approve/report) |
| `tools/adaptive_learning.py` | 466 | Quarantined learning memory (records, not code). `AdaptiveMemory`@127 (ingest/review/mark_used), `learn_from_journey`@307 |
| `tools/methodology_playbook.py` | 540 | 2026 methodology → human-validation tasks + non-executing tool plans. `build_validation_tasks`@335, `build_tool_plans`@351 |
| `tools/idor_research.py` | 603 | Offline IDOR/BFLA planning across 10+ reference classes. `build_idor_matrix`@480, `build_bfla_matrix`@337 |
| `tools/post_finding_trigger.py` | 467 | Post-finding/signal triggers: receipts, chain-graph refresh, queue. `trigger_after_finding`@190, `trigger_after_signal`@270 |

### 7.5 Governance, evidence, safety, support

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/safety.py` | 123 | **UNCENSORED pass-through** — all authorization functions unconditional (`target_in_scope` always True, `require_authorized_target` always passes) |
| `tools/execution_controller.py` | 154 | **UNCENSORED controller** — all gates removed; operational budget fields only (max_requests/max_seconds). `ExecutionPolicy`@36, `ActiveExecutionController`@73 |
| `tools/evidence.py` | 227 | Redacted evidence + deterministic replay artifacts. `EvidenceStore`@118 (add/add_replay_fixture/verify), `redact`@84 |
| `tools/state.py` | 511 | JSONL session state engine. `SessionState`@102, `add_finding`@300, `rotate_state`@407, `find_chain_candidates`@443 |
| `tools/chain_of_custody.py` | 585 | Tamper-proof per-finding audit trail (hash chain). `ChainOfCustody`@111 (init_chain/log_event/verify_chain) |
| `tools/crypto_vault.py` | 539 | Encrypted artifact store + secure deletion (AES/age). `Vault`@246 |
| `tools/chain_orchestrator.py` | 568 | Full-chain orchestrator: nodes/edges from leads, chain scoring, validation queue. `orchestrate`@325, `refresh_target`@424 |
| `tools/deep_chain.py` | 216 | Multi-hop chain synthesis beyond pairwise patterns. `DeepChainSynthesizer`@104 |
| `tools/capability_registry.py` | 733 | Catalog of discovered primitives. `CapabilityRegistry`@223 |
| `tools/program_fit.py` | 604 | Program-fit gate (HackerOne/Bugcrowd/etc. scope/noise filter). `ProgramFitGate`@188 |
| `tools/formal_verify.py` | 544 | Smart-contract formal verification bridge (Certora/Echidna harness generation). `FormalVerifyBridge`@384 |
| `tools/pii_firewall.py` | 325 | Deterministic PII masking before egress (nested JSON/XML, reversible in-memory tokens). `PIIFirewall`@206 |
| `tools/data_governance.py` | 153 | Schema field classification + Kafka encryption/ACL/retention plans |
| `tools/engagement_context.py` | 274 | Recorded execution context (accountability, never a gate). `record_context`@96, `stamp_operation`@146 |
| `tools/environment_profile.py` | 221 | Environment preflight (local/VPS/container). `EnvironmentProfile`@47, `collect_environment`@130 |
| `tools/harness_guard.py` | 304 | Session contract verifier (`--verify --json` → ready true/false). `initialize`@144, `verify`@171 |
| `tools/harness_command.py` | 171 | Parses `bugwolf --full attack this target …` invocations. `parse_invocation`@74 |
| `tools/harness_intelligence.py` | 210 | Offline reasoning brief builder. `build_brief`@120 |
| `tools/readiness.py` | 289 | Validates `configs/readiness.json` vs the live tree. `validate_manifest`@87 |
| `tools/reporting.py` | 351 | Review/reporting/disclosure gate. `ReportingGate`@140 (check/review/disclose) |
| `tools/release_ops.py` | 208 | SBOM build, bundle check, smoke imports |
| `tools/benchmark.py` | 244 | Runs benchmark corpus vs VulnBank. `run_benchmark`@125 |
| `tools/wordlist_gen.py` | 538 | Dynamic wordlist generation (no static lists). `generate`@418 |
| `tools/llm_attack_surface.py` | 384 | LLM/agentic AI attack-surface scanner. `LLMAttackSurfaceScanner`@209 |
| `tools/static_bridge.py` | 359 | Static analysis / patch-gap bridge: source fingerprinting, patch analysis, dep verification. `SourceFingerprinter`@104 |
| `tools/runtime_paths.py` | 40 | Workspace/slug helpers used by every module (`target_slug`, `workspace_root`, `runtime_path`) |
| `tools/stage_controller.py` | 21 | **Compatibility shim** → `tools.core.stage_controller` |
| `tools/research_loop.py` | 21 | **Compatibility shim** → `tools.core.research_loop` |
| `tools/campaign_orchestrator.py` | 20 | **Compatibility shim** → `tools.core.campaign_orchestrator` |
| `tools/agent_bus.py` | 20 | **Compatibility shim** → `tools.core.agent_bus` |

---

## 8. `tools/domains/` — leaf domain modules (14, publish onto signal bus)

### api (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/api/bopla_matrix.py` | 450 | BOPLA (OWASP API3) object-property-level authz matrix from OpenAPI schemas. `build_matrix`@206 |
| `tools/domains/api/graphql_batch_analyzer.py` | 452 | GraphQL batching/DoS/introspection abuse plans. `_introspection_plans`@165, `analyze`@364 |

### auth (3)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/auth/jwt_forgery.py` | 305 | Offline JWT analysis: alg header inventory + forgery plans (alg=none, confusion, weak HMAC). `analyze`@172 |
| `tools/domains/auth/oauth_flow_analyzer.py` | 436 | OAuth/OIDC endpoint/flow parsing from recon artifacts + validation plans. `analyze`@183 |
| `tools/domains/auth/ato_chain_planner.py` | 378 | Account-takeover chain synthesis from leads (email/reset/MFA/session/OAuth/JWT + enablers). `plan_chains`@282 |

### cloud (1)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/cloud/iam_privesc_graph.py` | 559 | AWS IAM privilege-escalation graph (21 Rhino methods) — offline capability analysis. `IamPrivescAnalysis`@370, `analyze`@435, `parse_policy_dump`@391 |

### llm (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/llm/agentic_tool_auth.py` | 382 | Tool-call sites × attacker-influenced args → "tool X with attacker-controlled Y" plans. `analyze`@164 |
| `tools/domains/llm/rag_memory_poisoning.py` | 390 | RAG/agent-memory poisoning vector ranking. `analyze`@173 |

### mobile (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/mobile/deep_link_analyzer.py` | 449 | Android manifest/iOS plist deep-link surface planning. `parse_android_manifest`@156, `parse_ios_links`@212, `analyze`@259 |
| `tools/domains/mobile/mobile_policy_checker.py` | 370 | Deterministic static manifest/plist policy checks (cleartext, backup, exports, …). `analyze`@272 |

### smart_contracts (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/smart_contracts/llm_contract_triage.py` | 365 | Exploitability ranking of static smart-contract findings (OpenAnt-style). `triage`@239 |
| `tools/domains/smart_contracts/price_manipulation_analyzer.py` | 336 | DeFi oracle/price manipulation lifecycle plans. `analyze`@259 |

### web (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/web/http_smuggling_detector.py` | 471 | HTTP request smuggling probe generator + oracle (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, 0.CL…). `build_plan`@246, `evaluate`@321 |
| `tools/domains/web/parser_differential.py` | 383 | WAFFLED-style WAF-bypass payload family generator. `generate`@236, `make_waf_blocked_listener`@290 |

---

## 9. `tools/intelligence/` · `recon/` · `validation/` (6 modules)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/intelligence/chain_graph_ai.py` | 336 | Missing-link chain proposals on the deep_chain graph. `propose`@134 |
| `tools/intelligence/failure_learning.py` | 408 | Blocker → bypass-candidate feedback loop + **operator approval gate**. `BypassCandidate`@155, `learn`@189, `approve_candidate`@293, `make_blocked_listener`@344 |
| `tools/intelligence/seed_advisor.py` | 336 | Seed/mutation probe proposals for research units. `advise`@222 |
| `tools/recon/historical_asset_delta.py` | 460 | Passive-DNS/CRT churn tracking (see §7.2) |
| `tools/validation/self_eval_harness.py` | 667 | AutoPenBench-style milestone scoring against fixed task set. `Milestone`@76, `EvalTask`@86, `evaluate`@137 (10 tasks, 100% = pass) |
| `tools/validation/verification_lab.py` | 393 | Disposable dynamic-validation lab plans (container/dir spec, setup→reproduce→verify→cleanup). `plan_labs`@276 |

---

## 10. `tests/` — 70 files, 920 tests, 15,141 lines

### 10.1 End-to-end / integration (largest)
| Test file | Lines | Covers |
|---|---|---|
| `tests/test_zero_day_research.py` | 957 | Zero-day candidate lifecycle, tracks, novelty, sequential rounds, exploit feedback |
| `tests/test_e2e_deep_dive_campaign.py` | 608 | Full campaign against in-process VulnBank: probe→observe→adapt→exploit→eval |
| `tests/test_live_feedback_loop.py` | 604 | Live probe→observation→adaptation cycle + WAF bypass approval cycle |
| `tests/test_apt_commander_week1.py` | 480 | Week-1 APT workflow: stage gating, artifacts, research freshness |
| `tests/test_ci_bundle_check.py` | 452 | Bundle content + self-eval-pass check (incl. tamper failure path) |
| `tests/test_research_loop.py` | 425 | Mandatory research sequence execution + freshness verification |
| `tests/test_observation.py` | 417 | Oracle rules R1–R7, hash integrity, follow-ups |
| `tests/test_discovery_core.py` | 409 | Surface model + mutator + scheduler coverage loop |
| `tests/test_leads.py` | 407 | Lead state machines, mutations, promotion, data-unlock/chain hypotheses |
| `tests/test_paper_intel.py` | 390 | Paper-derived analyzers (skill-chain, provenance, HTTPS privacy, control plane) |
| `tests/test_f05_strict_validation.py` | 337 | F0.5 strict-mode triage/refutation gates |
| `tests/test_live_executor.py` | 328 | Probe planning/execution, WAF detection, reproducible evidence |
| `tests/test_week8_selfeval_workflow_integrity.py` | 326 | Self-eval harness + workflow integrity interplay |
| `tests/test_week3_cloud_mobile_recon.py` | 305 | IAM privesc graph, mobile analyzers, recon delta |
| `tests/test_week2_bfa_graphql_oauth.py` | 305 | BOPLA matrix, GraphQL batch, OAuth flow analyzers |
| `tests/test_week6_ato_failurelearning_chaingraph.py` | 285 | ATO chains, failure learning + approval, chain graph AI |
| `tests/test_art_selector.py` | 284 | ART4SQLi tokenization/distance/F-measure |
| `tests/test_packaging.py` | 254 | Installer/bundle layout verification |

### 10.2 Unit suites (remaining 50+ files, grouped)
- **Workflow/gates:** `test_stage_controller` (247), `test_campaign_orchestrator` (242), `test_f05_campaign_gate` (180), `test_f05_quarantine_integrity` (196), `test_phases_2_5_6` (143), `test_phases_7_8` (109), `test_pipeline` (149), `test_fast_path_engine` (146), `test_engagement_context` (108), `test_environment_profile` (57), `test_safety_boundaries` (195)
- **Research/novelty:** `test_week4_llm_smartcontract_verification` (241), `test_week5_advisor_dynamic_checkpoints_pricemanip` (213), `test_deep_tools` (205), `test_safe_research_tracks` (191), `test_llm_attack_surface` (195), `test_batch_tracks` (164), `test_research_core` (108), `test_elicitation_bridge` (177), `test_adaptive_learning` (106), `test_pass_at_k` (180)
- **Domains:** `test_graphql_gid` (178), `test_cache_traversal` (173), `test_header_trust` (194), `test_contract_discovery` (212), `test_differential_runner` (107), `test_vhost_grouping` (119), `test_hunt_engine` (128), `test_hunt_chain_integration` (39), `test_schema_extractor` (146)
- **Infra/tooling:** `test_hardening` (241), `test_integrity` (149), `test_integrity_hardening` (133), `test_trigger_ledger_integrity` (81), `test_chain_orchestrator` (109), `test_chain_ai` (97), `test_harness_guard` (113), `test_harness_command` (60), `test_harness_intelligence` (60), `test_readiness` (112), `test_benchmark` (86), `test_agent_bus_trigger` (114), `test_model_router` (126), `test_opsec` (150), `test_wordlist_gen` (219), `test_methodology_playbook` (84), `test_post_finding_trigger` (102), `test_privacy_governance` (54), `test_js_ct_intel` (97), `test_js_token_forge` (94), `test_tech_fingerprint` (199)
- **Fixture:** `tests/fixtures/agent-inventory-security-gaps.json` — synthetic agent inventory for `paper_intel.assess_agent_control_plane` (test-only, no real data)

---

## 11. `references/` — 53 knowledge docs

### 11.1 Top-level (25)
`adaptive-learning.md`, `al-mizaan-gates.md`, `bug-bounty-intelligence-mcp.md`, `chain-analysis.md`, `cvss-guide.md`, `cwe-knowledge-base.md`, `defensive-intelligence.md`, `discovery-core.md`, `isolation.md`, `judging.md`, `knowledge.md`, `local-tooling.md`, `methodology.md`, `paper-intelligence.md`, `privacy-governance.md`, `recon-tooling.md`, `report-formatting.md`, `research-loop.md`, `setup.md`, `sis-intelligence.md`, `supervisor.md`, `wild-mode.md`, `zero-day-research.md`

### 11.2 `references/hacking-agents/` (22)
`access-control-agent`, `browser-automation-agent`, `business-logic-agent`, `cache-poisoning-agent`, `counter-intelligence-agent`, `credential-leak-agent`, `crypto-math-agent`, `economic-security-agent`, `graphql-agent`, `http-smuggling-agent`, `llm-ai-agent`, `mobile-client-agent`, `race-condition-agent`, `recon-agent`, `regression-agent`, `rogue-agent`, `shared-rules`, `smart-contract-agent`, `supply-chain-agent`, `temp-email-agent`, `waf-bypass-agent`, `web-api-agent` (all `.md`)

### 11.3 `references/attack-vectors/` (8)
`business-logic-vectors`, `cloud-vectors`, `llm-ai-vectors`, `mobile-vectors`, `smart-contract-vectors`, `spel-injection-vectors`, `web-api-vectors`, `zerodays` (all `.md`)

---

## 12. Runtime/state directories (git-ignored)

| Dir | Contents |
|---|---|
| `state/` | Runtime state: `learning/<target>.jsonl`, `chains/<target>/orchestration.{json,jsonl}`, sessions, signals, context, environment.json |
| `$WS/` | Example workspace: full `research/synth.example/` tree (pre-hunt→pre-report, wordlists, sources) + `.bugwolf/workflows/synth.example.json` |
| `.bugwolf/` | Persistent workflow state per target (`workflows/<target>.json`, `.jsonl`) |
| `recon/` | Recon output (e.g. `vulnbank.local/discovery/graphql-plans.json`, `ato-chain-plans.json`) |
| `research/` | Research checkpoints per target (`<target>/pre-hunt|post-recon|post-maps|bypass|post-findings|escalation|pre-report` with SUMMARY.md/results.json/sources/) |
| `dist/` | Built bundles: `bugwolf-v1.2.10.skill` + `bugwolf-v1.2.10.freebuff.zip` |
| `.private/`, `vault/` | reserved (empty) |
| `wordlists/resolvers.txt` | 24 public DNS resolvers used by recon |

---

## 13. Dependency architecture (from `DEPENDENCIES.md`, AST-verified)

- **Leaf isolation:** `domains/`, `intelligence/`, `recon/`, `validation/` are imported by **nothing**; they publish typed events onto `core/signal_bus.py` (`publish_or_warn`) and are invoked as standalone CLIs.
- **Only 2 direct leaf imports:** `core/campaign_orchestrator.py → intelligence/failure_learning.py` + `intelligence/seed_advisor.py`.
- **Orchestrator fan-in:** imports asset_discovery, campaign, chain_orchestrator, leads, mutator, refutation, research_model, research_thread, stage_controller, zero_day, core/{fuzz_bridge, live_executor, model_router, signal_bus, research_loop}, intelligence/{failure_learning, seed_advisor}.
- **Core internals:** `stage_controller → harness_guard, paper_intel`; `fuzz_bridge → live_executor, signal_bus, mutator, schema_extractor`; `research_loop → adaptive_learning, wordlist_gen`; `agent_bus → evidence, post_finding_trigger, safety`; `live_executor/signal_bus → runtime_paths`.
- **Upward coupling:** all leaf modules → `runtime_paths.py` for workspace resolution.

---

## 14. Working-tree delta (uncommitted, 86 files, +4,783/−1,059)

Largest uncommitted changes since `06b08ff`:
- `tools/core/campaign_orchestrator.py` **+897** — exploit feedback wiring (`_feed_exploit_to_chains`/`_feed_exploit_to_zero_day`), bypass-approval exploitation, self-eval integration
- `tools/zero_day.py` **+475** — `hunt_exploit_feedback`, impact-bounded unlocks, exploit provenance stamping
- `tools/refutation.py` **+398** — F0.5 strict gates expansion
- `tools/validation/self_eval_harness.py` **+305** — 10-task eval, bypass-approval milestone
- `tools/research_thread.py` **+231** — deterministic artifact attachment
- `tools/state.py` **+142** — session-state hardening
- `tests/test_zero_day_research.py` **+292**, `tests/test_ci_bundle_check.py` **+132**, `tests/test_apt_commander_week1.py` **+96**
- `tools/intelligence/failure_learning.py` **+98** — `approve_candidate` operator gate
- `tools/leads.py` **+117** — `derive_data_unlock_classes`/`chain_hypotheses_from_exploit`
- Plus small (+3/+4) additions to nearly all domain/intelligence modules (signal-bus publish wiring)
- `lab/vulnbank/server.py` +31 — `/api/gateway` WAF surface
- Docs: `CHANGELOG.md` +373, `AUDIT.md` regenerated, `README.md` +37, `SKILL.md` +35, `VERSION` → 1.2.10

---

## 15. Verification status (2026-08-26)

```
python3 -m unittest discover -s tests -p 'test_*.py'   → Ran 920 tests, OK
python3 -m compileall -q tools tests lab               → clean
bash -n tools/recon_engine.sh                          → syntax OK
python3 scripts/generate_audit.py                      → AUDIT.md regenerated
```

**Notable observations:**
1. `safety.py`, `execution_controller.py`, `recon_exec.py` are deliberately pass-through ("uncensored") — authorization is operator-declared context, enforced by workflow artifacts (stage prerequisites, evidence, human review) rather than target/scope rejection. This is the documented design intent (`README`, `SKILL.md`, `configs/readiness.json`).
2. The engineering-control layer is strong: evidence redaction (`evidence.py`), PII firewall, chain of custody, tamper-evident workflows, quarantined learning memory, replayable evidence requirements before CONFIRMED.
3. Runtime state, research output, and bundles are git-ignored; the tracked tree is pure source + docs.

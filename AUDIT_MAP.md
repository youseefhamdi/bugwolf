# BugWolf — Complete File Map & Line-by-Line Audit

> Hand-compiled engineering map of the full BugWolf plugin, **v1.3.0 → v1.4.0-multi-agent**
> (`VERSION`), working tree on `main` (`5a61907` + multi-agent layer).
> Every tracked source file is listed with its line count, purpose, and key
> definitions (class/function with starting line). Companion to the
> auto-generated `AUDIT.md` (run `python3 scripts/generate_audit.py`).
> Verified 2026-09-03 (post-multi-agent + intel): **1,383 tests pass (2 skipped)**,
> `compileall` clean, `recon_engine.sh` + all `scripts/*.sh` syntax OK,
> CI bundle check passes, 28 agent definitions in sync (`generate_agents.py --check`).
> v1.4 adds the multi-agent layer (§17): specialized agent registry,
> real model-tier dispatch, and the team execution engine.
> v1.5 adds the deep-research layer (§18): live intel (NVD/GitHub/KEV/Reddit/HN
> + harness-executed X/Medium/dork plans) feeding every agent dispatch, with
> operator-gated technique quarantine.

---

## 1. Scale at a glance

| Area | Files | Lines |
|---|---|---|
| `tools/` Python (all) | 180 (167 modules + 13 `__init__.py`) | 70,161 + 13 |
| — `tools/runtime/` (v1.3.0 mission layer) | 13 | 9,252 |
| — `tools/core/` | 10 | 6,733 |
| — `tools/domains/` (14 modules) | 21 | 5,726 + 7 |
| — `tools/intelligence/` | 4 | 1,080 + 1 |
| — `tools/recon/` | 3 | ~750 + 1 |
| — `tools/validation/` | 4 | 1,391 + 1 |
| — `tools/*.py` top-level | 126 | 47,611 |
| `tests/` | 130 test files, 1,334 tests (2 skipped) | 22,691 |
| `references/` | 53 docs (22 hacking-agents, 8 attack-vectors) | — |
| `scripts/` | 6 | ~940 |
| `configs/` | 10 | ~1,270 |
| `bridge/` | 1 (MCP stdio server) | 175 |
| `commands/` | 9 slash-command prompts | — |
| `hooks/` | 2 (hooks.json + stop/session hook) | ~170 |
| Runtime state (`state/`, `.bugwolf/`, `recon/`, `research/`, `dist/`) | ignored by git | — |
| **Total tracked source** | **~440 files** | **~142,000** |

Top-level layer map:

```
README/SKILL/CHANGELOG/AUDIT/AUDIT_MAP/*PLAN*/DEPENDENCIES/VERSION  → docs & plans
.claude-plugin/plugin.json   → manifest: 9 commands, hooks, SKILL.md
commands/                    → /bugwolf + 8 subcommand prompts
hooks/                       → SessionStart preflight digest + Stop freeze shim
bridge/bugwolf-mcp.py        → MCP (JSON-RPC over stdio) server: status/plan/run/leads/mode
configs/                     → JSON contracts (readiness, benchmark, fin_logic, models,
                               harness, freebuff-deepseek)
scripts/                     → build / install / CI / audit generators / lab compose
tools/                       → 167 Python modules (the engine)
  tools/runtime/             → 13 modules (9,252 lines): mission runner, task-graph
                               scheduler, contracts, scope gate, sandbox, preflight,
                               lead protocol, persistent modes, accounts, OAST
  tools/core/                → 10 modules: campaign orchestrator, stage controller,
                               agent registry (v1.4 multi-agent), model router
                               research loop, live executor, fuzz bridge, agent bus,
                               signal bus, model router
  tools/domains/             → 14 leaf modules: api, auth, cloud, llm, mobile,
                               smart_contracts, web
  tools/intelligence/        → 3: chain_graph_ai, failure_learning, seed_advisor
  tools/recon/               → 2: historical_asset_delta, depth_ladder
  tools/validation/          → 3: race_engine, self_eval_harness, verification_lab
  tools/*.py                 → ~120 top-level tools (hunt, zero_day, leads, paper_intel, …)
tests/                       → 130 unittest files (stub-target e2e suite)
references/                  → 53 markdown knowledge docs (agents, vectors, methodology)
```

**Architecture in one sentence:** a *strict workflow layer* (12-stage
hash-chained stage controller + 7-checkpoint mandatory research loop +
evidence/human-review gates) sitting on top of a *boundary-enforced
execution layer* — `tools/runtime/scope.py` enforces the operator-declared
scope deny-by-default at every network choke point, `tools/runtime/sandbox.py`
wraps every spawn with a binary allowlist + env scrub + kill switch, and
`tools/runtime/mission_runner.py` drives domain lanes as durable task graphs
with lead ladders — while domain modules publish typed events onto
`core/signal_bus.py` that the campaign orchestrator subscribes to.

---

## 2. Root documentation & plans

| File | Lines | Purpose |
|---|---|---|
| `README.md` | 891 | Product overview, APT Commander architecture, install (npx/offline), per-tool usage, live harness loop, bugwolf.xyz |
| `SKILL.md` | 2,705 | The skill definition: universal harness contract `BUGWOLF-HARNESS-CONTRACT-V2`, target intake + attestation, strict workflow, 12-stage pipeline, 5-pillar maps, lead ledger, wild-mode doctrine, research loop R1–R7, deep-hunt tool suite |
| `CHANGELOG.md` | ~900 | v1.0.0 → v1.9.2 (latest: recomposition, dispatch pinning, recon depth ladder, operator preflight/status depth reporting) |
| `AUDIT.md` | 82 (generated) | Auto-generated inventory by `scripts/generate_audit.py` — do not hand-edit |
| `AUDIT_MAP.md` | this file | Full hand-compiled file map |
| `BUGWOLF_ORCHESTRATOR_PLAN_V2.md` | 550 | Orchestrator plan v2: task graph, lead ladder, modes, preflight, sandbox/scope (sections cited by `tools/runtime/`) |
| `BUGWOLF_OMC_UPGRADE_PLAN.md` | 834 | Oh-My-Codebase upgrade plan |
| `PRIVATE_LAB_UPGRADE_PLAN.md` | 592 | Private-lab upgrade plan (compose stack, doctor, lifecycle) |
| `READYNESS_PLAN.md` | 644 | Full-power APT readiness: depth never reduced by gates; authorization = recorded context |
| `ENHANCEMENT_PLAN.md` | 372 | 2026 research-window enhancement roadmap (WAFFLED, IAM privesc, agentic AI) |
| `MISSION_PLAN.md` | 231 | Mission plan: capability truth/readiness telemetry, execution reliability, evidence-state hardening |
| `PLAN_AUDIT.md` | 84 | Plan-vs-implementation audit notes |
| `DEPENDENCIES.md` | 135 | AST-verified import graph: leaf modules publish to `core/signal_bus.py`, nothing imports them |
| `VERSION` | 1 | `1.9.2` |
| `LICENSE` | — | project license |
| `.gitignore` | 14 | ignores state/, .private/, vault/, recon/, research/, dist/, __pycache__/, .bugwolf/ |

---

## 3. `configs/` — JSON contracts (10 files)

| File | Lines | Purpose |
|---|---|---|
| `configs/readiness.json` | 238 | Machine-readable readiness contract: `L2-reproducible-research-harness`, release status `experimental-human-supervised`, execution profiles, per-target-class entrypoints/evidence/limitations |
| `configs/benchmark.json` | 119 | Versioned benchmark corpus (v2): case → bug_class/method/path/expected finding+severity, business_logic `signal_check`, requires `--base-url` (operator target, no hardcoded lab endpoint) |
| `configs/fin_logic.json` | 50 | Canonical 41-entry FIN-* business-logic technique registry (TOCTOU/PARAM/REPLAY/ROUND/NUM/VOUCHER/CRYPTO/TESTDATA/ARIBITRAGE) |
| `configs/models.json` | 40 | Model routing tiers for `tools/core/model_router.py` |
| `configs/freebuff-deepseek.json` | 54 | Freebuff/DeepSeek deployment contract: install paths, model tiers, harness guard commands, verification list |
| `configs/freebuff/AGENTS.md` | 98 | Freebuff project contract (harness-neutral) |
| `configs/harness/AGENTS.md` | 114 | Universal project contract for any harness |
| `configs/harness/CLAUDE.md` | 91 | Claude Code-specific contract |
| `configs/harness/BUGWOLF.md` | 212 | The short reloadable operating contract (deep-hunt tool suite + mandatory research order) |
| `configs/harness/intelligence.json` | 75 | Reasoning/creativity contract: creative angles, evidence states, handoff fields, direct-invocation behavior |

---

## 4. `scripts/` + CI (6 files)

| File | Lines | Purpose |
|---|---|---|
| `scripts/build_skill.sh` | 78 | Builds both release bundles: `dist/bugwolf-v<V>.skill` (SKILL.md at root, Claude.ai) and `dist/bugwolf-v<V>.freebuff.zip` (`.agents/skills/bugwolf/` layout) |
| `scripts/ci_bundle_check.sh` | 469 | CI: rebuild bundles, content-verify (self-eval harness ships, VERSION matches, no .pyc), extract freebuff bundle and run its own self-eval → must score 100% |
| `scripts/generate_audit.py` | 231 | Deterministic AUDIT.md generator (AST counts, module stats, CLI detection) |
| `scripts/install_freebuff.sh` | 60 | Offline install into `.agents/skills/bugwolf/` + install BUGWOLF.md/AGENTS.md/CLAUDE.md if absent + init harness manifest |
| `scripts/install_harness_contract.sh` | 31 | Install only the short harness contract + init manifest (no skill copy) |
| `scripts/lab_setup.sh` | 56 | Optional compose stack up/down (browser, Android, Anvil, Ollama, MCP, LocalStack) for local validation only — never a production boundary |
| `.github/workflows/ci.yml` | 52 | GitHub Actions: unittest suite + bundle check + artifact upload (python 3.12) |

---

## 5. `tools/runtime/` — the v1.3.0 mission layer (13 modules, 9,252 lines)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/runtime/mission_runner.py` | 2,942 | **Mission runner — the orchestrator brain.** Domain lanes as probe swarms: BOLA (direct/enumeration/scope/role/mass-assignment/hidden), header-trust, WAF bypass (X-Original-URL, path obfuscation, encoding, parser differential, case rotation, payload splitting), A/B/C auth matrix, FIN business-logic matrix (incl. a hand-rolled SHA-256 length-extension attack), contract/cloud/LLM matrices; verify lane replays winning techniques; lead ladder R1–T4. `http_probe`@93 (scope-gated), `replay_bola_technique`@267, `replay_bypass_technique`@665, `replay_auth_technique`@936, `_length_extend`@1411, `replay_fin_technique`@1523, `MissionRunner`@2242, `main`@2860 |
| `tools/runtime/contracts.py` | 618 | Structural result contracts, all hash-digested: rejects TaskResults that mention an "insight" without a lead ref. `ContractViolation`@116, `ToolReceipt`@183, `TaskSpec`@218, `validate_task_result`@350, `MissionSpec`@432, `parse_mission`@509, `record_task_result`@591, `main`@606 |
| `tools/runtime/scheduler.py` | 490 | Durable task-graph scheduler: fingerprinted nodes, credential redaction on save, preflight gate before any dispatch, resume re-dispatches open leads first. `task_fingerprint`@59, `_redact_mission_credentials`@139, `Scheduler`@171 (`plan_mission`@249, `record_preflight`@396, `resume`@423, `status`@451), `main`@462 |
| `tools/runtime/sandbox.py` | 446 | Subprocess sandbox + kill switch: binary allowlist + operator grants, scrubbed env, output caps, fail-closed audit (`state/sandbox/audit.jsonl`); kill switch fails CLOSED incl. corrupt marker. `engage_kill_switch`@114, `sandboxed_run`@243, `verify_sandbox`@327, `main`@386 |
| `tools/runtime/lead_protocol.py` | 449 | Anti-satisficing lead ladder (R1 insights→LeadSpec, R2 three terminal states PWNED/REFUTED/BUDGET-EXHAUSTED, R3 technique matrix recorded-tried, R4 research refresh, R5 append-only JSONL, R6 resume re-dispatch); composes `tools/leads.py` |
| `tools/runtime/preflight.py` | 419 | Mandatory pre-flight PF capability discovery (binaries, modules, MCP connections) with cached manifest + digest (read by the SessionStart hook, <10 ms). `inventory`@297, `run_preflight`@334, `capability_digest`@324, `main`@397 |
| `tools/runtime/accounts.py` | 401 | Operator-supplied A/B/C account matrix (attacker/victim/admin); tokens memory-only, redacted to `{kind}:<first4>...({len})`, `__redacted__` sentinel never replayed. `redact`@56 |
| `tools/runtime/modes.py` | 348 | Persistent modes engine (research/verify/deep-dive/coverage/report) with JSONL journal + replay on stop/resume; zero-open-leads report gate. `ModeEngine`@94 (`enter`@176, `tick`@208, `stop`@140, `resume`@150) |
| `tools/runtime/oast.py` | 254 | Self-hosted OAST: per-lead canary tokens (`oast<sha256(lead)[:12]>`), durable interaction registry, `OAST_CALLBACK` signal publication; unregistered canaries recorded but never attributed. `_canary_token`@52 |
| `tools/runtime/oast_tunnel.py` | 239 | Auto-armed SSH reverse tunnel so remote-target SSRF leads close on attributed public callbacks (`--oast` + `BUGWOLF_OAST_TUNNEL=1`). `OastTunnel`@46, `arm_from_env`@162, `selftest`@184 |
| `tools/runtime/scope.py` | 293 | **Deny-by-default operator scope gate.** Target host + explicit `--scope` entries allowed; `--exclude` carve-outs ALWAYS beat wildcards; fail-closed `ScopeViolation`; process-global, idempotent re-bind, refuses target mixing. `ScopeGate`@56 (`check`@124), `bind_target`@196, `check_url`@209, `load_scope_file`@229 |
| `tools/runtime/team.py` | 620 | **v1.4: Multi-Agent Team Engine** — waves recon→hunt(parallel specialists)→verify→report; ThreadPoolExecutor bounded by budget; append-only `team/runs.jsonl` ledger; atomic `team/state.json` checkpoints (write+fsync+rename); `TeamEngine`@~215 (`plan`@~330, `run`/`resume`@~430, `_recover_stale`@~410 heartbeat>15min fail-closed, `stop`@~570); member dispatch carries prompt+digest+scope+sandbox flags; no worker bound ⇒ BLOCKED evidence (first-class terminal), never fabricated; typed `TeamMessage` handoffs persisted to `messages.jsonl`. **v1.7: finding-driven recomposition** — hunt members may recommend unstaffed bug classes (`recommended_bug_classes` result field or `kind: agent_recommendation` messages); `_recommendations_from_results` + `_add_specialist`@~mid grow the roster mid-mission (registry-deterministic selection, budget-capped, deduped, workflow-safe); grown rosters re-enter the hunt wave before verify; every add/skip recorded in `state["recompositions"]` + runs ledger (`recomposed` events) + `TEAM_RECOMPOSED` signals; `--no-recompose` pins the roster; preference persists in `state.json` (`recompose`) and survives resume. **v1.8: architecture/ops hardening** — single shared wave driver `_drive_waves` (`run()`/`resume()` no longer duplicate loop logic), `recompose_waves=(recon,hunt)` (recon findings staff hunt specialists pre-hunt), `max_recompose_rounds=3` re-entry cap (`recompose_capped`/`recompose_rounds` recorded), idempotent ledger via `_recomposed_seen` (rehydrated on load), `preflight()` + CLI `--preflight` readiness report (no execution, no state writes). **v1.9.2: `_recon_depth_report()`** — shared `status()`/`preflight()` section: per-depth covered/total + untried/waived, close blockers (claimed only once a journal exists), evidence recommendations with `role`+`staffed` staffing state; `journal: false` honest degradation. CLI: `--plan/--run/--resume/--status --worker task-tool --timeout --no-recompose --preflight` |
| `tools/runtime/team_dispatch.py` | 421 | **v1.4: Task-tool dispatch bridge** — binds the team engine to live Claude Code subagent dispatch via a durable file queue (`team/dispatch/{jobs,results}/`). Engine side: `TaskToolWorker`@~80 (atomic enqueue, heartbeat refresh while waiting, honest BUDGET-EXHAUSTED on budget expiry). Harness side CLI: `--next` (rename-wins exclusive claim), `--complete`/`--fail`/`--release` (claim-token ownership enforced; impostor ⇒ exit 3), atomic tmp+fsync+rename writes; `bind_heartbeat`@~350 |
| `tools/runtime/native_dispatch.py` | 264 | **v1.6: native in-process dispatch worker** — `NativeTaskWorker` spawns each member's `bugwolf:<role>` subagent as one bounded `claude --print --output-format json` subprocess (prompt on stdin via `run_bounded_subprocess`, argv-only, process-group kill + honest `BUDGET-EXHAUSTED` on timeout, `ResourceLimitError` → FAILED). Honesty contract identical to the file-queue bridge: non-zero exit / empty output / `is_error` ⇒ FAILED, never fabricated DONE; `lead_status` passes through only when valid. `model_map` maps tier preferences to `--model` (**v1.7.1: `DEFAULT_MODEL_MAP` pins the router's preference strings out of the box — `none`→flagless, `slm-fast`→`haiku`, `frontier-reasoning`→`sonnet`; operator `model_map` merges per key; unmapped primary degrades to `fallback_preference`, both unmapped ⇒ flagless, never guessed**); `pin_agent=True` (**v1.7.2**) pins `--agent bugwolf:<role>` from the payload's `harness_role` so headless runs execute the specialist playbook — missing role ⇒ flagless, `pin_agent=False` opts out, `command_builder` still wins and remains the extension point for different flag names or extra flags. Team CLI: `--worker native` |
| `tools/runtime/browser_driver.py` | 162 | Client-side validation behind a `BrowserDriver` protocol; no driver bound → `blocked-browser` evidence lead, never a fabricated result. Scope-gated. `validate_client_side`@103, `blocked_browser_evidence`@156 |
| `tools/runtime/__init__.py` | 0 | package marker |

**Scope-gate choke points (verified):** `check_url` runs in
`runtime/mission_runner.http_probe`@100, `core/live_executor`@367,
`validation/race_engine`@175 (raw sockets), `runtime/browser_driver`@122, and
`hunt._scope_check`@248 (both hunt-engine curl paths — the live-replay
transport for differential_runner, header_trust, cache_traversal);
`recon_engine.sh` validates per-URL before each curl probe.

---

## 6. `tools/core/` — the engine's nervous system (10 modules, 6,733 lines)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/core/campaign_orchestrator.py` | 2,177 | **The plugin's brain.** Full lifecycle: receive target → discover assets → prioritize → research threads → live execution → exploit feedback → self-eval. `CampaignPhase`@81, `OrchestratorContext`@113, `CampaignOrchestrator`@134, `main`@~1979 |
| `tools/core/research_loop.py` | 1,445 | Mandatory deep-research loop (R1–R7 checkpoints). `ResearchTask`@49, `ResearchLoop`@375, `ResearchExecutor`@688, `run_mandatory_research`@~1045 |
| `tools/core/stage_controller.py` | 953 | Persistent no-skip workflow controller. 12 stages (`setup→…→report`), hash-chained artifact prerequisites, append-only artifact integrity. `WorkflowController`@320, `main`@881 |
| `tools/core/live_executor.py` | 829 | Real HTTP probes + replayable evidence; scope-gated at @367. `ProbeSpec`@147, `detect_waf`, `execute_probe`, `verify_reproducibility` |
| `tools/core/fuzz_bridge.py` | 441 | Coverage-aware fuzz loop feeding research threads; publishes FINDING_DISCOVERED. `FuzzObservation`@64 |
| `tools/core/signal_bus.py` | 365 | Event-driven bus ("nervous system"): typed events (`RECON_COMPLETE`, `FINDING_DISCOVERED`, `WAF_BLOCKED`, `OAST_CALLBACK`, `CHAIN_PROPOSAL`, …), persisted JSONL, replay. `SignalBus`@165 |
| `tools/core/agent_bus.py` | 356 | Agent-addressed signal passing (from_agent/to_agents), JSONL persisted + replayed. `AgentBus`@79 |
| `tools/core/model_router.py` | 334 | Deterministic complexity-tier routing (deterministic / local_slm / frontier) with advisory `model_preference` hints; tiers from `configs/models.json` |
| `tools/core/model_router.py` | 334→444 | Deterministic complexity-tier routing (deterministic / local_slm / frontier). **v1.4: real agent dispatch** — `route_agent_dispatch`@~330 (affinity floors: frontier never degrades, deterministic hard-caps), `route_unit_agent`@~395 (registry-bound WHO+tier+fallback; never raises). Tiers from `configs/models.json` |
| `tools/core/agent_registry.py` | 654 | **v1.4: Specialized Agent Registry** — 25 subagents (22 from `references/hacking-agents/` + 4 workflow: verify/chain/report/recon). `AgentSpec`@96, `AgentRegistry`@300 (`select`@~365 deterministic bug-class→domain→generalist→workflow fallback, `dispatch_for`@~410, `compose_team`@~500 budget-capped deterministic roster, `load_prompt` digest-verified anti-tamper). CLI: `--list/--agent/--prompt/--verify/--team` |
| `tools/core/__init__.py` | 1 | package marker |

---

## 7. `tools/` top-level — ~120 tool modules (47,611 lines)

### 7.1 Hunt / execution pipeline

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/hunt.py` | 1,476 | **Hunt Engine** — auth-aware scanner: quick checks, IDOR, active injection, chain-state refresh. All spawns pass the sandbox AND the scope gate (`_scope_check`@248 fails closed with a `scope-blocked:` sentinel in both `curl_fetch`@267 and `curl_fetch_observation`@319 — the audit-2026-09-03 choke-point gap closure); curl credentials go via `--config` stdin, never argv. `build_curl_cmd`@199, `curl_fetch`@267, `curl_fetch_observation`@319, `classify_response`@772, `main`@1041 |
| `tools/zero_day.py` | 1,398 | **Potentially-novel research orchestrator** — candidate generation, refinement, sequential rounds, chain hypotheses, exploit feedback. `ZeroDayResearchEngine`@525, `derive_refinements`@459, `main`@1256 |
| `tools/research_thread.py` | 1,011 | Self-driven research units (threads) with deterministic artifact resolution. `ThreadBuilder`@411 |
| `tools/campaign.py` | 963 | Campaign state engine — persistent APT-level research state. `CampaignState`@338, `CampaignManager`@462 |
| `tools/kill_chain.py` | 907 | Autonomous kill-chain builder from confirmed findings. `KillChainBuilder`@381, `discover_novel_chains`@747 |
| `tools/ledger.py` | 904 | Ledger verifier — evidence, coverage gaps, trigger-stream integrity. `LedgerVerifier`@148 |
| `tools/observation.py` | 861 | Oracle validation layer — raw responses can't silently refute (rules R1–R7). `HttpObservation`@87, `OracleValidator`@379 |
| `tools/patch_gap.py` | 806 | CVE disclosure→patch window planning. `PatchGapMonitor`@530 |
| `tools/leads.py` | 795 | Lead ledger — persistent OPEN-LEAD state machines (OPEN/MUTATING/FINDING/PARKED/KILLED; kill guard auto-parks one-half refutations). `Lead`@123, `create_lead`@230, `mutate_lead`@320 |
| `tools/agent_isolation.py` | 711 | Verifies each agent operates within its domain/scope/permission boundaries. `AgentIsolationChecker`@241 |
| `tools/adversary_emulation.py` | 699 | Agent actions → MITRE-style coverage. `AdversaryEmulation`@433 |
| `tools/infra_deploy.py` | 786 | Callback infra plans: HTTP callback server, DNS listener, interactsh, ngrok. `CallbackServer`@142, `InfraManager`@425 |
| `tools/carlini_loop.py` | 752 | Carlini Loop track — per-file brute-force analysis: unit emission, offline sink-catalog floor, harness-finding intake (idempotent, novelty-deduped) |
| `tools/perf.py` | 734 | Performance harness (orchestrator plan v2 §5.3/§7): the 13 measured perf targets |
| `tools/capability_registry.py` | 733 | Catalog of discovered primitives. `CapabilityRegistry`@223 |
| `tools/exploit_gen.py` | 572 | PoC generation: curl/Python/Burp/Metasploit/nuclei/Solidity templates. `generate_exploit`@478 |
| `tools/retest_scheduler.py` | 573 | Autonomous retest on scope/CVE/dependency changes. `RetestDaemon`@440 (spawn goes through the sandbox) |
| `tools/opsec.py` | 571 | Anti-attribution: proxy pool, UA rotation, header order, jitter. `OpsecRotator`@272, `build_stealth_request`@503 |
| `tools/refutation.py` | 517 | F0.5 precision-first refutation: deterministic confidence, `require_reproducible` forces CONFIRMED to need replayable proof. `RefutationEngine`@201 |
| `tools/fleet.py` | 458 | Parallel multi-target hunting. `FleetExecutor`@232 |
| `tools/lab_lifecycle.py` | 617 | Private-lab lifecycle manager (compose profiles, doctor, readiness) |
| `tools/reliability.py` | 305 | Execution-reliability telemetry (plan v2 §6) |
| `tools/reproducibility.py` | 288 | Deterministic re-execution of recorded commands (sandboxed) |
| `tools/benchmark.py` | 264 | Runs benchmark corpus (v2) against the operator-declared `--base-url`. `run_benchmark`@125 |
| `tools/capability_manifest.py` | 242 | Sandboxed capability self-test manifest |
| `tools/operator_dashboard.py` | 146 | Operator-facing mission/coverage dashboard data |
| `tools/recon_exec.py` | 109 | Uncensored recon command runner (pass-through allowlist) |
| `tools/lab_doctor.py` | 74 | Runtime readiness doctor for the six optional compose services |
| `tools/lab_runtime_adapters.py` | 118 | Adapters degrade MISSING runtimes to explicit diagnostics — never fake results |

### 7.2 Recon / asset intelligence

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/asset_discovery.py` | 583 | Recursive multi-source asset discovery. `AssetDiscoveryEngine`@260 |
| `tools/asset_intel.py` | 415 | Offline provider query plans (Amass/Shodan/Censys/FOFA/ZoomEye/SpiderFoot), ipfinder facets, export diffing. `diff_assets`@~295 |
| `tools/js_ct_intel.py` | 577 | Passive cert-transparency + JS intelligence pipeline. `collect_certificate_records`@198, `analyze_javascript`@~381 |
| `tools/js_token_forge.py` | 252 | Static client-side token-forging analyzer; stores only SHA-256 fingerprints of matched lines. `analyze_text`@107 |
| `tools/tech_fingerprint.py` | 491 | Post-recon tech fingerprinting. `TechFingerprinter`@318 |
| `tools/schema_extractor.py` | 506 | Auto-discovers OpenAPI/Swagger/GraphQL schemas from recon output. `SchemaDiscovery`@90 |
| `tools/chain_analyzer.py` | 273 | Offline high-impact static chain analysis. `analyze_paths`@247 |
| `tools/defensive_detection.py` | 159 | Defensive/lateral-movement/EDR-evasion *detection* hypotheses from logs |
| `tools/identity_cloud.py` | 450 | Identity/MFA/OAuth/SAML/cloud posture + CVE triage. `analyze_paths`@386 |
| `tools/ai_defense.py` | 141 | AI/MCP defense analysis. `analyze_paths`@115 |
| `tools/paper_intel.py` | 2,096 | **Largest module** — offline adapters from 2026 security papers (skill-chain, provenance, CTI→Sigma, binary RE, STAR HTTPS privacy, agent control-plane audit) |
| `tools/threat_intel.py` | 659 | HackerOne hacktivity fetch, CVE→target mapping. `ThreatIntel`@443 |
| `tools/trust_map.py` | 720 | Directed trust graph. `TrustMap`@126, `bootstrap_from_recon`@539 |
| `tools/recon_engine.sh` | 718 | Bash recon engine: subdomain/DNS/port/tech collection + research hooks; per-URL scope validation before each curl probe |
| `tools/recon/historical_asset_delta.py` | 460 | Passive-DNS/CRT churn tracker. `compute_delta`@238, `ingest_historical`@322 |
| `tools/recon/depth_ladder.py` | ~290 | **v1.9: recon depth ladder (D0-D3 anti-satisficing)** — `ReconDepthLedger` append-only JSONL journal (`state/orchestrator/recon-depth/<mission>.jsonl`): `record`/`waive`/`close` events, `untried` (partials never terminal, waivers honored), `close_blockers` (recon's honest exit exam), `coverage` per-depth report. DEPTH_TECHNIQUES canonical families per level; D3 = param-surface/js-route-map/cloud-buckets/mobile-endpoints/historical-crossref. **v1.9.1: `SIGNAL_RULES` + `recommendations()`** — recorded census evidence (bucket hostnames, WAF signatures, secret patterns, mobile endpoints) cross-references into `{bug_class, reason}` recommendations (technique-scoped regex, evidence-based: blocked attempts excluded, clean census recommends nothing, deduped, `recon D-evidence:` provenance); engine `_recompose_hook` merges them via shared `_apply_recommendations` (same dedupe/cap/idempotent ledger as member recommendations). Offline by construction (source-import test). Engine: recon-lane dispatches carry `intel.recon_depth` (slice + live coverage + blockers); CLI `--record/--waive/--close/--coverage/--recommendations` |

### 7.3 Discovery core (Web/API)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/surface_model.py` | 869 | Structured Web/API attack-surface model. `SurfaceModel`@132, `infer_vhost_candidates`@736 |
| `tools/mutator.py` | 468 | Structure-aware mutation plans (one variable at a time). `Mutator`@199 |
| `tools/discovery_scheduler.py` | 419 | Coverage-aware, impact-ranked scheduling + oracle loop. `DiscoveryScheduler`@140 |
| `tools/art_selector.py` | 630 | ART4SQLi payload selection (TF-IDF, 1/cosine spacing, FSCS). `PayloadSpace`@225, `f_measure`@519 |
| `tools/differential.py` | 198 | Differential divergence detector. `DifferentialDetector`@72 |
| `tools/differential_runner.py` | 366 | Live sibling-differential replay (via `hunt.curl_fetch_observation`). `DifferentialRunner`@149 |
| `tools/header_trust.py` | 679 | Forwarded/trust-header taxonomy + probe planner + live replay. `HeaderTrustRunner`@490 |
| `tools/contract_discovery.py` | 588 | Smart-contract state-space exploration + minimization. `ContractExecutor`@301, `ContractDiscoveryScheduler`@406 |
| `tools/cache_traversal.py` | 521 | Cache-key path-traversal track (CVE-2026-18051 class). `TraversalRunner`@333 |
| `tools/graphql_gid.py` | 455 | GraphQL `node(id:)` global-id harvesting (redacted) + bounded candidates. `analyze_introspection`@115 |

### 7.4 Research / candidate track

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/research_core.py` | 537 | Coverage-guided research substrate. `CoverageTracker`@74, `CorpusManager`@158 |
| `tools/research_model.py` | 208 | Shared candidate data model. `ResearchCandidate`@103 |
| `tools/research_sources.py` | 237 | Provenance-bound research registry. `SourceRegistry`@112 |
| `tools/zero_day_tracks.py` | 571 | Deterministic adapters for 5 surfaces + chain synthesis. `WebApiTrack`@228, `synthesize_chains`@155 |
| `tools/zero_day_pipeline.py` | 206 | Zero-day pipeline glue (intake→novelty→evidence) |
| `tools/novelty.py` | 279 | Novelty assessment (exact/near matches; never claims zero-day). `NoveltyEngine`@126 |
| `tools/novelty_pipeline.py` | 206 | Novelty pipeline wiring |
| `tools/impact_focus.py` | 284 | Criticality router. `CriticalityRouter`@175 |
| `tools/impact_validation.py` | 299 | Candidate evidence state machine. `CandidateStateMachine`@127 |
| `tools/triage.py` | 205 | Triage + disclosure gates. `CandidateTriage`@63 |
| `tools/adaptive_learning.py` | 466 | Quarantined learning memory (records, operator-reviewed only). `AdaptiveMemory`@127 |
| `tools/methodology_playbook.py` | 540 | 2026 methodology → human-validation tasks + non-executing tool plans. `build_tool_plans`@351 |
| `tools/idor_research.py` | 603 | Offline IDOR/BFLA planning across 10+ reference classes. `build_bfla_matrix`@337, `build_idor_matrix`@480 |
| `tools/post_finding_trigger.py` | 467 | Post-finding/signal triggers. `trigger_after_finding`@190 |
| `tools/candidate_lifecycle.py` | 254 | Candidate lifecycle transitions |
| `tools/candidate_cli.py` | 73 | Candidate CLI |
| `tools/mutation_lineage.py` | 93 | Mutation lineage graph |
| `tools/lineage_graph.py` | 125 | Evidence lineage graph (tool calls, parents) |

### 7.5 Web/API protocol & workflow surfaces

| Module | Lines | Purpose |
|---|---|---|
| `tools/web_api_research.py` | 141 | Web/API research adapter |
| `tools/web_api_protocol.py` | 115 | Web/API protocol runner |
| `tools/web_api_workflow.py` | 109 | Workflow skip/repeat/reorder candidate extraction |
| `tools/http_protocol_runner.py` | 102 | curl probes over HTTP/1.1–3 (h3 gated on quiche build) |
| `tools/protocol_adapters.py` | 111 | Protocol fixture adapters |
| `tools/protocol_differential_fixture.py` | 161 | Deterministic protocol differential fixture |
| `tools/multitenant_workflow.py` | 104 | Multi-tenant workflow surfaces |
| `tools/graphql_workflow.py` | 68 | GraphQL workflow candidates |
| `tools/claude_workflow.py` | 66 | Four-domain Claude Code workflow entry |
| `tools/cross_domain.py` | 161 | Cross-domain candidate correlation |
| `tools/multi_agent_fixture.py` | 86 | Multi-agent fixture runner |

### 7.6 Web3

| Module | Lines | Purpose |
|---|---|---|
| `tools/web3_protocol_fixture.py` | 131 | Web3 protocol fixture (test-only) |
| `tools/web3_research.py` | 90 | Web3 research adapter |
| `tools/web3_tool_adapter.py` | 85 | Web3 tool adapter |
| `tools/web3_fixture_runner.py` | 81 | Web3 fixture runner |

### 7.7 AI / LLM surfaces

| Module | Lines | Purpose |
|---|---|---|
| `tools/llm_attack_surface.py` | 384 | LLM/agentic AI attack-surface scanner. `LLMAttackSurfaceScanner`@209 |
| `tools/llm_sandbox.py` | 104 | LLM tool-call sandbox trace analysis |
| `tools/ai_red_team_adapter.py` | 112 | AI red-team adapter |
| `tools/ai_tool_adapters.py` | 99 | AI tool adapters |
| `tools/supply_chain_analyzer.py` | 94 | Supply-chain static analysis |
| `tools/red_team_runner.py` | 93 | Red-team runner |

### 7.8 Governance, evidence, safety, harness, support

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/execution_semantics.py` | 127 | **Deliberate pass-through** ("uncensored lab semantics"): validates URL/path SHAPE only; `target_in_scope` always True; `load_authorized_scope` injects `authorized: true`. The real enforcement lives in `tools/runtime/scope.py` + `sandbox.py` |
| `tools/execution_controller.py` | 154 | **Deliberate pass-through** controller — request/time/action budgets only, no authorization gates. `ExecutionPolicy`@36, `ActiveExecutionController`@73 |
| `tools/safety.py` | 31 | **Compatibility shim** → `tools.execution_semantics` (legacy import surface) |
| `tools/evidence.py` | 229 | Redacted evidence + replay fixtures. `EvidenceStore`@118 |
| `tools/state.py` | 528 | JSONL session state engine. `SessionState`@102, `find_chain_candidates`@443 |
| `tools/chain_of_custody.py` | 591 | Tamper-proof hash-chained per-finding audit trail (sandboxed replay). `ChainOfCustody`@111 |
| `tools/crypto_vault.py` | 546 | Encrypted artifact store + secure deletion. `Vault`@246 |
| `tools/chain_orchestrator.py` | 568 | Full-chain orchestrator. `orchestrate`@325 |
| `tools/deep_chain.py` | 216 | Multi-hop chain synthesis. `DeepChainSynthesizer`@104 |
| `tools/program_fit.py` | 604 | Program-fit gate (platform scope/noise filter). `ProgramFitGate`@188 |
| `tools/formal_verify.py` | 552 | Certora/Echidna harness generation bridge. `FormalVerifyBridge`@384 |
| `tools/pii_firewall.py` | 325 | Deterministic PII masking before egress. `PIIFirewall`@206 |
| `tools/data_governance.py` | 153 | Schema classification + Kafka encryption/ACL/retention plans |
| `tools/engagement_context.py` | 273 | Recorded execution context (accountability, never a gate). `record_context`@96 |
| `tools/environment_profile.py` | 221 | Environment preflight (declaration + optional OS scan). `collect_environment`@130 |
| `tools/harness_guard.py` | 304 | Session contract verifier (`--verify --json`). `initialize`@144, `verify`@171 |
| `tools/harness_command.py` | 171 | Parses `bugwolf --full attack this target …` invocations. `parse_invocation`@74 |
| `tools/harness_intelligence.py` | 210 | Offline reasoning brief builder. `build_brief`@120 |
| `tools/readiness.py` | 289 | Validates `configs/readiness.json` vs the live tree; probes scope gate + sandbox for real |
| `tools/reporting.py` | 351 | Review/reporting/disclosure gate. `ReportingGate`@140 |
| `tools/release_ops.py` | 213 | SBOM build, bundle check, smoke imports |
| `tools/wordlist_gen.py` | 538 | Dynamic wordlist generation (no static lists). `generate`@418 |
| `tools/static_bridge.py` | 359 | Static analysis / patch-gap bridge. `SourceFingerprinter`@104 |
| `tools/nvd_ingester.py` | 194 | NVD data ingest |
| `tools/dependency_map.py` | 72 | Dependency map extraction |
| `tools/target_intake.py` | 182 | Operator target spec recording + academic export (git rev-parse via sandbox) |
| `tools/digest_canary.py` | 45 | Canary canary-leak checks (`check_output_leakage`@41) |
| `tools/mcp_fixture.py` | 100 | Stdio MCP fixture (local validation) |
| `tools/sarif_export.py` | 56 | SARIF export |
| `tools/passk_metrics.py` | 57 | pass@k metrics |
| `tools/runtime_paths.py` | 40 | Workspace/slug helpers used by every module |

### 7.9 Compatibility shims

| Module | Lines | Purpose |
|---|---|---|
| `tools/stage_controller.py` | 21 | shim → `tools.core.stage_controller` |
| `tools/research_loop.py` | 21 | shim → `tools.core.research_loop` |
| `tools/campaign_orchestrator.py` | 20 | shim → `tools.core.campaign_orchestrator` |
| `tools/agent_bus.py` | 20 | shim → `tools.core.agent_bus` |

---

## 8. `tools/domains/` — leaf domain modules (14, 5,726 lines)

### api (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/api/bopla_matrix.py` | 450 | BOPLA (OWASP API3) object-property-level authz matrix. `build_matrix`@206 |
| `tools/domains/api/graphql_batch_analyzer.py` | 452 | GraphQL batching/DoS/introspection abuse plans. `analyze`@364 |

### auth (3)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/auth/jwt_forgery.py` | 305 | Offline JWT analysis + forgery plans. `analyze`@172 |
| `tools/domains/auth/oauth_flow_analyzer.py` | 436 | OAuth/OIDC flow parsing + validation plans. `analyze`@183 |
| `tools/domains/auth/ato_chain_planner.py` | 378 | ATO chain synthesis. `plan_chains`@282 |

### cloud (1)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/cloud/iam_privesc_graph.py` | 559 | AWS IAM privilege-escalation graph (21 Rhino methods). `analyze`@435 |

### llm (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/llm/agentic_tool_auth.py` | 382 | Tool-call sites × attacker-controlled args. `analyze`@164 |
| `tools/domains/llm/rag_memory_poisoning.py` | 390 | RAG/memory poisoning vector ranking. `analyze`@173 |

### mobile (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/mobile/deep_link_analyzer.py` | 449 | Android/iOS deep-link surface planning. `analyze`@259 |
| `tools/domains/mobile/mobile_policy_checker.py` | 370 | Static manifest/plist policy checks. `analyze`@272 |

### smart_contracts (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/smart_contracts/llm_contract_triage.py` | 365 | Exploitability ranking of static SC findings. `triage`@239 |
| `tools/domains/smart_contracts/price_manipulation_analyzer.py` | 336 | DeFi oracle/price-manipulation lifecycle plans. `analyze`@259 |

### web (2)
| Module | Lines | Purpose |
|---|---|---|
| `tools/domains/web/http_smuggling_detector.py` | 471 | HTTP smuggling probe generator + oracle. `build_plan`@246 |
| `tools/domains/web/parser_differential.py` | 383 | WAFFLED-style WAF-bypass payload families. `generate`@236 |

---

## 9. `tools/intelligence/` · `recon/` · `validation/` (7 modules, 2,931 lines)

| Module | Lines | Purpose & key definitions |
|---|---|---|
| `tools/intelligence/chain_graph_ai.py` | 336 | Missing-link chain proposals. `propose`@134 |
| `tools/intelligence/failure_learning.py` | 408 | Blocker → bypass-candidate feedback + **operator approval gate**. `approve_candidate`@293 |
| `tools/intelligence/seed_advisor.py` | 336 | Seed/mutation probe proposals. `advise`@222 |
| `tools/recon/historical_asset_delta.py` | 460 | Passive-DNS/CRT churn tracker. `compute_delta`@238, `ingest_historical`@322 |
| `tools/recon/depth_ladder.py` | ~290 | **v1.9: recon depth ladder (D0-D3 anti-satisficing)** — `ReconDepthLedger` append-only JSONL journal (`state/orchestrator/recon-depth/<mission>.jsonl`): `record`/`waive`/`close` events, `untried` (partials never terminal, waivers honored), `close_blockers` (recon's honest exit exam), `coverage` per-depth report. DEPTH_TECHNIQUES canonical families per level; D3 = param-surface/js-route-map/cloud-buckets/mobile-endpoints/historical-crossref. **v1.9.1: `SIGNAL_RULES` + `recommendations()`** — recorded census evidence (bucket hostnames, WAF signatures, secret patterns, mobile endpoints) cross-references into `{bug_class, reason}` recommendations (technique-scoped regex, evidence-based: blocked attempts excluded, clean census recommends nothing, deduped, `recon D-evidence:` provenance); engine `_recompose_hook` merges them via shared `_apply_recommendations` (same dedupe/cap/idempotent ledger as member recommendations). Offline by construction (source-import test). Engine: recon-lane dispatches carry `intel.recon_depth` (slice + live coverage + blockers); CLI `--record/--waive/--close/--coverage/--recommendations` |
| `tools/validation/race_engine.py` | 331 | Race-condition raw-socket engine (scope-gated at @175) |
| `tools/validation/self_eval_harness.py` | 667 | AutoPenBench-style milestone scoring (10 tasks, 100% = pass). `evaluate`@137 |
| `tools/validation/verification_lab.py` | 393 | Disposable dynamic-validation lab plans. `plan_labs`@276 |

---

## 10. `bridge/`, `commands/`, `hooks/`, `wordlists/`

| File | Lines | Purpose |
|---|---|---|
| `bridge/bugwolf-mcp.py` | 175 | MCP server (JSON-RPC 2.0 over stdio): `bugwolf_status/plan/run/leads/mode`; never crashes — failed calls return error objects. `dispatch`@~139, `main`@~158 |
| `commands/bugwolf.md` | — | Mission start: MissionSpec parse → preflight → scheduler run |
| `commands/bugwolf-plan.md` | — | Scheduler dry-run (graph + preflight gate, no dispatch) |
| `commands/bugwolf-run.md` | — | Execute/resume mission (open leads first, finished work never re-runs) |
| `commands/bugwolf-status.md` | — | Graph + lead ledger + mode journal + preflight digest |
| `commands/bugwolf-review.md` | — | Adversarial lead review (verify-lane replay, disproof checklist) |
| `commands/bugwolf-report.md` | — | Report assembly (requires ZERO open leads; redaction + provenance) |
| `commands/bugwolf-stop.md` | — | Freeze mode state via the stop hook |
| `commands/bugwolf-resume.md` | — | Replay JSONL tail; open leads → chains → new recon |
| `commands/bugwolf-sandbox.md` | — | Sandbox status/kill/arm/grant/revoke/verify (never auto-arm) |
| `hooks/hooks.json` | 24 | SessionStart → preflight digest (cached); Stop → persistent-mode freeze |
| `hooks/bugwolf_stop_hook.py` | 100 | Thin stdlib shim: one JSON event in → one JSONL journal line (allowlisted scalar keys only) → one JSON decision out; a hook failure is logged and swallowed so it can never stall the harness |
| `wordlists/resolvers.txt` | 24 | Public DNS resolvers used by recon |

---

## 11. `tests/` — 130 files, 1,334 tests, 22,691 lines

**Fixtures / stand-ins:**
- `tests/_stub_target.py` — deterministic stdlib-only operator-target stand-in for CI (the v1.3.0 replacement for the removed shipped labs); suites skip cleanly when absent.
- `tests/fixtures/agent-inventory-security-gaps.json` — synthetic agent inventory for `paper_intel.assess_agent_control_plane` (test-only).

**End-to-end / integration (boot the stub target in-process):**
`test_e2e_deep_dive_campaign.py` (full U1–U5 pipeline: pass@k, artifact bridging, strict F0.5, 12-stage workflow, probe pass, fuzz→spawn→reproduce, 10-task eval), `test_mission_runner_e2e.py`, `test_live_feedback_loop.py`, `test_fin_lane.py`, `test_auth_lane.py`, `test_domain_lanes.py`, `test_phase5_oast_browser.py`, `test_phase6_modes_ladder.py`, `test_apt_commander_week1.py`, `test_ci_bundle_check.py`, `test_packaging.py`, `test_doc_consistency.py` (pins AUDIT_MAP.md ↔ `tools/recon/` contract).

**Unit suites (remaining ~110 files, grouped):**
- **Workflow/gates:** stage_controller, campaign_orchestrator, f05_* (gate/quarantine/strict), phases_2_5_6, phases_7_8, pipeline, fast_path_engine, engagement_context, environment_profile, safety_boundaries, week8_selfeval_workflow_integrity
- **Research/novelty:** zero_day_research (957 lines — largest test), research_loop, research_core, week4_llm_smartcontract_verification, week5_advisor_dynamic_checkpoints_pricemanip, deep_tools, safe_research_tracks, batch_tracks, adaptive_learning, pass_at_k, passk_metrics, near_duplicate_clustering, novelty_pipeline, candidate_lifecycle, mutation_lineage, lineage_graph, carlini_loop
- **Runtime/orchestrator:** runtime_contracts, runtime_scheduler, mission_runner_e2e, orchestrator_preflight, operator_dashboard, target_intake, sandbox, sandbox_coverage, scope_gate, accounts_matrix, oast_tunnel, ai_sandbox
- **Discovery/domains:** discovery_core, surface/schema tests, art_selector, header_trust, vhost_grouping, graphql_gid, cache_traversal, contract_discovery, differential_runner, hunt_engine, hunt_chain_integration, schema_extractor, week2_bfa_graphql_oauth, week3_cloud_mobile_recon, week6_ato_failurelearning_chaingraph, week4, week5
- **Infra/tooling:** hardening, integrity, integrity_hardening, trigger_ledger_integrity, chain_orchestrator, chain_ai, harness_guard, harness_command, harness_intelligence, readiness, benchmark, agent_bus_trigger, model_router (+config), opsec, wordlist_gen, methodology_playbook, post_finding_trigger, privacy_governance, js_ct_intel, js_token_forge, tech_fingerprint, release_hardening, perf_gate, reproducibility, reliability, observation, leads, multitenant/web_api/graphql workflow suites, http_protocol_runner, protocol_adapters, protocol_differential_fixture, web3_* suites, ai_tool_adapters, ai_red_team_adapter, supply_chain, red_team_runner, llm_attack_surface, multi_agent_fixture, cross_domain, nvd_fetch, nvd_ingester, digest_canary, sarif_export, lab_doctor, lab_lifecycle, deep_tools, elicitation_bridge

---

## 12. `references/` — 53 knowledge docs

### 12.1 Top-level (23)
`adaptive-learning.md`, `al-mizaan-gates.md`, `bug-bounty-intelligence-mcp.md`, `chain-analysis.md`, `cvss-guide.md`, `cwe-knowledge-base.md`, `defensive-intelligence.md`, `discovery-core.md`, `isolation.md`, `judging.md`, `knowledge.md`, `local-tooling.md`, `methodology.md`, `paper-intelligence.md`, `privacy-governance.md`, `recon-tooling.md`, `report-formatting.md`, `research-loop.md`, `setup.md`, `sis-intelligence.md`, `supervisor.md`, `wild-mode.md`, `zero-day-research.md`

### 12.2 `references/hacking-agents/` (22)
`access-control-agent`, `browser-automation-agent`, `business-logic-agent`, `cache-poisoning-agent`, `counter-intelligence-agent`, `credential-leak-agent`, `crypto-math-agent`, `economic-security-agent`, `graphql-agent`, `http-smuggling-agent`, `llm-ai-agent`, `mobile-client-agent`, `race-condition-agent`, `recon-agent`, `regression-agent`, `rogue-agent`, `shared-rules`, `smart-contract-agent`, `supply-chain-agent`, `temp-email-agent`, `waf-bypass-agent`, `web-api-agent` (all `.md`)

### 12.3 `references/attack-vectors/` (8)
`business-logic-vectors`, `cloud-vectors`, `llm-ai-vectors`, `mobile-vectors`, `smart-contract-vectors`, `spel-injection-vectors`, `web-api-vectors`, `zerodays` (all `.md`)

---

## 13. No shipped labs (v1.3.0 policy)

As of `70712dc` ("feat: FIN business-logic lane + remove shipped labs
(real-world plugin)") the repo ships **no vulnerable lab fixtures**. The
former `lab/vulnbank/server.py` (274 lines) and `lab/web3` fixture were
deleted: the plugin binds exclusively to **operator-declared targets**
(`tools/target_intake.py` records the target spec + attestation; the
v1.3.0 scope gate enforces the declared boundary). `tests/_stub_target.py`
stands in as a deterministic operator target for CI regression only, and
`scripts/lab_setup.sh` + `docker-compose.lab.yml` remain available for
optional local runtime validation (never a production boundary). Historical
mentions of VulnBank in `CHANGELOG.md` and the older plan documents are
records of past releases, not current structure.

---

## 14. Runtime/state directories (git-ignored)

| Dir | Contents |
|---|---|
| `state/` | Runtime state: `orchestrator/<mission>/` (graph.json, leads.jsonl, modes.jsonl, hooks.jsonl, report.json, `team/` (state.json, runs.jsonl, messages.jsonl)), `preflight/manifest.json`, `learning/<target>.jsonl`, `sessions/<target>/` (probes.jsonl, leads.jsonl, maps/), `signals/events/`, `sandbox/audit.jsonl`, `environment.json` |
| `.bugwolf/` | Persistent workflow state per target (`workflows/<target>.json`) |
| `recon/` | Recon output (discovery plans, js-intel, methodology, …) |
| `research/` | Research checkpoints per target (`<target>/pre-hunt|post-recon|post-maps|bypass|post-findings|escalation|pre-report`) |
| `dist/` | Built bundles: `bugwolf-v<V>.skill` + `bugwolf-v<V>.freebuff.zip` |
| `.private/`, `vault/` | reserved (empty) |

---

## 15. Dependency architecture (from `DEPENDENCIES.md`, AST-verified)

- **Leaf isolation:** `domains/`, `intelligence/`, `recon/`, `validation/` are imported by **nothing** (2 exceptions: `core/campaign_orchestrator.py → intelligence/{failure_learning, seed_advisor}.py`); they publish typed events onto `core/signal_bus.py` (`publish_or_warn`) and run as standalone CLIs.
- **Runtime boundary:** `runtime/scope.py` is consulted at the four network choke points (mission_runner, live_executor, race_engine, browser_driver); `runtime/sandbox.sandboxed_run` is the spawn path for 16 modules (hunt, fleet, capability_manifest, preflight, oast_tunnel, asset_intel, js_ct_intel, crypto_vault, chain_of_custody, formal_verify, retest_scheduler, release_ops, target_intake, reproducibility, http_protocol_runner, readiness).
- **Orchestrator fan-in:** mission_runner ↔ scheduler/contracts/lead_protocol/preflight/modes/accounts/oast; campaign_orchestrator imports asset_discovery, campaign, chain_orchestrator, leads, mutator, refutation, research_model, research_thread, stage_controller, zero_day, core/{fuzz_bridge, live_executor, model_router, signal_bus, research_loop}.
- **Core internals:** `stage_controller → harness_guard, paper_intel`; `fuzz_bridge → live_executor, signal_bus, mutator, schema_extractor`; `research_loop → adaptive_learning, wordlist_gen`; `agent_bus → evidence, post_finding_trigger, execution_semantics`.
- **Upward coupling:** all leaf modules → `runtime_paths.py` for workspace resolution.

---

## 16. Verification status (2026-09-03)

```
python3 -m unittest discover -s tests -p 'test_*.py'   → Ran 1373 tests, OK (skipped=2)
python3 -m compileall -q tools tests scripts bridge    → clean
bash -n tools/recon_engine.sh scripts/*.sh             → all OK
python3 scripts/generate_audit.py                      → AUDIT.md regenerated
python3 scripts/generate_agents.py --check             → 25 agent definitions in sync
bash scripts/ci_bundle_check.sh                        → OK (exit 0)
```

**Notable observations:**
1. `tools/execution_semantics.py`, `tools/execution_controller.py`, and the `tools/safety.py` shim are deliberately pass-through ("uncensored" lab semantics — shape validation only). Real enforcement lives in exactly two places: `tools/runtime/scope.py` (deny-by-default, checked at every network choke point) and `tools/runtime/sandbox.py` (spawn allowlist + kill switch). This is the documented design intent (README, SKILL.md, `configs/readiness.json`).
2. The engineering-control layer is strong: evidence redaction (`evidence.py`), PII firewall, chain of custody, tamper-evident workflows, quarantined learning memory with an operator approval gate, replayable-evidence requirement before CONFIRMED, credential redaction in the scheduler and account matrix.
3. Runtime state, research output, and bundles are git-ignored; the tracked tree is pure source + docs.
4. Closed gap (audit 2026-09-03, fixed same day): `tools/hunt.py`'s `curl_fetch`/`curl_fetch_observation` previously did not consult the scope gate; both now run `_scope_check` (fail-closed `scope-blocked:` sentinel, auto-bind for standalone use) ahead of the sandbox spawn, so live replays routed through them (`differential_runner`, `header_trust`, `cache_traversal`) obey the operator scope. Pinned by `tests/test_hunt_engine.py::TestScopeGateChokePoint`.

---

## 17. v1.4 multi-agent layer (this revision)

BugWolf previously orchestrated *work* (probes, lanes, leads) with a single
harness session. v1.4 adds OMC-style orchestration of *agents*, adapted to
the hostile-target assumption:

### 17.1 New files

| File | Lines | Purpose |
|---|---|---|
| `tools/core/agent_registry.py` | 654 | 25 specialized subagents (21 bug-class specialists from `references/hacking-agents/` + 4 workflow agents: recon/verify/chain/report). Deterministic selection, digest-verified playbooks, budget-capped team composition |
| `tools/runtime/team.py` | 600 | Team engine: waves, parallel members, JSONL run ledger, atomic checkpoints, stale-worker recovery, typed inter-agent messages |
| `scripts/generate_agents.py` | 114 | Projects the registry into `agents/bugwolf/<role>.md` harness subagent files; `--check` mode for CI drift detection |
| `agents/bugwolf/*.md` | 25 files | Generated subagent definitions (name/description/model-tier/tools/scope/sandbox front-matter + playbook body) |
| `commands/bugwolf-team.md` | — | `/bugwolf-team` slash command (plan/run/resume/status) |
| `tests/test_multi_agent.py` | 389 | 24 tests: registry, dispatch routing, waves, messages, resume/recovery, scheduler bindings, generator sync, MCP surface |
| `tests/test_team_dispatch.py` | ~290 | 10 tests: atomic claim exclusivity, ownership rejection, honest timeout, release-to-queue, heartbeat binding, full engine-through-queue round trip, CLI exit codes |
| `tools/core/model_router.py` | +110 | Real dispatch decisions (`route_agent_dispatch`, `route_unit_agent`) |
| `tools/runtime/scheduler.py` | +35 | `attach_agent_bindings()` — lane roots carry `bugwolf:<role>` + tier |
| `bridge/bugwolf-mcp.py` | +55 | `bugwolf_agents` + `bugwolf_team` MCP tools (7 total) |

### 17.2 Architecture

```
registry (WHO):  25 AgentSpecs -- bug-class ownership → domain generalist
                 → workflow fallback; playbooks digest-verified at load
dispatch (TIER): route_agent_dispatch -- complexity score ∨ affinity floor
                 (frontier never degrades below frontier; deterministic
                 hard-caps at 0.0); preference strings resolved by configs/models.json
execution (HOW): TeamEngine waves recon→hunt→verify→report; harness worker
                 callable executes `bugwolf:<role>`; engine never calls a model
surface:         /bugwolf-team command · MCP bugwolf_agents/bugwolf_team ·
                 agents/bugwolf/*.md · scheduler lane bindings
```

### 17.3 Invariants (all pinned by `tests/test_multi_agent.py`)

1. **Deterministic composition** — identical (domains, bug-classes, budget) ⇒ identical roster digest.
2. **Tamper-evident playbooks** — prompt digest re-verified at every load; mismatch raises.
3. **Scope + sandbox per member** — every dispatch payload records `scope_required`/`sandbox_required`; the gate and sandbox hold unchanged at the choke points (team threads execute through the same `hunt`/runtime transports).
4. **No fake results** — no worker bound ⇒ BLOCKED evidence per member, never a fabricated outcome.
5. **Durable & resumable** — append-only runs.jsonl; atomic state.json checkpoints only at member terminal states; stale claims (>15 min heartbeat) fail closed and are re-dispatched; finished members never re-run.
6. **Routing never gates** — any tier degrades per `fallback_preference`; registry-unavailable environments fall back to tier-only routing.
7. **Messages are typed** — `to_role`-addressed handoffs persisted to messages.jsonl; credentials never ride inter-agent context (accounts matrix redacts upstream).

---

## 18. v1.5 deep-research layer (this revision)

Agents' playbooks froze at write time; the world did not. §18 adds the
research loop that keeps every hunt dispatch current — the agent-side
equivalent of the reference corpus's Phase-2 threat-intel mapping.

### 18.1 New files

| File | Lines | Purpose |
|---|---|---|
| `tools/intel/research_engine.py` | 499 | **Research packs.** Direct sources with injectable `urlopen`: NVD CVE 2.0 (keyword+version), GitHub PoC search, CISA KEV (1,694 entries, correlated — KEV hit ⇒ confidence 0.95), Reddit (r/netsec, r/bugcrowd, r/websecurity), HN Algolia. Harness sources (X/Twitter, Medium, Google dorks — no keyless API, never faked) emit concrete query plans the Claude Code session executes with WebSearch/WebFetch. Per-source fail-open: a dead source degrades into the pack's honesty fields (`sources_degraded`), never fails the pack. |
| `tools/intel/technique_ledger.py` | 308 | **Research quarantine.** SUBMITTED → QUARANTINE → (operator approve, time-boxed 90d) → ACTIVE → EXPIRED. SHA-256 content digest binds approval to bytes; tampered content cannot be approved. Hunt dispatches carry ONLY active unexpired entries for the member's bug classes — quarantine never rides along. |
| `references/hacking-agents/threat-research-agent.md` | — | Playbook: version-evidenced CVE research, documented negatives, bounty-pattern weighting. |
| `references/hacking-agents/community-signal-agent.md` | — | Playbook: Reddit/HN/X/Medium mining protocol, ledger submission discipline. |
| `references/hacking-agents/exploit-intel-agent.md` | — | Playbook: PoC matching to observed surface, KEV triage, canary-safe adaptation. |
| `tests/test_intel_layer.py` | ~270 | 10 tests: fixture-driven source adapters, KEV correlation, degradation honesty, plan-only mode (zero fetches), ledger lifecycle/tamper guard, roster selection, dispatch integration with quarantine isolation. |

### 18.2 Flow

```
recon tech_stack ──┐
mission bugs ──────┼─→ ResearchEngine.build_pack()  (once per run, shared)
                   │      ├─ NVD/GitHub/KEV/Reddit/HN  (direct, live or degraded)
                   │      └─ X/Medium/dork plans       (harness executes)
                   ▼
TeamEngine._build_research_context(member)
                   ├─ research_pack slice        → payload["intel"]
                   └─ ledger.active(bug_class)   → approved techniques only
                   ▼
member dispatch (hunt agents hunt with TODAY's intel; new techniques from
community-signal wait in QUARANTINE for operator approval)
```

### 18.3 Invariants (pinned by `tests/test_intel_layer.py`)

1. **Provenance mandatory** — every intel item carries source + URL.
2. **Degradation is recorded, never hidden** — `sources_degraded` + pack notes.
3. **KEV correlation boosts, version-unconfirmed downgrades** — deterministic confidence.
4. **Quarantine isolation** — an operator-approved ledger is the only path from "the internet says" to "an agent may try".
5. **Intel never gates** — any failure degrades to frozen playbooks; research is additive.

---

## 19. v1.6 research-driven agent expansion (this revision)

The v1.5 engine made agents researchable; §19 makes them current. A live
research pass (web pulls: The-XSS-Rat 2026 practical guide, OWASP Agentic
Top 10 2026 ASI01–ASI10, OWASP LLM 2025/2026, MCP security corpus
(Invariant tool-poisoning advisory, CSA notes, NSA CSI, 97M-download/82%
path-traversal stats), Unit 42 web-IDPI in-the-wild taxonomy (22
techniques), PortSwigger CSD/browser-desync corpus, 2026 ATO writeups,
WCD/WCP guides) was distilled into three vector catalogs, then four
specialists were built on them.

### 19.1 New vector catalogs (references/attack-vectors/)

| File | Contents |
|---|---|
| `agentic-ai-vectors-2026.md` | ASI01–10 test patterns, MCP vectors (tool poisoning, rug pulls, path traversal, missing OAuth, IDE auto-exec, context poisoning), Unit42 IDPI taxonomy (delivery methods, jailbreak methods, intent severity ladder), LLM Top 10 alignment, canary-only operating rules |
| `web-cache-vectors-2026.md` | WCD delimiter ladder (`;`, `%3B`, `.;`, `..;`), cache-key abstractions, WCP playbook (unkeyed sweeps, gadget chaining, H2-era desync), chain map (WCD→CSRF, WCP→XSS→ATO) |
| `ato-chains-2026.md` | OAuth account fusion/PKCE downgrades, 0-click reset ladders, email-verification ATO windows, entropy-feasibility proofs, payout order, GDPR multiplier |

### 19.2 New agents (registry 28 → 32)

| Role | Tier | Bug classes | Source |
|---|---|---|---|
| `mcp-supply-chain` | frontier | mcp_tool_poisoning, mcp_rug_pull, mcp_path_traversal, agentic_supply_chain, ide_autoexec_rce | ASI04 + MCP corpus |
| `agentic-hijack` | frontier | agent_goal_hijack, indirect_prompt_injection, tool_misuse, memory_poisoning, system_prompt_leak | ASI01/02/06/07 + Unit42 |
| `cache-attack` | local_slm | cache_deception, cache_poisoning, cache_key_confusion, h2_desync_poisoning, cpdos | WCD/WCP catalogs |
| `ato-chain` | frontier | account_takeover, oauth_fusion, pkce_downgrade, reset_poisoning, email_verification_ato | 2026 ATO corpus |

### 19.3 Research-engine dork upgrade

Query plans now include the 2026 writeup-corpus dorks: infosecwriteups/
medium ATO+OAuth chains, PortSwigger-research/Unit42 primary research,
GitHub bug-bounty checklist repos (the exact discovery path this revision
used).

All 32 definitions in sync (`generate_agents.py --check`); dispatch
routing verified for every new bug class; intel packs regenerated with
the expanded plan set.

---

## 20. v1.5 corpus layer (this revision — 76-PDF distillation)

The operator uploaded a 76-document corpus (2FA/MFA, ATO, IDOR/BAC,
smuggling/desync, SSRF/host-header, API/SQLi, recon/dorks, cloud,
business-logic, RCE/upload, XML/SAML, platform misconfig, and the
Claude-Code-setup methodology). Every document was read and distilled
into code; the PDFs were then removed from the repo per operator
instruction. Verified: **1,405 tests pass (2 skipped)**, 39 agents in
sync, `compileall` clean.

### 20.1 New modules

| Module | Lines | Purpose |
|---|---|---|
| `tools/core/checklists.py` | 515 | Canonical 2026 checklist registry: 124 items, 11 lanes, every ID source-tagged to corpus docs, canary-safety tags (6 attest-gated), bug-class→slice mapping |
| `tools/core/coverage_ledger.py` | 189 | Endpoint × checklist verdict ledger (`coverage.json`): evidence-cited verdicts, n-a demands a reason, attest items cannot confirm without operator clearance, atomic writes, digest integrity |

### 20.2 New agents (registry 32 → 39)

| Role | Tier | Bug classes | Corpus source |
|---|---|---|---|
| `mfa-bypass` | local_slm | mfa_bypass, otp_bypass, two_factor_bypass | 001/030/058/062 2FA-MFA checklists |
| `host-header` | local_slm | host_header, header_injection, routing_confusion | 031/032 header corpus |
| `rce-chain` | frontier | file_upload, ssti, deserialization, lfi_to_rce, image_parser_rce, regex_validation_gap | 018/022/034/038/051/068 RCE corpus |
| `xml-xxe` | local_slm | xxe, saml, xml_injection, xslt_injection, soap_attack | 006/036 XML/SAML corpus |
| `shadow-surface` | local_slm | surface_expansion, staging_exposure, takeover_candidate, acquired_assets, port_exposure | 013/017/037/043/060 recon corpus |
| `platform-misconfig` | local_slm | platform_misconfig, aem_exposure, jira_exposure, default_credentials, source_disclosure | 005/009/010/057 platform corpus |
| `webhook-logic` | frontier | webhook_abuse, payment_logic, entitlement_bypass, replay_attack, rounding_abuse | 003/047/049 financial-logic corpus |

### 20.3 Playbook upgrades (4 existing)

`access-control` (modern IDOR corpus: body-first refs, four mechanisms,
blind side channels), `business-logic` (NCC financial: TOCTOU,
number-format, rounding), `http-smuggling` (Klein variants, CRLF-powered
desync, browser-powered, queue-poisoning safety law), `graphql`
(mutation input-type scope bypass, field-suggestion reconstruction).

### 20.4 Orchestration wiring

- Team plan records the mission's canonical `checklist_slice` +
  `attest_pending` set; every dispatch payload now carries
  `intel.checklist.{member_ids, mission_ids, attest_pending}` alongside
  the research pack.
- Team `run`/`resume` end with a `coverage_gate`: open (unclosed,
  closeable) checklist IDs read from the mission coverage ledger —
  surfaced in `status()` for the report wave, never silently dropped.
- Research-engine query plans gained the corpus dork lanes (GitHub
  org census, Shodan favicon/port, CT staging census, webhook exposure,
  per-class writeup lanes).

### 20.5 Corpus removal

All 76 PDFs deleted from the repo (`git rm`) after distillation; their
knowledge now lives only in the checklist registry, playbooks, and
coverage tooling. PDFs remain in git history but not in HEAD.

### §17.4 Native in-process dispatch (v1.6)

The two-process drain loop is no longer required. `NativeTaskWorker`
(`tools/runtime/native_dispatch.py`) implements the same worker seam
(`worker(payload) -> result-dict`) as the file-queue bridge but dispatches
each team member **inline**: one bounded headless `claude --print
--output-format json` subprocess per member, spawned from the engine process
itself. No queue, no claim tokens, no second terminal:

```bash
python3 -m tools.runtime.team --mission M --target T --worker native --run --json
```

Honesty invariants (pinned by `tests/test_native_dispatch.py`, 20 tests):
subagent non-zero exit / empty output / `is_error` ⇒ **FAILED**; subprocess
timeout ⇒ **BUDGET-EXHAUSTED** (process group killed via
`run_bounded_subprocess`); output cap ⇒ **FAILED**; `lead_status`
(PWNED/REFUTED/BUDGET-EXHAUSTED) passes through only from structured output
and only when valid. Spawn discipline: argv-only, prompt on stdin (never
argv — no E2BIG, no process-list leak), model tier mapped via `model_map`
(unknown preferences dropped, never guessed), `command_builder` extension
point for pinning `subagent_type` per CLI version. Scope/sandbox flags stay
in the payload — in-process dispatch does not widen the enforcement plane.
The task-tool file queue remains available (`--worker task-tool`) for
two-terminal operation.

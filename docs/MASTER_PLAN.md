# BugWolf Master Plan — v2.0 "Mind of the Wolf"
### From checklist scanner to understanding-driven zero-day hunter

> **Thesis:** Criticals and zero-days start from maximum-deep understanding of the target and its business model — not from payloads. Payloads only matter after a correct model of the target tells you where assumptions live. This plan re-architects bugwolf around that thesis, on top of the packaging/engine/hooks work already required to be the #1 Claude Code plugin.
>
> Research grounding: Google Project Zero's **Naptime/Big Sleep** found the first real-world AI-discovered 0-day (SQLite) and improved CyberSecEval2 scores **20x** — explicitly attributing the gain to *methodology* (agent ↔ target-model interaction, specialized understanding tools, perfect verification, independent hypothesis trajectories), not model scale. The business-logic canon (PortSwigger/OWASP) defines hunting as *"understand the intended workflow, find the flawed assumptions."* BugWolf's existing 5-map doctrine (Asset/Trust/Identity/State/Capability) is the right idea — but as operator-written markdown, it is a checklist, not understanding. This plan makes it **computed, sequential, and load-bearing**.

> **Status: EXECUTED THROUGH v1.22.0** (2026-09). **All implementation phases — 0, 1, 2, 3, 4, 5, 6, 8, §8.3 (model-slice dispatch + chain prediction), 1.1b HTTP/2, 2.4 capture→replay, and 3.2–3.4 hooks — are shipped and verified** (full suite 1,737 tests OK; manifest gate OK; 39 agents in sync). Remaining to v2.0.0: **Phase 7 — the measured proof** only. See REVISED EXECUTION ORDER.

---

## STATUS DASHBOARD

| Phase | Part | Ship | Status | Evidence |
|---|---|---|---|---|
| 0 + 4 | IV — Packaging | **v1.10.0** | ✅ **DONE** | marketplace.json, plugin.json fixed, root `.mcp.json` → `bridge/bugwolf-mcp.py`, generator emits native `model:`, packaging gates in CI |
| 1 | II — Send engine | **v1.11–1.12 + v1.20** | ✅ **DONE** (1.1b shipped v1.20.0) | `tools/runtime/replay/`: message/apply/encode/backend_socket/observe/governor/batch/engine + hpack/h2; stub CL.TE **and H2.CL** desync tests detect what curl cannot |
| 2 | III — Browser & auth session | **v1.13.0 + v1.21** | ✅ **DONE** (2.4 shipped v1.21.0) | `browser_driver_playwright.py` (2.1), `session_context.py` (2.2), `authed_crawl.py` (2.3) + MCP `bugwolf_sessions`; **`capture_addon.py` + `capture_replay.py` (2.4)**; 2.5 browser-confirmed verdicts wired in the verify lane |
| 3 | V — Hooks | **v1.14.0 + v1.22** | ✅ **DONE** (3.2–3.4 shipped v1.22.0) | `bugwolf_pretool_scope_hook.py` (Bash+WebFetch, contract persistence, deny = exit 2) + `bugwolf_hooks.py` (UserPromptSubmit context + stale-model warning; PostToolUse hash-chained evidence ledger with replay_key; SessionStart cockpit with target-model freshness) |
| 5 | VI — Commands | **v1.15.0** | ✅ **DONE** | Six commands shipped incl. **`/bugwolf-understand`** (now drives the real pipeline); 16 commands total |
| 6 | VII — Opsec | **v1.16.0** | ✅ **DONE** | home-beacon dead (all 3 instances), `release_signing.py` + release.yml signing, 40+ pinned tool installs, `OAST_TRANSPARENCY.md`, `harness_guard verify_install` |
| 8 | I — Understanding Layer | **v1.17.0** | ✅ **DONE** | `understanding/{base,stages,pipeline}.py` + CLI; U1→U9 strict sequential, hash-chained, fail-closed, incremental; coverage gate parks unsupported classes with reasons; `/bugwolf-understand` + MCP `bugwolf_understand` |
| §8.3 | I — Feeding the hunt | **v1.18–1.19** | ✅ **DONE** | v1.18: `understanding/dispatch.py` (`model_slice()` + `render_prompt_block()` + `dispatch_gate()`) wired into `team.py` and the mission runner. v1.19: `understanding/chain_predict.py` — U7×U8 **predicted chains** staff specialists pre-hunt, reorder family swarms predicted-first, and append a "Predicted chains — dispatch first" section to the brief; the coverage gate still wins over prediction |
| 7 | VIII — Proof | **v2.0.0** | ⬜ **TODO** | the remaining build — detailed below |

Legend: ✅ done and verified · ◐ core shipped, one named piece missing · ⬜ not started.

---

## PART I — THE UNDERSTANDING LAYER (the foundation, Phase 8) — ✅ SHIPPED v1.17–1.18

### 8.0 What it is

A **sequential, always-first stage** that builds a machine-consumable Target Model before any hunting is permitted. It replaces "maps as artifacts" with "maps as computed state" — versioned, hash-chained, diffable across passes, and *required input* for every hunting agent. **Rule 6 is now enforced mechanically at dispatch** (`dispatch_gate()`: no model ⇒ clean no-op; parked class ⇒ skip with recorded fact).

Two principles from the research, adopted verbatim:
- **Naptime's "space for reasoning":** the Understanding Layer is deliberately *not* an LLM free-for-all. It is deterministic extraction (cheap, complete, honest) + bounded LLM reasoning passes (expensive, hypothesis-generating) over deterministic output. The deterministic engines are **shipped**; every stage artifact carries a `challenge` field that is the exact input contract for the operator-side bounded LLM pass — the passes deepen without changing any pipeline code.
- **Naptime's "independent hypothesis trajectories":** each understanding hypothesis carries its own dispro plan and is verified independently — one wrong belief can't contaminate the model (U8 by construction).

### 8.1 The 9 sequential stages — all shipped as deterministic engines

```
U1 BUSINESS MODEL      → U2 RECON CENSUS → U3 APPLICATION LOGIC → U4 IDENTITY/AUTHZ
→ U5 DATA & STATE      → U6 TRUST/BOUNDARIES → U7 CAPABILITY MAP → U8 ASSUMPTION LEDGER
→ U9 MODEL SYNTHESIS & COVERAGE GATE
```

| # | Stage | Status | Delivered engine (stages.py) | Artifact |
|---|---|---|---|---|
| U1 | **Business Model** | ✅ | Page/ToS/pricing fetch via replay engine; entity extraction (user/merchant/admin); monetization + trust-decision mining; model-type classification (marketplace/SaaS/fintech/content/dev-tool); money paths + verification/recovery flows | `business.json` |
| U2 | **Recon Census** | ✅ | Surface ranking by business-criticality (money ×6, differentials ×8, OpenAPI boost) over the fetched surface | ranked `surface` in model |
| U3 | **Application Logic** | ✅ | Workflow extraction across 7 families (purchase/auth/redemption/recovery/verification/onboarding/**funds-out**) + state machines (ordered state verbs) | `workflows` in model |
| U4 | **Identity/Authz** | ✅ | Roles (with origin attribution jwt→body→operator), JWT `alg`/`kid` inventory, authz boundaries from differential statuses | `identity.json` |
| U5 | **Data & State** | ✅ | Bounded object-ID format extractor + client-controlled field inventory (fed live from `session_context`) | `data.json` |
| U6 | **Trust/Boundaries** | ✅ | Header-trust family inventory + boundary crossings from crawl/header evidence | `trust.json` |
| U7 | **Capability Map** | ✅ | (role, object, verb, impact) tuples ranked dollars→privilege→ATO/PII | `capabilities.json` |
| U8 | **Assumption Ledger** | ✅ | Per-stage assumptions with origin/confidence/dispro plan, ranked by fragility (1−confidence)×stage weight; JSONL seed list, operator-annotatable | `assumptions.jsonl` |
| U9 | **Synthesis & Coverage Gate** | ✅ | 10 coverage classes; a class hunts **only with model support**, else **parked with reason**; renders the Hunting Brief | `target-model.json`, `hunting-brief.md` |

Pipeline properties (verified by `tests/test_understanding_layer.py`, 20 tests): strict per-stage prerequisites (`StagePrerequisiteError`), fail-closed (no facts at all ⇒ refusal, never a hollow brief), incremental recompute via input hashes (tamper ⇒ affected stages only), hash-chained artifacts.

### 8.2 Why sequential matters — ENFORCED

The scheduler blocks hunting until the model passes the coverage gate; **and now the dispatch layer enforces it a second time** (v1.18): a parked class cannot be sprayed even if a stale roster tries. Belt and suspenders.

### 8.3 Feeding the hunt — ✅ COMPLETE (v1.18 core + v1.19 prediction)

- ✅ Every dispatch prompt is **augmented with the relevant model slice**: a hunting agent for `business-logic` receives workflows (U3) + money paths (U1) with ranked hypotheses and dispro plans; an IDOR agent receives the object-ID inventory (U5) + roles/identity matrix (U4). No agent hunts from a blank slate. Wired at both integration points: `TeamEngine._build_research_context` (per-member intel) and `MissionRunner` web-lane dispatch (family gate + park logging).
- ✅ The **Assumption Ledger (U8) is the hypothesis pool**: agents test dispro plans, they don't wander. Wild mode is now assumption-first by construction.
- ✅ **Chain-prediction dispatches (shipped v1.19)** — the U-layer predicts chains *before testing*: a granted capability (U7) × a fragile assumption (U8) yields a ranked, terminal-aware dispatch (`chain_predict.py`); predicted classes staff their specialists pre-hunt, reorder the family swarm, and headline the brief. CyberStrike's chain engine only correlates *findings*; bugwolf predicts them.

### 8.4 What's reused vs new — outcome

| Planned reuse | Outcome |
|---|---|
| 5-map doctrine → U4–U7 outputs | ✅ delivered |
| accounts matrix + per-credential crawl | ✅ delivered (`authed_crawl` rides the replay engine: scope gate + governor inherited) |
| session/JWT decode | ✅ delivered (`session_context`, live claim inventory) |
| U8 + dispro-plan generator | ✅ delivered |
| U9 synthesis + coverage gate | ✅ delivered |
| Model-slice injection into dispatch prompts | ✅ delivered (v1.18) |
| U7×U8 predicted-chain dispatches | ✅ delivered (v1.19, `chain_predict.py` — prediction engine + pre-hunt staffing + brief section; `deep_chain` remains the observed-findings synthesizer and its graph feeds the prediction's terminal chaining) |

---

## PART II — SEND ENGINE (Phase 1) — ✅ SHIPPED v1.11–1.12 (one gap)

| # | Component | Status | Notes |
|---|---|---|---|
| 1.1 | `replay/message.py` — byte-exact HTTP/1.1 parse/serialize | ✅ | header case, whitespace, duplicates, malformed framing round-trip exactly |
| 1.1b | **HTTP/2 pseudo-layer** (hpack, stream framing) | ✅ **shipped v1.20.0** — hpack (RFC 7541, no-Huffman + non-conformant mode) + h2 framing + H2Frontend; H2.CL desync observed end-to-end (victim receives the internal-gateway admin-token response); safe-mode control proves the switch genuinely opt-in |
| 1.2 | `replay/apply.py` — 16 mutation ops | ✅ | JSON dot-paths, set-cookie/method/path-param/target |
| 1.3 | `replay/encode.py` — composable pipelines | ✅ | url, double-url, base64, hex, html-dec, unicode |
| 1.4 | `replay/backend_socket.py` — raw socket sender | ✅ | `send_raw` (CL.TE/TE.CL), duplicate headers, Host override, timing |
| 1.5 | `replay/observe.py` — facts only, never verdicts | ✅ | verdicts remain the F0.5 gate's job |
| 1.6 | `replay/governor.py` — circuit breaker, AIMD, token bucket, budget | ✅ | no self-DoS; crawl/session/dispatch all inherit it |
| 1.7 | `replay/batch.py` — compare + sweep modes | ✅ | A/B per-side credentials, one mutation × N positions |
| 1.8 | Tool surface `http_replay` / `http_replay_raw` via MCP, scope-gated | ✅ | deny-by-default, sandboxed |
| 1.9 | Desync stub tests | ✅ | CL.TE-smugglable frontend; CI asserts the raw engine detects desync where curl cannot |
| 1.10 | U5/U6 drive compare/sweep strategies | ✅ | model slices name the mutation surface (v1.18 wiring) |

---

## PART III — BROWSER & AUTH SESSION (Phase 2) — ✅ SHIPPED v1.13 (one gap)

| # | Component | Status | Notes |
|---|---|---|---|
| 2.1 | `browser_driver_playwright.py` real binding | ✅ | navigate/console/DOM/screenshot; missing Playwright ⇒ honest `blocked-browser` |
| 2.2 | Session context store | ✅ | per-credential tokens (memory-only, structural redaction), roles with source attribution, live JWT decode, object-ID inventory, identity matrix; MCP `bugwolf_sessions` |
| 2.3 | Autonomous authenticated crawl | ✅ | same URL space once per identity via the replay engine; `differential_paths()` = the authz hunt's candidate list; artifacts `access_matrix.json` + `pages.jsonl`; runs automatically at mission step 2.7 when accounts are bound |
| 2.4 | **Capture→replay loop** (mitmproxy addon / extension → `captures.jsonl` → replay import) | ✅ **shipped v1.21.0** — self-contained addon (byte-exact wire text, framing headers withheld + noted, suffix allow-list) + fail-closed loader + scope-never-widens replay + drift facts + `bugwolf_capture_replay` MCP tool |
| 2.5 | Browser-confirmed verdicts | ✅ | client-side lane requires console/DOM signature — reflection ≠ execution enforceable |

---

## PART IV — PACKAGING (Phase 0) — ✅ SHIPPED v1.10

All five acceptance items delivered: marketplace.json with owner/tags/category · plugin.json version-sync + repository/keywords with skills restructure · root `.mcp.json` → bridge · CI version-sync + manifest gate (`tools/plugin_manifest.py --all`) · SECURITY.md + CONTRIBUTING.md + signed release workflow (v1.16 upgrade). 16 commands, 39 agents, 14 MCP tools registered and drift-checked.

---

## PART V — HOOKS (Phase 3) — ✅ CORE SHIPPED v1.14 (two hooks missing)

| # | Hook | Status | Notes |
|---|---|---|---|
| 3.1 | **PreToolUse scope enforcement** (the killer feature) | ✅ | Bash **and** WebFetch matchers; host extraction → scope gate → deny (exit 2, un-overridable) with reason + policy fact; writes/clears contract around missions; inert without a contract, fail-open on harness errors; 17 tests |
| 3.2 | UserPromptSubmit (NL invocation → MissionSpec injection) | ✅ **shipped v1.22.0** | mission context via additionalContext + TARGET MODEL STALE warning (window: BUGWOLF_MODEL_MAX_AGE_H, 24h) |
| 3.3 | PostToolUse (auto-capture HTTP-ish outputs → hash-chained evidence ledger with `replay_key`) | ✅ **shipped v1.22.0** | evidence.jsonl hash chain + replay_key; bugwolf replay reports captured natively |
| 3.4 | SessionStart cockpit | ✅ **shipped v1.22.0** | scope + preflight + sandbox + leads + mode + target-model freshness; v1.14 shim unchanged (cockpit = second SessionStart hook) |

---

## PART VI — AGENTS & COMMANDS (Phases 4–5) — ✅ SHIPPED v1.10 + v1.15

**Agents:** generator emits native `model:` (sonnet/opus/haiku/inherit) — the silently-ignored `model-tier:` is **forbidden by a packaging gate**; real Claude Code tool names; per-agent allowlists; 39 agents byte-identical to the registry (generator `--check` in CI).

**Commands (all six + existing ten = 16):** `/bugwolf-leads`, `/bugwolf-scope` (intake + live gate preview + hook contract verification), `/bugwolf-research` (R1–R7 + freshness), `/bugwolf-chain`, `/bugwolf-doctor` (stub-target smoke + **opt-in `--check-update` with pinned release hash**), **`/bugwolf-understand`** — the front door: runs the real U1→U9 pipeline and prints the Hunting Brief.

---

## PART VII — OPSEC & SUPPLY CHAIN (Phase 6) — ✅ SHIPPED v1.16

- ✅ **Home-beacon dead** — all three instances (SKILL.md auto-update section, session-start step, residue) removed; replacement is opt-in `/bugwolf-doctor --check-update` against pinned Releases.
- ✅ **Signed releases** — `tools/release_signing.py`: SHA-256 tree manifest + minisign modes for `SHA256SUMS.txt`; release.yml signs when `MINISIGN_KEY` secret exists (honestly unsigned otherwise); artifacts published.
- ✅ **Installed-tree verification** — `harness_guard verify_install` checks the manifest on disk.
- ✅ **Pinned tool installs** — every `@latest` → tagged release, every floating pip → `==` pin, no pipe-to-shell; policy block in `references/recon-tooling.md`; 24-test opsec suite enforces the format.
- ✅ **OAST transparency** — `docs/OAST_TRANSPARENCY.md`: what crosses the tunnel, who sees it, self-hosted option.

---

## PART VIII — PROOF (Phase 7) — ⬜ THE REMAINING BUILD (ships v2.0.0)

1. **Scored corpus** in the stub target: IDOR, authz bypass, mass assignment, CL.TE, ~~H2.CL desync (arrives with 1.1b)~~ ✅ **H2.CL items shipped v1.22.1** (`h2cl-victim-poisoned` desync case + `h2cl-safe-front-end` negative control; lab-backed transport in the benchmark scorer; evidence = victim-observed smuggled marker; hermetic runs skip lab cases with a recorded reason), cache poisoning, race/coupon, XSS (browser-confirmed), JWT confusion, SSRF (OAST closure), GraphQL gid, business-logic workflow skip. Ground truth = trigger + impact. Each corpus item declares which U-stage/assumption feeds it — corpus doubles as an Understanding-Layer regression suite. ✅ **U-regression bridge shipped v1.23.0** (`tools/u_regression.py`: each case's `u_stages` declaration becomes executable checks over a live mini-mission — declared-stage artifacts, per-class fact support, negative-control absence facts; `benchmark.py --enable-u-regression` folds it into the gate as `u_regression_ok`).
2. **Metrics**: per-class detection rate, FP rate (F0.5 gate efficacy), requests-per-finding, time-to-first-finding, lead→finding promotion rate, recomposition effectiveness, **assumption-dispro rate (U8 hypotheses confirmed vs refuted)**.
3. **Head-to-head**: same corpus through raw Claude Code, Claude-BugHunter, offensive-claude. Publish the table with v2.0.0. Neither competitor publishes numbers.
4. **Adopt offensive-claude's best idea**: blind checker rebuttal loop (artifact-only checker, PASS/KILL/DOWNGRADE, Wilson-bounded model trust) on top of the F0.5 gate.
5. **Benchmark harness** (`tools/benchmark/` + `tests/test_benchmark.py`): deterministic run harness (seeded, budgeted, scope-contracted), JSONL run records, metric extraction, one-command corpus replay — CI runs the smoke corpus on every PR so the #1 claim stays measured, not remembered.

---

## REVISED EXECUTION ORDER (where we actually are → v2.0)

The original week-based order is obsolete — the delivered order diverged deliberately (engine before hooks; understanding after sessions, as the rationale predicted). The remaining path:

| Ship | Contents | Why this order |
|---|---|---|
| **v1.19.0 — "Parity + Prediction"** | ① ~~deep_chain × U7×U8 predicted chains~~ ✅ **shipped v1.19.0** · ② ~~1.1b HTTP/2 pseudo-layer~~ ✅ **shipped v1.20.0** · ③ ~~2.4 capture→replay loop~~ ✅ **shipped v1.21.0** · ④ ~~hooks 3.2 + 3.3 + cockpit 3.4~~ ✅ **shipped v1.22.0** | ALL FOUR delivered: predictions staff pre-hunt; H2.CL joins the desync classes; session traffic replays through the governed engine; the harness remembers (context injection, evidence chain, cockpit). Parity complete — only Phase 7 remains |
| **v2.0.0 — "Mind of the Wolf"** | Phase 7 complete: scored corpus, benchmark harness, head-to-head table, checker rebuttal loop, published metrics | proof ships last, against a frozen feature set — numbers must not chase a moving target |

Fallback preserved from the original plan: if time forces a cut, the benchmark keeps the deterministic-corpus subset (HTTP/2-dependent H2.CL items move to a v2.0.x addendum) — the measurement never blocks on the parity gaps.

### Cross-pollination: ECC + Agent-Reach (deep plan → `docs/INTEGRATION_PLAN.md`) — ✅ **IMPLEMENTED v1.24.0 (all six phases)**
A verified-source audit of the ECC harness project (continuous-learning instinct loop, bounty-hunter skip-list, agent-eval methodology, agent-security threat model) and the Agent-Reach channel architecture (ordered backends, real-probe checks, doctor, antibot heuristics) produced a six-phase integration plan mapped to v1.24.0–v1.29.0: **A** instincts (post-mission learning loop over existing ledgers → dispatch weighting + cockpit), **B** noise filter (skip-list as executable ReportingGate logic), **C** head-to-head harness (agent-eval methodology completing the Phase 7 deliverable), **D** injection canaries (target content is data-with-provenance, never instruction), **E** intel lane (AR Channel ABC ported under bugwolf's third-party/scope rules, default-off, v2.0.x addendum candidate), **F** antibot facts in `_fetch_pages`. Wholesale adoption of either project and their install flows are explicitly refused (hook collision / resolver shadowing / prompt-injection-by-install-doc); the plan's design law keeps every addition stdlib-only, deterministic-first, scope-safe, and hermetically testable.

---

## SUCCESS CRITERIA (measured "first place") — status

1. ✅ `/plugin install bugwolf@youseefhamdi` — one line, CI-validated (manifest gate + version sync).
2. ✅ **Only** plugin whose hunting is gated on a computed Target Model (sequential U1–U9, coverage-gated, dispatch-enforced twice).
3. ✅ **Only** plugin enforcing scope at the harness level (PreToolUse hook, Bash+WebFetch, deny = exit 2).
4. ✅ Raw-socket replay shipping (smuggling/desync/cache-poisoning classes) — H2.CL shipped with the 1.1b layer (v1.20.0); chain **prediction** already shipped (v1.19.0)
5. ✅ Browser-confirmed client-side findings out of the box.
6. ✅ 39 specialists dispatching natively through the Task tool.
7. ⬜ Published head-to-head benchmark — the only one in the space (v2.0.0).
8. ⬜ Assumption-dispro rate reported per mission — the metric that proves "understanding finds zero-days" (v2.0.0).

---

*Sources: Google Project Zero, "Project Naptime" (2024) and "From Naptime to Big Sleep" (2024); PortSwigger Web Security Academy, Business Logic Vulnerabilities; OWASP Top 10 for Business Logic Abuse. Delivery evidence: CHANGELOG v1.10.0→v1.18.0, full-suite runs (1,653 tests OK), manifest gate, AUDIT_MAP.md.*

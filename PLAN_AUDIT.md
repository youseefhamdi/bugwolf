# Audit: BUGWOLF_OMC_UPGRADE_PLAN.md (double-checked, file-by-file re-verification)

**Audited:** 2026-09-02. First pass sampled both trees; this revision re-ran verification with deeper, line-level reads of `bugwolf` (v1.2.11) and `oh-my-claudecode` (v5.1.0).
**Verdict:** Unchanged directionally — the plan is phased, exit-criteria-driven, and its honesty ethos matches the repos. The re-check **confirmed all three original critical findings** and **added three corrections to the first audit**: (1) BugWolf already has a natural-language mission intake parser, (2) the existing event bus has 16 typed events, not 10, (3) one governance claim (`safety.py`) was wrong — it is a deprecated shim, and the real semantics module *intentionally does not enforce authorization*.

---

## 1. Plan claims verified against code (confirmed)

| Plan claim | Evidence |
|---|---|
| OMC v5.1.0 reference | `oh-my-claudecode/package.json`, `.claude-plugin/plugin.json` both `5.1.0` |
| 12-stage campaign workflow, checkpoints | `tools/core/campaign_orchestrator.py` (1,908+ lines, `CampaignOrchestrator`@133, `CampaignPhase`@81), `tools/core/stage_controller.py` (`WorkflowController`@320, append-only artifact digests, workflow-chain integrity hashes) |
| Evidence, replay, ledger, chain-of-custody | `tools/core/live_executor.py` (822 lines: `build_probe_specs`@221, `execute_probe`@546, `execute_exploit`@686, `verify_reproducibility`@752, `replay_key`), `tools/core/fuzz_bridge.py` (379 lines), `ledger.py`, `chain_of_custody.py`, `refutation.py` (`require_reproducible` F0.5 gate) |
| Domain coverage §7 | Verified directories: `tools/domains/{api,web,auth,cloud,llm,mobile,smart_contracts}` — e.g. `iam_privesc_graph.py`, `rag_memory_poisoning.py`, `agentic_tool_auth.py`, `http_smuggling_detector.py`, `deep_link_analyzer.py`, `price_manipulation_analyzer.py`; plus `zero_day_tracks.py` with five domain track classes |
| Existing `signal_bus.py`, research threads, learning, ledgers should publish into new event model | Correct instinct — verified `tools/core/signal_bus.py` (334 lines, replay + persistence + `publish_or_warn`); `tools/core/agent_bus.py` (`AgentBus`@79, persistent inbox/processed/deliveries) |
| "No second implementation of campaign/evidence/ledger" | Matches `DEPENDENCIES.md` AST-verified leaf→signal_bus architecture |
| Performance targets and measurement | `tools/benchmark.py` + `configs/benchmark.json` (BOLA/mass-assignment cases incl. negative control `bola-missing-999`) exist |

## 2. Critical finding A (re-confirmed, strengthened): the plan re-invents modules that exist

| Plan proposes | Already exists (verified) | Correction to plan |
|---|---|---|
| §5.1 five capability profiles; `runtime/model_router.py` | **`tools/core/model_router.py`** (226 lines): 3 tiers (`deterministic`/`local_slm`/`frontier`), complexity scoring, advisory `model_preference` hints, fail-open degradation — *no `configs/models.json` exists yet; that part is genuinely new* | Extend the existing router with config-file profile mapping; keep advisory, fail-open semantics. Do not build a second router. |
| §O4 event bus with 10 event names | **`tools/core/signal_bus.py` already has 16 typed events** (`RECON_COMPLETE`, `FINDING_DISCOVERED`, `WAF_BLOCKED`, `STAGE_ADVANCED`, `SMUGGLING_CANDIDATE`, `AUTH_CANDIDATE`, `DISCOVERY_COMPLETE`, `RESEARCH_REFRESHED`, `CLOUD_CANDIDATE`, `MOBILE_CANDIDATE`, `ASSET_DELTA`, `LLM_CANDIDATE`, `LAB_PLANNED`, `CHAIN_PROPOSAL`, `EVAL_COMPLETE`, `GRAPHQL_CANDIDATE`) plus a documented `CANONICAL_LISTENERS` wiring table | Plan's 10 events are a subset-and-rename. Only `MissionCreated`, `TaskPlanned`, `TaskStarted`, `ArtifactProduced`, `VerificationCompleted`, `ReportReady` are genuinely new; `BlockerObserved` ≈ `WAF_BLOCKED`/blocked-thread states. Extend, don't replace. |
| §O3 scheduler, "benchmark asyncio vs threads" | `tools/fleet.py` `FleetExecutor`@232 (ThreadPoolExecutor, bounded concurrency, shutdown flag), `tools/discovery_scheduler.py` `DiscoveryScheduler`@140, `execution_controller.py`, `execution_semantics.py` | Runtime model is settled by convention (threads). Drop the dual-runtime benchmark. |
| §O6 team execution | `tools/core/agent_bus.py` (mailbox transport), `multi_agent_fixture.py` (`MultiAgentFixture`@17) | Name agent_bus as transport. |
| §O2 registry + §8 "generated capability manifest" | `tools/capability_registry.py` (`CapabilityRegistry`@223, `CapabilityChain`@200, 643+ lines), `tools/readiness.py` (289 lines) + `configs/readiness.json` (readiness levels L0–L4, claims validation, per-target-class entrypoints) | Extend; don't build new. |
| Phase 0 "inventory" | `AUDIT_MAP.md` (per-module symbol map), `DEPENDENCIES.md` (import graph) | Phase 0 ≈ already done; rewrite as validation. |
| §4.2 Layer B "normalize conversational requests into MissionSpec" | **`tools/harness_command.py`** (171 lines): parses `bugwolf --full attack this target <url>` into an execution plan; `MODE_FLAGS` cover web/web_api/smart_contract/cloud_cicd/llm_ai/mobile/report/triage; never executes; `configs/harness/intelligence.json` defines direct-invocation semantics | **New finding in re-check.** Layer B's intake parser already exists — MissionSpec should be built on top of `harness_command.parse_invocation`, not written fresh. |
| §11 proposed layout | Root `SKILL.md` exists; `tools/{core,domains,intelligence,validation}` is the established structure; `state/`, `configs/` exist | Use `tools/runtime/` (or extend `tools/core/`), not top-level `runtime/`; don't list SKILL.md as a new deliverable. |

**Shim trap (re-confirmed):** `tools/{campaign_orchestrator,research_loop,stage_controller,agent_bus}.py` at top level are compatibility shims re-exporting `tools.core.*` (`sys.modules[__name__] = _impl`). Any Phase 5 rewrite must keep these importable and CLI-runnable — tests (`test_apt_commander_week1.py`, `test_ci_bundle_check.py`) and `scripts/ci_bundle_check.sh` reference them.

## 3. Critical finding B (re-confirmed): the Claude integration layer is mis-specified

Re-verified OMC's actual integration surface, file by file:

- `.claude-plugin/plugin.json` + `marketplace.json` ("28 agents, 35 skills")
- `hooks/hooks.json`: `UserPromptSubmit` (keyword-detector, skill-injector), `SessionStart` (session-start, project-memory, wiki), `PreToolUse` (pre-tool-enforcer), `PermissionRequest` (permission-handler), `PostToolUse` (post-tool-verifier, rules-injector, failure), `SubagentStart/Stop` (subagent-tracker, verify-deliverables), `PreCompact`, `Stop` (**persistent-mode.mjs**, workflow-drift-guard, context-guard-stop, session-end)
- `commands/` (21 command markdown files), `skills/` (35 directories with SKILL.md, e.g. `ralph` = PRD-driven persistence loop with reviewer verification), `bridge/*.cjs` + `src/mcp` for MCP

No SDK-embedding layer exists anywhere in OMC. Meanwhile BugWolf's own `SKILL.md` declares `BUGWOLF-HARNESS-CONTRACT-V2` targeting **Claude Code, Freebuff/Codebuff, Codex, Cursor, Windsurf, Copilot** — harness-agnostic by design, and `model_router.py` explicitly states "BugWolf never calls a model itself."

**Correction to plan Layer A:** build a **plugin package around the Python CLI** (`plugin.json`, `hooks.json` with a SessionStart gate running `tools/harness_guard.py --verify`, a Stop hook wired to persistent modes, `commands/bugwolf*.md`, existing SKILL.md, optional MCP server exposing tools). Delete `runtime/claude_adapter.py` and Agent-SDK embedding. This preserves harness-agnosticism and removes the plan's biggest architectural risk.

## 4. Critical finding C (re-confirmed, one claim corrected): governance spine

The re-check found nuance the first audit got wrong:

- ✅ `tools/harness_guard.py` — contract verification gate; belongs as the SessionStart hook.
- ✅ `tools/target_intake.py` — operator spec, attestation, RoE, scope recording; must attach to MissionSpec provenance.
- ✅ `tools/opsec.py` (`OpsecRotator`@272, `FreshProxyPool`@117), `tools/pii_firewall.py` — real operational modules.
- ❌ **Correction:** `tools/safety.py` is a **deprecated compatibility shim** ("Use `tools.execution_semantics` for new imports"), and `tools/execution_semantics.py` **intentionally does not enforce authorization, scope membership, or active/destructive confirmations** — it validates shape only ("isolated lab mode", "uncensored execution semantics"). The plan's principle "external operations remain visible, bounded, and attributable" therefore has **no enforcement layer today beyond advisory gates** (`stage_controller` integrity digests, `refutation` evidence gates, F0.5). The upgrade plan must either (a) state this explicitly as a known limitation, or (b) schedule a real policy-enforcement boundary as a phase deliverable. Silent assumption of enforcement is exactly the "documentation overstates maturity" risk the plan lists.

## 5. Structural issues (re-confirmed)

1. **Two phase tracks** (O1–O6 vs 0–8) overlap with no cross-map (O3≈Phase 3, O4≈Phase 3/5, O1≈Phase 2). Merge or map.
2. **Layout conflicts** — see table above.
3. **Registry discipline gap:** OMC's "honest capability reporting" is mechanically enforced in `src/workflow/registry.ts` (TIER0 roles, risk classes, `failModeForRisk` fail-closed/fail-open) and `src/workflow/projections.ts` (`computeRegistryDigest`, `checkProjectionDrift`). BugWolf's `/bugwolf-*` surface (Phase O1) should adopt the digest+drift-check pattern via `capability_registry.py` + CI; the plan never mentions this mechanism.
4. **OMC team runtime is not portable:** `src/team/` is ~72 TypeScript files (tmux-comm, tmux-session, pane-readiness, worker-health, git-worktree…). Keep O6 conceptual; say so explicitly.

## 6. Minor issues

- §12 test plan should name existing suites to extend: `test_apt_commander_week1.py` (signal_bus coverage), `test_e2e_deep_dive_campaign.py`, `test_f05_strict_validation.py` (delegates to `live_executor.verify_reproducibility`), `test_live_executor.py`, `test_fuzz_bridge.py`, `test_integrity_hardening.py`.
- OMC advertises 28 agents/35 skills; plan's 14 roles is better right-sized — keep it, and justify via plan non-goal "no agents without measurable role separation."
- §8.1 baseline metrics should cite `configs/benchmark.json` + `tools/benchmark.py` as the existing harness.

## 7. Recommended revisions (ordered, updated)

1. Layer A → plugin packaging (plugin.json + hooks + commands + SKILL.md + optional MCP). Delete SDK adapter.
2. Layer B → build `MissionSpec` on `harness_command.parse_invocation` + `target_intake` provenance. Don't write a new parser.
3. §5 → extend `tools/core/model_router.py`; add `configs/models.json` (genuinely new); add provenance hashes to results.
4. §O4 → extend `signal_bus.py` taxonomy (+6 new events), transport via `agent_bus.py`. Delete `events.py` proposal.
5. §O3 → extend FleetExecutor + DiscoveryScheduler; threads; drop asyncio benchmark.
6. Add governance to Layers B/C: harness_guard as SessionStart hook; target_intake on MissionSpec; **decide explicitly on authorization enforcement** (see §4 finding) instead of assuming it.
7. Merge O-phases into §10 with a mapping table.
8. Fix §11 layout to `tools/runtime/`, `tools/agents/`; keep shims working through Phase 5.
9. Phase 0 → validate AUDIT_MAP/DEPENDENCIES/readiness instead of re-inventorying.
10. Phase O1/8 → add OMC-style registry digest + drift check to CI.

## 8. Effort estimate (updated)

With the substrate credited, Phases 0–2 shrink to roughly a third of planned scope (contracts + router/config extension + plugin packaging + intake adapter). Phases 3–5 remain the real work. **One new scope item emerged from the re-check:** an explicit authorization/scope enforcement boundary (or a documented decision to remain advisory-only) — this should be scheduled before Phase 3 dispatches live traffic.

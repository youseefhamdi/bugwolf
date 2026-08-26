# BugWolf module dependency graph (one page)

What imports what inside `tools/`, focused on how the **core/campaign engine**
connects to the **`domains/` · `intelligence/` · `recon/` · `validation/`**
modules. Verified by an AST pass over every `.py` under `tools/` (88 modules
with intra-tools edges; excludes `__init__.py` stubs, `.pyc`, and pure-stdlib
imports).

> **The key architectural fact:** `domains/`, `intelligence/`, `recon/` and
> `validation/` are **leaf modules — nothing imports them**. They publish onto
> the shared event bus (`core/signal_bus.py`) and are wired into the campaign
> as **standalone CLI tools** (required in the release bundle + invoked by the
> orchestrator/CI), not as import dependencies. Import-level coupling is almost
> entirely **upward**: leaf → `core/signal_bus.py`.

---

## 1. Direct import consumers of `domains/ · intelligence/ · recon/ · validation/`

Only **two** modules anywhere in `tools/` import from these groups:

```
core/campaign_orchestrator.py  →  intelligence/failure_learning.py
                               →  intelligence/seed_advisor.py
```

Everything else that needs domain results does so via `core/signal_bus.py`
events (`FINDING_DISCOVERED`, `WAF_BLOCKED`, `SMUGGLING_CANDIDATE`, …), not
imports.

---

## 2. Upward imports — leaf modules → `core/signal_bus.py`

Every module below imports `tools.core.signal_bus` (typed events) + the
`publish_or_warn` helper. They publish findings and **do not** depend on the
orchestrator; the orchestrator subscribes.

| Group | Modules importing `core/signal_bus.py` |
|---|---|
| `domains/api` | bopla_matrix · graphql_batch_analyzer |
| `domains/auth` | ato_chain_planner · jwt_forgery · oauth_flow_analyzer |
| `domains/cloud` | iam_privesc_graph |
| `domains/llm` | agentic_tool_auth · rag_memory_poisoning |
| `domains/mobile` | deep_link_analyzer · mobile_policy_checker |
| `domains/smart_contracts` | llm_contract_triage · price_manipulation_analyzer |
| `domains/web` | http_smuggling_detector · parser_differential |
| `intelligence` | chain_graph_ai · failure_learning · seed_advisor |
| `recon` | historical_asset_delta |
| `validation` | self_eval_harness · verification_lab |

*(All 20 additionally import `runtime_paths.py` for workspace resolution; each
domain module uses a local `_repo_root` helper for its own output paths.)*

---

## 3. `core/campaign_orchestrator.py` fan-in (the campaign engine's imports)

The orchestrator wires the whole engine together. It imports (among top-level &
core) these **specialized** modules:

```
asset_discovery · campaign · chain_orchestrator · leads · mutator ·
refutation · research_model · research_thread · stage_controller · zero_day
core/fuzz_bridge · core/live_executor · core/model_router · core/signal_bus
core/research_loop
intelligence/failure_learning · intelligence/seed_advisor   ← the ONLY domains/intelligence deps
```

Other `core/` tools import each other (and top-level helpers) as:

```
core/stage_controller   →  harness_guard · paper_intel (stage artifact logic)
core/fuzz_bridge        →  core/live_executor · core/signal_bus · mutator · schema_extractor
core/research_loop      →  adaptive_learning · wordlist_gen
core/live_executor      →  runtime_paths
core/signal_bus         →  runtime_paths
core/agent_bus          →  evidence · post_finding_trigger · safety
core/model_router       →  (none — pure classifier)
```

---

## 4. Campaign toolchain (top-level → core/intelligence)

```
campaign.py (state)      →  evidence · runtime_paths · safety
asset_discovery.py       →  campaign.py
research_thread.py       →  asset_discovery · campaign · core/model_router
fleet.py                 →  runtime_paths · safety · state
leads.py                 →  deep_chain · runtime_paths · state
chain_orchestrator.py    →  deep_chain · evidence · runtime_paths · safety
core/campaign_orchestrator →  ← fan-in above (drives ALL of the preceding)
```

---

## 5. At a glance

```
                       ┌────────────────────────────────────────────┐
                       │         core/campaign_orchestrator.py      │
                       │   the engine imports (imports only):       │
                       │   campaign · asset_discovery · research_.. │
                       │   chain_orchestrator · leads · mutator ·   │
                       │   refutation · zero_day · stage_controller │
                       │   core/{fuzz_bridge,live_executor,         │
                       │        model_router,signal_bus,research_..}│
                       │   intelligence/{failure_learning,          │
                       │                 seed_advisor}              │
                       └───────────────┬────────────────────────────┘
                                       │ subscribes to events
                                       ▼
                        ┌────────────────────────────────────────┐
                        │  core/signal_bus.py (typed event bus)  │
                        │  publish_or_warn(…)                    │
                        └───────▲────────────────────────▲───────┘
                                │ publishes              │ publishes
      ┌──────────────────────────┴───────┐   ┌───────────┴──────────────────────┐
      │  domains/{web,api,auth,cloud,    │   │  intelligence/ · recon/ ·        │
      │    llm,mobile,smart_contracts}   │   │  validation/  (20 leaf tools)    │
      │  14 analyzers + 6 advisors       │   │  e.g. self_eval_harness          │
      └──────────────────────────────────┘   └──────────────────────────────────┘
      Each leaf imports ONLY core/signal_bus + runtime_paths,
      and is driven as a standalone CLI tool (bundle REQUIRED list).

      There are NO import edges back from leaves into the orchestrator.
```

---

*Edges derived on 2026-08-26 from an AST import walk of `tools/`. The two rows
that matter for the question "which core tools import which
domains/intelligence modules" are: `core/campaign_orchestrator.py →
intelligence/failure_learning.py, intelligence/seed_advisor.py` — and the
event-bus publish path that binds the other 18 leaf modules.*
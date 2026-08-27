# BugWolf Zero-Day Capability Implementation Status

Current as of the last verified run. The full suite passes:

```text
python3 -m unittest discover -s tests -p 'test*.py'
Ran 1030 tests
OK
```

## Implemented

### Phase 1 — Shared foundation

| Module | Purpose |
|---|---|
| `tools/candidate_lifecycle.py` | Shared `ResearchCandidate` schema, lifecycle state machine, signatures, dedup store, legacy migration, report export |
| `tools/novelty_pipeline.py` | Advisory catalog, novelty classification, ranking, reproducibility manifests, near-duplicate clustering |
| `tools/sarif_export.py` | SARIF 2.1.0 export |
| `tools/candidate_cli.py` | Candidate query CLI with filters and SARIF export |
| `tools/nvd_ingester.py` | NVD 2.0 JSON feed ingestion into the advisory catalog (offline, operator-supplied feed) |
| `tools/zero_day_pipeline.py` | End-to-end pipeline runner tying adapters, novelty, chaining, and reports |

### Phase 2 — Web/API

| Module | Purpose |
|---|---|
| `tools/web_api_research.py` | OpenAPI surface analysis, sibling drift, behavioral deltas |
| `tools/web_api_workflow.py` | Workflow skip/reorder/repeat, race-condition signals |
| `tools/web_api_protocol.py` | Protocol trace normalization, HAR export |
| `tools/protocol_adapters.py` | GraphQL / WebSocket / gRPC observation adapters |
| `tools/protocol_differential_fixture.py` | HTTP/2·HTTP/3 differential + serverless/edge simulation |
| `tools/supply_chain_analyzer.py` | Install-script and provenance analysis |
| `tools/http_protocol_runner.py` | Bounded HTTP/1.1·HTTP/2·HTTP/3 probing via curl with graceful skips |

### Phase 3 — Web3

| Module | Purpose |
|---|---|
| `tools/web3_research.py` | Invariant violations, cross-environment trace deltas |
| `tools/web3_tool_adapter.py` | Slither / property-runner output normalization |
| `tools/web3_fixture_runner.py` | Bounded tool planning and execution (Slither, Echidna, Medusa, Foundry, ...) |
| `tools/web3_protocol_fixture.py` | ERC-4337 and L2 bridge replay models |
| `lab/web3/` | Foundry-style lab fixture: `Vault.sol`, `Invariants.t.sol`, `foundry.toml`, `manifest.json` |

### Phase 4 — AI red teaming

| Module | Purpose |
|---|---|
| `tools/ai_red_team_adapter.py` | Agent tool misuse, RAG/memory/MCP poisoning |
| `tools/ai_tool_adapters.py` | PyRIT / Garak / Promptfoo trace normalization |
| `tools/llm_sandbox.py` | Deterministic local LLM harness with tracing |
| `tools/mcp_fixture.py` | MCP tool/resource metadata mutation fixtures |
| `tools/digest_canary.py` | Model/data digest, provenance tracking, leakage canaries |
| `tools/multi_agent_fixture.py` | Multi-agent delegation tracking, goal-hijack detection |
| `tools/red_team_runner.py` | Bounded PyRIT/Garak/Promptfoo command planning and execution |

### Phase 5 — Cross-domain

| Module | Purpose |
|---|---|
| `tools/cross_domain.py` | Candidate correlation across AI / Web/API / Web3, chain reports |
| `tools/lineage_graph.py` | Document → tool call → request → transaction lineage |

## Lab fixtures

| Fixture | Purpose |
|---|---|
| `lab/web3/src/Vault.sol` | Intentionally vulnerable lab-only contract (reentrancy, unrestricted oracle setter, no staleness checks) |
| `lab/web3/test/Invariants.t.sol` | Foundry-style invariant tests with deterministic fuzz seed |
| `lab/web3/foundry.toml` | Deterministic fuzz configuration |
| `lab/web3/manifest.json` | Declared intentional findings, tools, isolation flags |
| `lab/FIXTURES.md` | Fixture inventory, usage, isolation requirements |

## Test coverage

Each module has a focused test file under `tests/`:

```text
tests/test_candidate_lifecycle.py
tests/test_novelty_pipeline.py
tests/test_near_duplicate_clustering.py
tests/test_sarif_export.py
tests/test_candidate_cli.py
tests/test_nvd_ingester.py
tests/test_zero_day_pipeline.py
tests/test_web_api_research.py
tests/test_web_api_workflow.py
tests/test_web_api_protocol.py
tests/test_protocol_adapters.py
tests/test_protocol_differential_fixture.py
tests/test_supply_chain.py
tests/test_http_protocol_runner.py
tests/test_web3_research_adapter.py
tests/test_web3_tool_adapter.py
tests/test_web3_fixture_runner.py
tests/test_web3_protocol_fixture.py
tests/test_web3_lab_fixture.py
tests/test_ai_red_team_adapter.py
tests/test_ai_tool_adapters.py
tests/test_ai_sandbox.py
tests/test_digest_canary.py
tests/test_multi_agent_fixture.py
tests/test_red_team_runner.py
tests/test_cross_domain.py
tests/test_lineage_graph.py
```

## Remaining / integration-layer only

These require external toolchains or live environments and are intentionally
left as optional, bounded integrations with graceful skips when the tool is
absent:

- Live NVD API polling (ingester accepts offline feed files).
- Live HTTP/2·HTTP/3 socket-level probing beyond curl's capabilities.
- Running the Foundry lab fixture requires an external `forge` binary.
- Live PyRIT/Garak/Promptfoo runs require those toolchains installed.

## Operating boundary

These modules never contact production systems, never restore authorization
gates, and preserve the existing uncensored execution semantics and
operational reliability controls (atomic writes, locking, UUID operation IDs,
bounded subprocesses, timeouts, artifact limits, disk guards).
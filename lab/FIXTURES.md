# BugWolf Lab Fixtures

All fixtures are **local and disposable**. They exist to exercise BugWolf's
deterministic core and domain adapters in an isolated research environment.
None of them reach production, third-party targets, real credentials, or
external networks.

> BugWolf uncensored mode intentionally does not enforce target authorization,
> scope membership, active-operation confirmation, or destructive-operation
> confirmation inside the plug-in. It is designed for isolated research
> environments where the operator provides the execution boundary externally.
> This mode must not be used as a safety boundary for production systems,
> third-party targets, or environments containing real credentials or data.

## Web / API

### `lab/vulnbank/`

Local in-process HTTP fixture (stdlib-only) used by the end-to-end and
live-feedback loop tests. Serves:

- REST endpoints (`/api/users`, `/api/users/1`, `/api/ingest`, `/api/gateway`);
- GraphQL (`/graphql`);
- auth/login surface (`/login`);
- schema discovery (`/openapi.json`, `/tech.json`).

Run:

```bash
python3 lab/vulnbank/server.py [port]
```

## Web3

Planned local fixtures (Foundry/Hardhat projects in a disposable container):

- oracle and stale-price variants;
- flash-loan-like atomic accounting;
- reentrancy and read-only reentrancy;
- upgrade and initialization mistakes;
- bridge message replay and domain confusion;
- ERC-4337-style validation/paymaster behavior;
- L2 message and withdrawal simulations;
- safe controls with equivalent interfaces.

The offline models in `tools/web3_protocol_fixture.py` and
`tools/web3_fixture_runner.py` already support these analyses without a chain.

## AI red teaming

Planned fixtures (local model/tool sandbox):

- pinned model or deterministic fake model (`tools/llm_sandbox.py`);
- RAG corpus with benign and poisoned documents;
- fake MCP servers and tool descriptions (`tools/mcp_fixture.py`);
- tools with observable but harmless state changes;
- memory store with session boundaries;
- multi-agent delegation graph.

## Adding a fixture

1. Keep it stdlib-only or fully disposable.
2. Serve on an ephemeral port (or in-memory models only).
3. Add a test that boots it and exercises one adapter end to end.
4. Never require real credentials, external egress, or production routes.
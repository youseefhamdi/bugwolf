<!-- bugwolf/docs — architecture
     SCHEMA: bugwolf-docs-architecture-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Architecture

BugWolf is a security-research AI company organized into **seven layers**.
Each layer has a strict contract with the layers above and below it, so a
component at layer N may only depend on layer N-1 (or below). This file
documents the layers, their files, and the audit-relevant decisions that
each one enforces.

## Layer 0 — Foundation

**Purpose.** The lowest layer: Python 3.10+ standard library only,
hash-chained append-only journal, capability registry digest, and
fail-closed gates. No third-party dependencies.

**Files.**
- `bugwolf/cli/main.py` — entry point that bootstraps the harness guard.
- `bugwolf/unified_state/journal.py` — SHA-256 hash-chained journal.
- `bugwolf/governance/capability_digest.py` — registry hash, CI drift check.
- `bugwolf/governance/scope.py` — deny-by-default scope gate.
- `bugwolf/governance/contracts.py` — typed contracts between modules.

**Contracts.**
- `STUB-SAFE`: any external service that is missing returns the literal
  string `"unavailable"` rather than raising.
- Append-only: there is no `delete`, `update`, or `clear` method on
  the state journal.
- Every state transition is recorded as a JSON entry whose SHA-256
  digest is computed as `sha256(prev_hash || canonical_json(entry))`.

**Audit-relevant decisions.**
- We refuse any dependency that pulls a transitive binary blob at
  install time (torch, selenium, playwright).
- We refuse any HTTP client that does not let us disable connection
  pooling without raising (`urllib3` is fine, `requests` is fine, but
  the policy says stdlib only — `urllib.request`).
- The capability registry digest is computed at every CLI start so
  that a build-time drift is caught before any probe.

## Layer 1 — Runtime

**Purpose.** LLM backends, playbooks, and bridges that translate a
declared workflow into actual probes.

**Files.**
- `bugwolf/runtime/` — LLM backend dispatch (anthropic, openai, ollama,
  stub).
- `bugwolf/playbooks/` — workflow YAMLs loaded into a runtime state
  machine.
- `bridge/` — language bridges to non-Python tooling (Go, Rust, shell).

**Contracts.**
- A playbook declares its target scope at the top; the runtime
  refuses to execute it without a matching scope entry.
- An LLM backend returns `LLMResult(text, confidence, model_id,
  tokens_used)`; nothing else is passed back to the caller.

**Audit-relevant decisions.**
- The runtime never speaks HTTP without a `StealthFetcher` wrapping
  the connection (UA pool rotation, proxy rotation, Tor fallback).
- The runtime never writes to disk except through the unified state
  journal.

```
+------------------+
|     Layer 6      |  CLI / reporting / state / docs
+------------------+
        ^
+------------------+
|     Layer 5      |  Rust core, distributed master/worker, bench
+------------------+
        ^
+------------------+
|     Layer 4      |  Fuzz / taint / semantic / regression / chain
+------------------+
        ^
+------------------+
|     Layer 3      |  Capability absorption (scanners, patterns)
+------------------+
        ^
+------------------+
|     Layer 2      |  Governance (scope, question gate, CVSS, ...)
+------------------+
        ^
+------------------+
|     Layer 1      |  Runtime (LLM, playbooks, bridges)
+------------------+
        ^
+------------------+
|     Layer 0      |  Foundation (stdlib, journal, digest, contracts)
+------------------+
```

## Layer 2 — Governance

**Purpose.** The decision layer: every probe, finding, and report is
vetted by the scope gate, the question gate, the CVSS scorer, the
OPSEC router, the capability digest, the evidence chain, and the
typed contracts.

See `docs/GOVERNANCE.md` for the full module-by-module reference.

**Files.**
- `bugwolf/governance/scope.py`
- `bugwolf/governance/question_gate.py`
- `bugwolf/governance/cvss.py`
- `bugwolf/governance/opsec.py`
- `bugwolf/governance/capability_digest.py`
- `bugwolf/governance/evidence.py`
- `bugwolf/governance/contracts.py`
- `bugwolf/governance/safety.py`
- `bugwolf/governance/execution_semantics.py`

**Contracts.**
- The scope gate denies by default: an empty `in_scope` list DENIES
  the request.
- The question gate (LLM-as-judge) requires seven questions answered
  with `recorded_evidence_block` per question; otherwise the finding
  is dropped.
- The evidence chain stores SHA-256 of each recorded block; tampering
  breaks the chain and the audit refuses the report.

## Layer 3 — Capability Absorption

**Purpose.** The pattern library: 68 scanners, 62 EVM patterns,
272 CIS controls, 70 methodology patterns, and 12 chain YAMLs.

**Files.**
- `bugwolf/scanners/web/`, `bugwolf/scanners/api/`, `bugwolf/scanners/auth/`,
  `bugwolf/scanners/cloud/`, `bugwolf/scanners/infra/`,
  `bugwolf/scanners/mobile/`, `bugwolf/scanners/llm/`,
  `bugwolf/scanners/web3/`, `bugwolf/scanners/orchestrator/`.
- `bugwolf/methodology/patterns/` — one subdirectory per bug class.
- `bugwolf/methodology/templates/` — Markdown templates for engagements.
- `bugwolf/methodology/chains/` — 12 chain YAMLs (H100 chains).

**Contracts.**
- A scanner declares its bug class and required evidence block; it
  cannot emit a finding without evidence.
- A pattern has a schema that is validated at load time; a malformed
  pattern is rejected before it can be invoked.

## Layer 4 — Zero-Day Research Core

**Purpose.** The engines that look for vulnerabilities that have
never been catalogued: fuzzing, taint tracking, semantic diff,
regression baselines, and chain synthesis.

**Files.**
- `bugwolf/fuzz/` — coverage-guided fuzz harness generator (libFuzzer,
  AFL++, Honggfuzz, Atheris, Boofuzz, Schemathesis, Foundry, Echidna,
  Medusa).
- `bugwolf/taint/` — taint-tracking engine for source-to-sink flows.
- `bugwolf/semantic/` — semantic diff and business-logic detector.
- `bugwolf/regression/` — regression baselines (chains, scanners,
  governance).
- `bugwolf/chain/` — pairwise chain builder and validator.

**Contracts.**
- The fuzz engine generates source code + build script + run script +
  corpus + crashes + manifest.json. It never runs the fuzz itself.
- The taint engine records source/sink pairs as fact entries in the
  unified state journal.
- The chain validator refuses a chain that does not close a typed
  contract end-to-end.

## Layer 5 — Production Hardening

**Purpose.** The performance-critical paths are written in Rust;
the distributed layer (Redis master + worker) scales horizontally;
the benchmark suite measures regression.

**Files.**
- `bugwolf-rs/` — Rust crate (`lib.rs`, `gate.rs`, `hash.rs`,
  `journal.rs`, `parsers.rs`, `request_engine.rs`, `scanner_core.rs`,
  `taint.rs`, `fuzzer.rs`, `destructive_gate.rs`, `skill_loader.rs`).
- `bugwolf/distributed/` — Redis client, master, worker, IPC bridge,
  load balancer, recovery, state, result dedup.
- `bugwolf/benchmarks/` — synthlab, adversarial, regression, scoring.

**Contracts.**
- The Rust core exposes a `cdylib` consumed by Python via
  `bugwolf/python_bindings/`.
- The distributed master pushes a task to a worker only after the
  scope gate has approved the target.
- The benchmark suite binds to `127.0.0.1` only; no public listener
  is ever started.

## Layer 6 — Integration

**Purpose.** The unified CLI, the reporting layer, the unified state
machine, and the docs.

**Files.**
- `bugwolf/cli/` — `main.py`, `dispatch.py`, `commands/`.
- `bugwolf/reporting/` — `main.py`, `types.py`, `aggregator.py`,
  `json_reporter.py`, `markdown_reporter.py`, `html_reporter.py`,
  `sarif_reporter.py`, `hackerone.py`, `bugcrowd.py`, `intigriti.py`,
  `immunefi.py`.
- `bugwolf/unified_state/` — `state.py`, `machine.py`, `merge.py`,
  `chain.py`, `facade.py`, `migrate.py`, `types.py`.
- `docs/` — Markdown documentation.

**Contracts.**
- Every CLI command goes through `tools/harness_guard.py` first.
- Every report emits a JSON, a Markdown, an HTML, and a SARIF
  variant; the JSON variant is the canonical one.
- Every state migration is reversible (`migrate.py` records the
  inverse step).

## Cross-layer guarantees

- **Fail-closed**: a missing dependency, an empty scope, an
  unparseable contract — all produce an error, never a default-pass.
- **STUB-SAFE**: any external service that is unreachable returns
  `"unavailable"`, never raises.
- **Hash-chained journal**: every state transition is recorded with
  its SHA-256 chain, so tampering is detectable.
- **Capability digest**: the registry of every scanner + chain +
  pattern + CIS control is hashed at CLI start; a build-time drift
  is caught before any probe.

## Where to read next

- Layer 2 deep dive: `docs/GOVERNANCE.md`
- Layer 3 patterns: `docs/METHODOLOGY.md`
- Layer 5 benchmarks: `docs/BENCHMARKS.md`
- Operator runbook: `docs/OPERATIONS.md`
- Security model: `docs/SECURITY.md`
- Second-brain (company model): `docs/COMPANY.md`, `MEMORY.md`,
  `LEARNINGS.md`, `decisions.md`
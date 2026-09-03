# BugWolf Operator Runbook

This runbook covers day-to-day operation of BugWolf in an **isolated research
lab**. BugWolf deliberately does not enforce authorization, scope membership,
or destructive-operation confirmation inside the plug-in; the operator is the
execution boundary. Read the operating boundary statement below before
running anything.

## Operating boundary

> BugWolf uncensored mode intentionally does not enforce target authorization,
> scope membership, active-operation confirmation, or destructive-operation
> confirmation inside the plug-in. It is designed for isolated research
> environments where the operator provides the execution boundary externally.
> This mode must not be used as a safety boundary for production systems,
> third-party targets, or environments containing real credentials or data.

Operators must:

1. Run BugWolf only inside an isolated lab (disposable VMs/containers, no
   production credentials, no external egress unless explicitly approved).
2. Explicitly scope every campaign target before starting it.
3. Review every candidate and chain report before acting on it.
4. Clean up lab state and artifacts after each campaign.

## Runtime Requirements

Verified environment:

| Component | Requirement |
|---|---|
| Python | 3.14 (stdlib-only core; no third-party runtime deps) |
| curl | optional — HTTP/1.1·HTTP/2 probing (`tools/http_protocol_runner.py`) |
| forge (Foundry) | optional — operator-supplied Foundry projects (graceful skip if absent) |
| slither / echidna / medusa / mythril / halmos | optional — Web3 tool runners (graceful skip if absent) |
| PyRIT / Garak / Promptfoo | optional — AI red-team runners (graceful skip if absent) |

All external tools are optional. When a tool is missing, the corresponding
runner reports availability and skips without failing the pipeline.

## State and Artifact Layout

| Path | Contents |
|---|---|
| `state/sessions/<target>/candidates.jsonl` | Research candidates (append-only, signature-deduped) |
| `state/sessions/<target>/findings.jsonl` | Legacy finding records (migrated to candidates) |
| `state/chains/<target>/cross-domain.json` | Cross-domain chain reports |
| `state/evidence/` | Captured request/response evidence |
| `exploits/<target>/` | Generated PoCs |
| `reports/` | Exported SARIF / JSON / Markdown reports |
| `logs/` | Structured JSON operation logs |

## Daily Operations

### 1. Verify the lab is healthy

```bash
python3 -m unittest discover -s tests -p 'test*.py'
```

### 2. Check the operator dashboard

```bash
python3 -m tools.operator_dashboard --root . --json
```

or

```bash
python3 -m tools.operator_dashboard --root .
```

The dashboard reports candidate counts by domain/status/severity, active vs
terminal candidates, novelty mix, cross-domain chains, and corrupt lines.

### 3. Query candidates

```bash
python3 -m tools.candidate_cli --domain web_api --status reproduced --limit 50
python3 -m tools.candidate_cli --bug-class bola --export-sarif reports/bola.sarif
```

### 4. Refresh the advisory catalog (optional, online mode)

```bash
python3 -m tools.nvd_ingester --fetch --days 30 --max-records 500 \
  --catalog state/advisories.json
```

The fetch uses a strict timeout and no retry loop; offline environments
simply get an error result and the catalog is untouched. Offline ingestion
from a mirrored feed file:

```bash
python3 -m tools.nvd_ingester --feed nvd_feed.json --catalog state/advisories.json
```

### 5. Run the end-to-end zero-day pipeline

```bash
python3 -m tools.zero_day_pipeline --observations observations.json \
  --advisories state/advisories.json --project-root .
```

The pipeline registers candidates from the domain adapters, runs novelty
classification, builds chains and lineage, and exports SARIF/JSON/Markdown
reports.

### 6. Run the orchestrated mission (scheduler + hunt lanes + lead protocol)

The mission runner drives the full graph: pre-flight gate -> recon ->
web/API hunt families (BOLA swarm, WAF-bypass matrix, FIN business-logic
matrix, fuzz, GraphQL) -> verify lane (independent replay) -> report.

```bash
python3 -m tools.runtime.mission_runner --mission-id bw-001 \
  --target https://operator-target.example \
  --paths "/api/users/1,/api/checkout,/api/admin/panel" \
  --accounts accounts.json --json
```

- `--paths` is operator-declared surface (recon output or intake). Empty
  means no probing — there are no shipped target defaults.
- `--accounts` (optional) is the A/B/C account matrix JSON:

```json
[
  {"label": "A", "username": "attacker", "token": "<paste from browser>",
   "identifiers": ["attacker", "1001"]},
  {"label": "B", "username": "victim", "password": "...",
   "login_path": "/login", "identifiers": ["victim", "1002"]},
  {"label": "C", "username": "admin", "token": "...", "identifiers": ["admin"]}
]
```

With accounts bound, identity surfaces (users/admin/account/profile/role)
run the three-way A/B/C differential and any boundary hole opens the
seven-technique auth-bypass swarm (R3 full-matrix accounting, winning
verified by independent replay). Session tokens are used in-memory only
and are redacted in all notes, leads, and reports. Money-flow surfaces
(checkout/payment/voucher/withdraw/…) auto-instantiate the FIN matrix;
TOCTOU confirmation runs through the single-window race engine (hard cap
30, one window, no retries — plan §2.5 safety ceiling).

## Missions, Persistent Modes & the Ladder (Phase 6)

Run a full mission (preflight -> lanes -> verify -> report):

```bash
python3 -m tools.runtime.mission_runner --mission-id bw-1 --target https://operator-target \
    --paths /api/users/1,/api/ingest --accounts accounts.json
```

**Persistent modes** (state machines over the task graph, `tools/runtime/modes.py`):
`research` | `verify` | `deep-dive` | `coverage` | `report`. Each has explicit entry
predicates (e.g. report refuses to run with open leads) and a JSONL journal at
`state/orchestrator/<mission>/modes.jsonl`. Stop/resume is replay-the-tail:
open leads re-dispatch FIRST (R6); completed deterministic work never re-runs (P5).

**Escalation ladder (T0-T4)** — every stalled lead walks it automatically in the
verify lane: full technique matrix (T1) -> research refresh recorded as an R4 ref
t whose derived techniques JOIN the required set (T2) -> deep-dive escalation (T3)
-> swarm pass@k over remaining techniques (T4) -> `BUDGET-EXHAUSTED` with every
attempt recorded, operator-visible. Terminal states are FINAL — a late replay can
never overwrite BUDGET-EXHAUSTED/PWNED with REFUTED.

**Plugin package** (`.claude-plugin/plugin.json`): 8 `/bugwolf-*` commands,
microsecond JSONL hooks (`hooks/`), and an optional MCP bridge
(`bridge/bugwolf-mcp.py`) exposing `bugwolf_status/plan/run/leads/mode` over
JSON-RPC stdio:

```bash
claude mcp add bugwolf -- python3 bridge/bugwolf-mcp.py
```

## Performance Dashboard & Gates (Phase 7)

Measure the plan-5.3 targets and write `state/perf/dashboard.json`:

```bash
python3 tools/perf.py --measure        # full dashboard
python3 tools/perf.py --gate           # regression gate (exit 1 on unmet)
python3 tools/perf.py --yield-mission <id>   # plan-5.4 yield metrics
```

Nine targets are measured offline and CI-gated (plan artifact < 5 s, worker
startup < 50 ms/lane, hook round-trip < 10 ms, transition durability < 1 s,
cold resume < 1 s, zero deterministic re-runs, >= 6 lanes, 100% OAST
attribution, zero duplicate dispatches). Live-campaign targets (dispatch
latency, context duplication, frontier-call reduction, escalation latency)
are listed NOT MEASURED with reasons — never silently dropped. P6
dedup-before-dispatch collapses duplicate task fingerprints at graph-build
time, so identical work is never dispatched twice.

## Evidence Review Workflow

For every candidate that reaches `reproduced` or later:

1. Open the candidate JSON: `state/sessions/<target>/candidates.jsonl` (or
   the per-candidate export in `reports/`).
2. Verify behavioral evidence — status codes alone are **not** sufficient;
   require content/behavioral matching between baseline and mutated runs.
3. Verify the payload lineage: how the payload evolved through mutations.
4. Verify reproduction notes: clean-state replay instructions.
5. Run the reproduction steps yourself in the lab before calling it confirmed.
6. Classify novelty against the local advisory catalog
   (`state/advisories.json`); `potentially_novel` only means "no local match",
   not "zero-day".

## Cleanup Procedures

Before destroying a lab VM or container:

```bash
# Remove all campaign state
rm -rf state/sessions state/chains state/evidence

# Remove generated PoCs and reports
rm -rf exploits reports

# Remove logs
rm -rf logs
```

For a full clean checkout, also remove `state/advisories.json` if you want a
fresh advisory catalog.

## Known Non-Fatal Warnings

- `ResourceWarning: Implicitly cleaning up <HTTPError 404/400/500/403>` —
  expected during fuzzing; HTTP error responses are intentionally exercised.
- `[!] Unknown format: rust` — PoC export only supports certain formats;
  non-fatal.
- Missing optional tools (`forge`, `slither`, etc.) produce skip messages,
  not failures.

## Incident / Anomaly Handling

If a candidate or chain report looks wrong:

1. Capture the operation IDs and evidence refs from the candidate record.
2. Correlate with `logs/` using the operation ID.
3. Re-run the reproduction steps from a clean state.
4. If the finding does not reproduce, transition the candidate to
   `rejected` or `inconclusive` with a note.
5. If evidence was corrupted, restore from the checksummed artifact or
   re-run the campaign step.

## Security Posture of the Tool Itself (product audit)

The plug-in is offensive tooling; its own hygiene is part of the product:

- **Credentials never touch disk.** `MissionSpec.accounts` passwords/tokens
  are redacted to `__redacted__` at the persistence boundary
  (`Scheduler.save`). A resumed mission treats redacted credentials as
  absent: the auth lane degrades to anon observations and discloses it in
  the bind notes — re-bind with a fresh `--accounts` file.
- **Race traffic validates TLS by default** (`RaceRequest.verify_tls=True`);
  opting out is an explicit operator decision per request.
- **The OAST listener binds loopback** by default. Point a remote target at
  it only via `BUGWOLF_OAST_PUBLIC_URL` (a tunnel/reverse proxy you own) —
  canary URLs advertise that public route, and attribution stays 100%.
- **Hook journals are allowlisted.** The stop/resume shim records only
  `mission_id / session_id / reason / trigger / source` — caller payloads
  cannot turn `state/orchestrator/<mission>/hooks.jsonl` into a dump.
- Session tokens live in memory only (`tools/runtime/accounts.py`); every
  token leaving that module for logs/reports is redacted.

## Operating Boundary Recap

- The **operator** is the authorization boundary: they declare the target,
  surfaces, and accounts; the plug-in ships no targets and no credentials.
- Pre-flight runs before any mission work and records its manifest;
  readiness (`python3 -m tools.readiness`) reports L1 with explicit
  warnings (authorization not enforced at the execution boundary, no
  complete SSRF guard, no subprocess sandbox) — read them before real-world
  use and run inside a scoped, monitored environment.
- Every finding is a hypothesis until an operator reproduces and reviews it.
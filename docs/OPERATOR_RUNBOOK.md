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

## Operating Boundary Recap

- No authorization gates exist inside the plug-in by design.
- The lab is the boundary: disposable, isolated, no real credentials.
- Every finding is a hypothesis until an operator reproduces and reviews it.
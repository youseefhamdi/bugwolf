# Web/API Discovery Core

The discovery core turns recon artifacts into a systematic, coverage-aware
search for novel vulnerabilities. It sits between the methodology maps/plans
and the authorization controller: it *structures* the target's own contract,
*generates* structure-aware differential mutations, and *schedules* them in
impact order — but it never performs HTTP itself.

Three modules, used in order:

1. `tools/surface_model.py` — build the structured surface.
2. `tools/mutator.py` — generate structure-aware mutation plans.
3. `tools/discovery_scheduler.py` — order by impact + coverage, run the
   observation loop, and record the next deterministic step.

## 1. Surface model

```bash
python3 tools/surface_model.py \
  --target example.com \
  --openapi openapi.json \
  --urls-file recon/example.com/urls.txt \
  --output recon/example.com/discovery/surface-model.json
```

Parses:

- OpenAPI 3.x and Swagger 2.0 (parameters, request bodies, required fields,
  enums, formats).
- GraphQL introspection (root fields as operations, arguments as typed
  parameters, enum values populated).
- Recon URL/parameter lists (query and path parameters).

It also infers two high-value structures automatically:

- **Version siblings** — operations whose paths differ only by version segment
  (`/v1/users/{id}` vs `/v2/users/{id}`), the classic "fixed one surface,
  forgot the sibling" divergence.
- **Workflow transitions** — per-resource step ordering from method + verb
  (`create → approve → cancel`), so the mutator can probe skip/repeat/reorder.
- **Vhost candidates** — internal subdomains of the target
  (`admin.example.com`, `api.example.com`, …) ranked by internal-looking label
  and grouped by resolved IP, feeding the host-confusion probes.

### Auto schema extraction from recon output

You do not have to hand-point at schema files. `tools/schema_extractor.py`
scans the recon artifacts (`urls.txt`, `live-hosts.txt`, `swagger.txt`,
`jsfiles.txt`, `js-endpoints.txt`, downloaded JS) for OpenAPI/Swagger and
GraphQL endpoints, plus schema JSON paths referenced inside JS bundles, then
builds the model automatically.

```bash
# Discover (offline) and build the model from recon/example.com/
python3 tools/schema_extractor.py --target example.com \
  --recon-dir recon/example.com --output recon/example.com/discovery/surface-model.json

# Or let the scheduler/mutator do it directly via --recon-dir
python3 tools/discovery_scheduler.py --target example.com \
  --recon-dir recon/example.com --output-dir recon/example.com/discovery
```

Any schema already downloaded under `recon/<target>/schemas/` is parsed
directly; otherwise the URL list provides a baseline. Downloading discovered
schemas and running GraphQL introspection is a separate gated live step:

```bash
python3 tools/schema_extractor.py --target example.com \
  --recon-dir recon/example.com --fetch --scope-file scope.json --confirm-active
```

The fetch passes every request through the execution controller and refuses to
run without a scope file and explicit active confirmation.

## 2. Structure-aware mutator

```bash
python3 tools/mutator.py \
  --target example.com \
  --openapi openapi.json \
  --output recon/example.com/discovery/mutations.jsonl
```

Each mutation changes exactly one variable. Kinds:

| Kind | What it probes |
|---|---|
| `boundary` | type/format-aware extremes (int overflow, empty/long/unicode strings, out-of-enum values) |
| `required_tamper` | omit a required field, or send `null` |
| `mass_assignment` | inject an undeclared field (`role`, `is_admin`, `paid`, …) into a write body |
| `pollution` | duplicate a query parameter (`id=1&id=2`) |
| `injection` | minimal SQLi/XSS/SSTI/path-traversal/command/redirect probes on sink-named parameters only |
| `blind_sqli` | time-based blind SQLi detection *plans* (DB-agnostic `SLEEP`/`PG_SLEEP`/`WAITFOR DELAY`) on pagination/sort parameters (`offset`, `page`, `limit`, `sort`, `order`, `filter`) |
| `state` | skip / repeat / reorder a workflow step |
| `sibling_differential` | replay identical input against a version sibling and diff |
| `header_trust` | forged forwarded/trust header (IP, host, scheme, path, method) per origin |

### Sitemap + pagination surface

A classic injection surface hides in sitemap and pagination endpoints
(`/sitemap.xml?offset=1`). The surface model ensures a
`GET /sitemap.xml` operation carrying `offset`, `page`, `limit`, `sort`,
`order`, and `filter` parameters (typed integer) even when recon recorded a
bare sitemap URL. The mutator then plans `blind_sqli` time-based detection
for those parameters. The sleep strings are detection *plans* — they are never
sent by the mutator; live execution still requires the gated controller.

Every mutation carries a `risk` class (`read`/`active`/`state_change`/
`destructive`). The mutator only *plans* — the strings above are never sent by
this module.

## 3. Discovery scheduler (offline plan + coverage)

```bash
python3 tools/discovery_scheduler.py \
  --target example.com \
  --openapi openapi.json \
  --urls-file recon/example.com/urls.txt \
  --output-dir recon/example.com/discovery \
  --budget 200 --min-focus medium
```

Writes `surface-model.json`, `coverage.json`, and a ranked `plan.jsonl`.
Ranking is: impact-focus tier (critical first) → untried first → mutation kind
(divergence/state before boundary/injection).

### ART4SQLi payload-aware scheduling (`--art`)

The `--art` flag switches budget allocation to the ART4SQLi selection method
(Zhang, Zhang, Wang, Zhao, Zhang — *ART4SQLi: The ART of SQL Injection
Vulnerability Discovery*, IEEE Trans. Reliability). ART4SQLi is adaptive
random testing applied to the *payload* input space: effective payloads
cluster together in token space, so each next probe is chosen to be as far as
possible from everything already evaluated, maximizing the chance of landing
inside the cluster within a limited budget (~26% fewer attempts than random
in the paper's benchmarks).

```bash
python3 tools/discovery_scheduler.py --target example.com \
  --recon-dir recon/example.com --output-dir recon/example.com/discovery \
  --budget 200 --art --art-fixed-size 10
```

`tools/art_selector.py` implements the three steps of the paper:

1. **Tokenization (§III-C1)** — SQLi payload strings decompose into grammar
   tokens: quotes/encodings (`%27`), the whitespace-comment tactic (`/**/`),
   block/line/hash comments, SQL keywords and functions, operators, and
   normalized literals (`num`, `hex`, `id`).
2. **TF-IDF vectors (§III-C2, eq. 2)** — a payload's vector is
   `log(F_i + 1) × log(k / N_i)` (token frequency × inverse document
   frequency) over the whole pool, L2-normalized.
3. **Distance + FSCS selection (§III-B/C3, eq. 3, Alg. 1+2)** — distance is
   `1 / cosine(v_p, v_q)` in `[1, +∞)` (1 = identical, ∞ = orthogonal); each
   round draws a fixed-size candidate set (default 10, the paper's suggested
   value; `--art-fixed-size 0` = max-min over all candidates) and picks the
   candidate farthest from the evaluated set. The paper's RNG is replaced by
   deterministic `seed`-ed candidate-set draws (`mutation_id` hashes), so
   plans are reproducible.

Payload-bearing mutations (`injection` / `blind_sqli`) are compared in token
space; all other kinds fall back to the structural feature vector (kind,
method, bug class, risk, parameter/path buckets). The mutator's SQLi pool now
covers the paper's five payload classes — boolean-based blind, error-based,
union query, stacked queries, time-based blind — so the token space has real
spread to work with. `art-report.json` records the diversity score, fixed
size, payload vocabulary size, and how many selected mutations carry
payloads; `f_measure()` in `art_selector.py` reproduces the paper's F-measure
metric for comparing selection strategies.

## Live execution loop

The scheduler accepts a transport callable that executes one mutation and
returns an oracle-validated `ObservationRecord`. The transport is responsible
for authorization — it must pass every request through the execution
controller with the required scope and `--confirm-active` /
`--confirm-destructive` confirmations.

```python
from tools.discovery_scheduler import DiscoveryScheduler, CoverageTracker
from tools.surface_model import load_surface

model = load_surface(target="example.com", openapi_file="openapi.json")
scheduler = DiscoveryScheduler("example.com")
coverage = CoverageTracker()

# transport(mutation) -> ObservationRecord, built on hunt.py's
# curl_fetch_observation + the ActiveExecutionController + OracleValidator.
summary = scheduler.run(scheduler.allocate(model, coverage, 50), transport, coverage)
```

The loop is deterministic:

- `SIGNAL` → coverage marked observed; `on_signal` can register a lead in
  `leads.py` with the trigger/impact two-half framing.
- `UNKNOWN` + follow-up → the scheduler emits the oracle's `FollowUpStep` as
  the next deterministic experiment (one-variable discipline preserved).
- `REFUTED` / `ERROR` → coverage marked, nothing further.

Value-level anti-repeat lives in the lead ledger (`next_mutation()`), while the
scheduler's coverage tracks the semantic `(operation × variable × kind)` space
so budget is allocated to untested high-focus surface.

## Live sibling-differential runner

`tools/differential_runner.py` replays the identical request against each
paired surface (v1/v2, REST/GraphQL, web/mobile) and scores live divergence —
the executor for the mutator's `sibling_differential` plans and the live
counterpart of the static `differential.py` detector.

```bash
# Offline: emit the pair plan (no network)
python3 tools/differential_runner.py --target example.com \
  --recon-dir recon/example.com --json

# Live: replay pairs through the gated controller and score divergence
python3 tools/differential_runner.py --target example.com \
  --recon-dir recon/example.com --scope-file scope.json --confirm-active --json
```

Scoring reuses the oracle's `compute_metrics` (status, body similarity,
headers, timing, redirects): status (0.25) and body (0.35) changes are
materials; headers/timing/redirects contribute but never trigger divergence on
their own. A diverged pair is reported as sibling drift with the weaker surface
named as the lead. The runner never performs HTTP itself — it takes a
`transport` callable (hunt.py's `curl_fetch_observation` behind the execution
controller), so tests inject a fake transport.

## Header-trust / proxy-trust analysis

A large, high-yield bug class lives in *forwarded/trust headers*: when a proxy,
CDN, or app layer trusts a client-supplied header, an attacker can pretend to
be a trusted peer and unlock IP allowlists, reach internal-only hosts, confuse
virtual-host routing, override scheme/method, or rewrite the request path
(which can escalate to SSRF/RCE).

`tools/header_trust.py` is the canonical taxonomy + probe planner + gated live
runner for this surface:

```bash
# Offline: emit the probe plan (no network)
python3 tools/header_trust.py --target example.com \
  --recon-dir recon/example.com --json

# Or write the plan to a file (also used automatically by recon_engine.sh)
python3 tools/header_trust.py --target example.com \
  --recon-dir recon/example.com --output recon/example.com/discovery/header-trust-plan.json

# Live: baseline-vs-forged replay through the gated controller
python3 tools/header_trust.py --target example.com \
  --recon-dir recon/example.com --scope-file scope.json --confirm-active --json
```

`recon_engine.sh` runs the offline planner automatically after schema
extraction + discovery, writing
`recon/<target>/discovery/header-trust-plan.json`. Live replay is *not*
automated — it still requires `--confirm-active` + a scope file.

Host-confusion probes target the application's *own* internal vhost candidates:
`schema_extractor.build_surface` reads `subs.txt`, `resolved.txt`, and
`live-hosts.txt`, groups subdomains by resolved IP, and ranks internal-looking
hosts first. `header_trust.probes_from_model` then replays those hostnames as
`Host` / `X-Forwarded-Host` / `X-Host` / … values against the live origin,
alongside the generic `localhost`/`internal`/`backend` list.

The taxonomy is grouped by bug class and expands to concrete probes per
origin host and representative path:

| Group | Example headers | Forged value classes |
|---|---|---|
| IP trust / allowlist bypass | `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Forwarded` | `127.0.0.1`, `::1`, `10.0.0.1`, `169.254.169.254` |
| Host / vhost confusion | `X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, `Host` | `localhost`, `internal`, `backend`, `admin` |
| Scheme / port override | `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `Front-End-Https`, `X-Forwarded-Port` | `https`/`http`, `on`, `443` |
| Path / URI rewrite (SSRF→RCE) | `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`, `X-Accel-Redirect` | `/admin`, `/internal`, `/actuator` |
| Method override | `X-HTTP-Method-Override`, `X-Method-Override` | `POST`, `PUT`, `DELETE` |

Each probe is replayed **baseline vs forged** and classified by the shared
oracle. The oracle owns the authoritative state (conservative: status
divergence is UNKNOWN pending follow-up); the runner additionally surfaces the
characteristic **denied → allowed** pattern as a `trust_signal` hypothesis to
validate. The mutator emits `header_trust` mutations keyed to each origin host
so the discovery scheduler's coverage loop steers budget across this surface
like any other. Forged values are trust *hypotheses* — never executed payloads,
and live replay runs only behind `--confirm-active` + a scope file.

## Safety boundary

- All generation is offline and deterministic.
- No HTTP, no payload transmission, no OAST/Collaborator, no file writes to a
  host, no command execution.
- Live execution requires an authorized scope and runs only through the
  execution controller's read/active/state-change/destructive gates.
- Injection-class mutations are plans; they are not auto-fired.
- Findings are candidates requiring reproducible trigger evidence, bounded
  impact, and human review — never unverified zero-day claims.

## Smart-contract extension

The same coverage loop drives contract state-space exploration through
`tools/contract_discovery.py`. It generalizes
`zero_day_tracks.SmartContractTrack.explore_sequences` into a coverage-aware,
scheduler-driven search.

```bash
python3 tools/contract_discovery.py --spec contract-spec.json \
  --output-dir contract-discovery --budget 200
```

The spec is JSON:

```json
{
  "target": "Token",
  "roles": ["attacker", "user", "owner"],
  "functions": [
    {"name": "deposit",  "args": [{"name": "amount", "type": "uint256"}], "payable": true},
    {"name": "withdraw", "args": [{"name": "amount", "type": "uint256"}], "roles": ["user"]},
    {"name": "setOwner", "args": [{"name": "newOwner", "type": "address"}], "roles": ["owner"]}
  ],
  "invariants": [
    {"name": "solvency", "description": "sum(balances) == totalSupply"}
  ]
}
```

Mutation plans: `sequence` (bounded BFS), `boundary` (per-argument type
extremes), `role` (caller), and `reentrancy` (self re-entry). Ranking reuses
the impact router: `withdraw`/`transfer`/`mint`/`setOwner` surfaces rank
critical first.

Execution is an in-memory, deterministic simulation:

```python
from tools.contract_discovery import (
    ContractExecutor, ContractDiscoveryScheduler)
from tools.discovery_scheduler import CoverageTracker

# transitions: name -> fn(state, call) -> state
# invariants:   name -> predicate(state) -> bool
executor = ContractExecutor(initial_state, transitions, invariants)
scheduler = ContractDiscoveryScheduler(model, executor)
coverage = CoverageTracker()            # the SAME tracker as the Web core
summary = scheduler.run(scheduler.allocate(coverage, 200), coverage)
```

`run()` records invariant violations into the shared coverage tracker and
automatically minimizes each violating sequence to a minimal reproducer (the
contract analogue of the oracle follow-up step). No chain, fork, transaction,
or model call happens here — transition and invariant predicates are supplied
by the caller (e.g. from a fork-based reproduction harness).

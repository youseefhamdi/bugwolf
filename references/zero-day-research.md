# BugWolf Potentially-Novel Research Track

BugWolf can help discover **potentially novel vulnerabilities**. It must not claim that a candidate is a zero-day until independent research, reproducibility, impact validation, and human review are complete.

## Environment preflight

Before starting discovery, ask whether the agent is running on a local workstation, VPS, container/VM, or unknown base, and whether a passive local OS/resource inventory is permitted. Use `tools/environment_profile.py` to record the answer. Do not infer hosting location or authorization from network identity.

```bash
python3 tools/environment_profile.py --location <local|vps|container_vm|unknown> --json
python3 tools/environment_profile.py --location <location> --scan-os --confirm-os-scan --json
```

The second command is optional and requires explicit operator confirmation. It records only basic platform/resource information and an allowlisted tool inventory; it performs no network or filesystem reconnaissance.

## Research lifecycle

```text
HYPOTHESIS
  ↓ controlled observation
OBSERVED
  ↓ replay with the same fixture
REPRODUCIBLE
  ↓ bounded victim-impact proof
IMPACT_BOUNDED
  ↓ local/public deduplication
NOVELTY_PENDING
  ↓ reviewer approval
HUMAN_REVIEW → CONFIRMED → DISCLOSED
                 ├→ DUPLICATE
                 └→ REJECTED
```

A candidate without a trigger trace, impact trace, and evidence bundle stays a hypothesis or open lead.

## Core tools

| Tool | Purpose |
|---|---|
| `tools/zero_day.py` | Orchestrate local candidate generation and persistence |
| `tools/research_model.py` | Candidate lifecycle, evidence references, mutation history |
| `tools/execution_controller.py` | Scope, confirmation, rate, request, and time budgets |
| `tools/evidence.py` | Redacted replay fixtures and hash-linked evidence |
| `tools/novelty.py` | Local/near-duplicate comparison and parallel research adapters |
| `tools/triage.py` | Human-review and disclosure gates |
| `tools/zero_day_tracks.py` | Web/API, contract, cloud/CI, LLM/agentic, and mobile adapters |
| `tools/methodology_playbook.py` | Offline workflow plans, signal-to-impact tasks, and confirmation-only tool plans |

## 2026 workflow methodology

The playbook encodes the reviewed articles' useful discipline: tools produce signals, human validation establishes the trigger, and impact must be demonstrated separately. It generates bounded plans for:

- skipped, repeated, reordered, and tampered workflow steps;
- role, ownership, hidden-feature, tenant, and server-side validation boundaries;
- payment/subscription state, one-time token reuse, idempotency, and file access;
- IDOR, SQL-injection, XSS, scanner, discovery, and response-differential validation tasks.

```bash
python3 tools/methodology_playbook.py \\
  --target staging.example.com \\
  --scope-file scope.json \\
  --urls-file recon/staging.example.com/urls.txt \\
  --signals-file recon/staging.example.com/nuclei.txt \\
  --output-dir recon/staging.example.com/methodology
```

This command is offline. It writes `workflow-plans.jsonl`, `validation-tasks.jsonl`, and `tool-plans.jsonl`; it does not run ffuf, nuclei, SQLMap, or XSStrike. The generated SQLMap plan deliberately excludes `--dbs`, `--tables`, and `--dump`, and all tool plans require a later explicit active review.

## Local candidate generation

```bash
python3 tools/zero_day.py \
  --target local-project \
  --surface cloud_cicd \
  --path .github/workflows/build.yml \
  --json
```

Supported surfaces:

- `web_api`
- `smart_contract`
- `cloud_cicd`
- `llm_agentic`
- `mobile_binary`

For `web_api`, the adapter seeds zero-day-class hypotheses from static
artifacts (source, config, docs, request bundles):

- GraphQL global node-id enumeration — `gid://…` passed to `node(id:)`
  resolves objects without field-level filters; composite ids can leak
  objects across visibility boundaries (HackerOne #1618347);
- cache/page-key path traversal — a cache key derived from the request path
  flowing into a filesystem path can escape the cache directory and write or
  overwrite files (CVE-2026-18051 class, unauthenticated file write);
- daemon/notification input reaching a shell sink (CVE-2026-73570 class,
  unauthenticated RCE via SNMP notification handling);
- client-supplied account headers (`X-Account-Id`), id-bearing cookies
  (`userid=…; tenant=…`), JWT claim references (`"sub": 42`), and
  predictable file/upload references.

The command performs local analysis only. It does not send requests, submit transactions, call model providers, validate credentials, or exploit a device.

## Sequential research loop

By default the orchestrator is single-pass. With `--sequential`, zero-day
research runs **round over round**: round 0 registers the input hypotheses;
each later round takes the top ranked candidates from the previous round's
kept output, runs the injected research adapters (offline when none are
injected), derives bounded second-order hypotheses per bug class, and
registers them through the same novelty dedup — so only genuinely new
candidates survive into the next round.

```bash
python3 tools/zero_day.py --target T --surface web_api --path bundle.txt \
  --sequential --rounds 3 --per-round 2 --json
```

```json
{
  "rounds": [
    {"round": 0, "kept": 5},
    {"round": 1, "sources": 2, "derived": 5, "kept": 5},
    {"round": 2, "sources": 2, "derived": 4, "kept": 4},
    {"round": 3, "sources": 2, "derived": 2, "kept": 2}
  ],
  "ordering": {"sequential": true, "rounds_count": 4, ...}
}
```

Each derivation is a deterministic template keyed by bug class (composite-gid
axis replay, encoded-cache-key traversal, shell metacharacter variants, tool
argument overreach, PendingIntent hijack, …). The derived hypothesis carries
its parent's candidate id, and a `derivation_lineage` skips templates already
explored on that chain — so a round explores *new angles* instead of
re-stating the previous round, and the per-round derived counts shrink as
lineages converge (5 → 4 → 2 above). Research sources from injected adapters
attach to derived candidates as `research_sources`. Bounds: `--rounds`
(default 3), `--per-round` (default 4), and `--budget` (default 64) cap the
total kept pool; the loop also stops when a round yields nothing new. The
final candidate list is still pre-ranked for validation (`--spread`
`--top-k` apply as usual).

The sequential loop is deterministic and offline; research adapters are
responsible for their own network authorization, and no derived hypothesis
bypasses the normal novelty/human-review gates.

## Chained hypothesis synthesis

Single-class hypotheses are usually a known class — the novelty lives at the
**boundaries between classes**. `tools/zero_day_tracks.py` carries a causality
table (`CHAIN_RULES`) that pairs an input-class candidate with a
sink/impact-class candidate and emits a chained hypothesis with a chain
severity and a validation template:

- cache-key path control → write sink → **arbitrary file write** (CVE-2026-18051 class)
- daemon/notification input → command sink → **unauthenticated command execution** (CVE-2026-73570 class)
- gid enumeration + claim/header/cookie identity → **cross-tenant object disclosure**
- untrusted checkout → remote script pipe → **pipeline code execution**
- hidden context + tool authorization → **prompt-injection tool abuse**
- exported component + WebView bridge, mutable PendingIntent chains, contract
  invariant violation + trace differential, and more (~24 rules)

```bash
# Standalone: synthesize chains from the registered pool
python3 tools/zero_day.py --target T --surface web_api --path A --chains --json
# Sequential mode synthesizes chains automatically after rounds converge
python3 tools/zero_day.py --target T --surface web_api --path A --sequential --json
```

Chains carry `chain_components` (the two component candidate ids), the rule,
and the chain severity — the criticals come from chains. They are bounded
(`--max-chains`, default 32), deterministic (highest-severity source + sink
per rule), and registered through the same novelty dedup, so re-synthesis of
the same pair never multiplies. `ordering.chains` reports the count in JSON
output.

## Cache-key path traversal track

`tools/cache_traversal.py` turns the W3 Total Cache page-cache-key flaw class
(CVE-2026-18051 — unauthenticated arbitrary file write via path traversal in
the cache key) into a discovery track:

```bash
# Offline: compute which crafted request paths escape the cache root
python3 tools/cache_traversal.py --target example.com \
  --spec w3tc-page-cache \
  --urls-file recon/example.com/urls.txt \
  --output-dir recon/example.com/cache-traversal

# Gated lab replay: send escaping probes, verify with marker files
python3 tools/cache_traversal.py --target example.com \
  --spec w3tc-page-cache --urls-file recon/example.com/urls.txt \
  --base-url https://lab.example.com \
  --scope-file scope.json --confirm-active --json
```

The model covers cache-key construction (raw path, path-as-directories, hashed
keys), sanitization order-of-operations (a filter stripping literal `..` is
bypassed by `%2e%2e%2f` because decoding happens at key-build time), multiple
URL-decode passes (double-encoded families), and Windows-style roots.
`--list-specs` shows the canonical constructions; a JSON spec file models a
target's exact key format.

Lab safety: every probe carries a unique `bwtr-<hash>.html` marker filename,
verification requests only the marker's resolved location and a never-written
control path, and escape above the web root is left as a read-only lab
filesystem check. The track never overwrites `.htaccess` or any existing file
— it proves directory escape with its own artifact, then stops.

## GraphQL introspection + gid:// harvesting adapter

`tools/graphql_gid.py` builds the candidate list for the two-account
validation flow on Relay-style GraphQL deployments. It does two offline jobs:

1. **Introspection analysis.** Given an introspection result (e.g. produced
   by `tools/schema_extractor.py --fetch` under the gated controller), it
   finds `node`/`nodes` resolvers and the object types that carry global ids
   (Node-interface implementors and `id: ID!` carriers).
2. **gid:// harvesting.** It extracts global-id references *already present*
   in the target's own material (JS bundles, saved queries, schema docs) —
   it never generates or enumerates ids. Output ids are redacted (only a
   SHA-256 hash references the raw value), and composite ids
   (`gid://app/ClassA::TypeB/group-id-object-id`, the HackerOne #1618347
   pattern) are flagged as multi-axis ownership.

```bash
python3 tools/graphql_gid.py --target example.com \
  --introspection recon/example.com/introspection.json \
  --artifacts recon/example.com/js recon/example.com/queries.txt \
  --output-dir recon/example.com/graphql-gid --json
```

Each high/medium candidate becomes a read-only two-account validation plan:
Account A creates one disposable fixture and records its gid (the allowed
control); Account B replays **A's owned gid** through `node(id:)` /
`nodes(ids:)` and every field is compared against the control. Composite gids
are replayed per numeric component. Prohibited: sequential/bulk `node(id:)`
enumeration, reuse of gids harvested from other users' artifacts, reading
real private objects' titles/scope, and any state-changing mutation through
gids.

## Authorized active validation

Create a scope file that explicitly identifies the approved target. The scope file is an operator-provided authorization record; `authorized: true` is not a cryptographic proof of legal permission.

```json
{
  "authorized": true,
  "in_scope_domains": ["staging.example.com"],
  "in_scope_wildcards": ["*.staging.example.com"],
  "out_of_scope_domains": ["production.example.com"]
}
```

Use the execution controller for every live operation:

```python
from tools.execution_controller import (
    ActionClass, ActiveExecutionController, ExecutionPolicy,
)

policy = ExecutionPolicy(
    target="staging.example.com",
    scope_file="scope.json",
    allow_active=True,
    confirm_active=True,
    allowed_actions={ActionClass.READ, ActionClass.ACTIVE},
    max_requests=100,
    min_interval_seconds=0.2,
)
controller = ActiveExecutionController(policy)
result, receipt = controller.run(
    ActionClass.ACTIVE,
    "https://staging.example.com/api/test",
    lambda: perform_one_bounded_request(),
)
```

State-changing and destructive actions require separate confirmation. Use test accounts, staging fixtures, explicit rollback instructions, and bounded proof-of-impact. Never use a candidate's novelty as a reason to bypass safety controls.

## Novelty workflow

Run local deduplication first. Novelty assessment is **payload-aware**: when a
candidate carries a concrete trigger value (in `metadata["payload"]` or
`metadata["mutated"]`), its ART4SQLi grammar tokens join the stable
fingerprint, and pairwise near-duplicate checks use token-frequency cosine
over the same token space — two candidates shipping the identical trigger are
`exact_duplicate` even when their hypotheses are worded differently, and
near-identical triggers surface as `likely_variant`. Then run independent
research adapters in parallel for:

1. Existing local candidates and prior session findings
2. Program policy and known-issue exclusions
3. Public disclosures, CVEs, and vendor advisories
4. Similar implementation variants and sibling surfaces

Research adapters must return structured results and preserve source references. A failed search is `research_incomplete`, not evidence that a candidate is novel.

## Validation prioritization

`ZeroDayResearchEngine.prioritize` orders candidates for validation:
potentially-novel and higher-severity candidates first (then confidence,
then recency). With `spread=True`, payload-bearing candidates are additionally
ordered by ART4SQLi farthest-first selection over their token space, so a
bounded validation budget samples distinct trigger regions instead of
re-testing near-duplicate payloads (the rare-cluster intuition: effective
bugs cluster in token space, so spreading maximizes the chance of landing in
one). Non-payload candidates follow in the same ranking.

The CLI wires this ranking into its output — `--json` is **pre-ranked for
validation**: `python3 tools/zero_day.py --target T --surface web_api --path A
--spread --top-k 5 --json` emits candidates in validation order with a
1-based `rank` on each, and an `ordering` block recording the mode
(`novelty_severity` or `novelty_severity_spread`), the `top_k` budget, and
`total_generated`. `--top-k` bounds the emitted validation budget without
dropping candidates from the store; `total_generated` keeps the full count
visible. Output schema is `bugwolf-zero-day-output-v2`.

## Evidence requirements

Every candidate intended for review should have:

- Controlled request/response or execution trace
- Candidate and control roles
- One-variable mutation record
- Reproduction steps or deterministic replay fixture
- Bounded impact statement in victim terms
- Redacted secrets and tokens
- Hash-linked evidence references

The evidence store masks authorization, cookie, API-key, secret, password, and private-key values before persistence.

For the additional defensive and asset tracks, see [`references/defensive-intelligence.md`](defensive-intelligence.md). Those tracks remain offline-only and do not turn article claims, provider exports, or CVE references into confirmed findings.

## Review and disclosure

Only a candidate in `HUMAN_REVIEW` may be approved. Only a `CONFIRMED` candidate can produce a disclosure report. Reports should say **potentially novel** unless independent novelty review supports stronger language. Do not disclose secrets, private customer data, destructive payloads, or unreviewed exploit automation.

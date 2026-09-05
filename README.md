  
# BugWolf

```
██████╗ ██╗   ██╗ ██████╗ ██╗    ██╗ ██████╗ ██╗      ███████╗
██╔══██╗██║   ██║██╔════╝ ██║    ██║██╔═══██╗██║      ██╔════╝
██████╔╝██║   ██║██║  ███╗██║ █╗ ██║██║   ██║██║      █████╗
██╔══██╗██║   ██║██║   ██║██║███╗██║██║   ██║██║      ██╔══╝
██████╔╝╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╔╝███████╗██║
╚═════╝  ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝

██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

> All-round authorized security-research skill for Claude Code and Freebuff — parallelized agents for smart contract audits (EVM, Move, Solana, TRON), web/API security, local tooling orchestration, and submission-ready reports for HackerOne, Bugcrowd, Intigriti & Immunefi.

> **AI Pentesting Tool:** Run isolated, cloud-hosted pentesting sandboxes at **[bugwolf.xyz](https://bugwolf.xyz)** — your AI key, your Firecracker microVM, your report. Pipeline: recon → hunt → triage → H1-ready report. AI slop gets you rate-limited; BugWolf gets you paid.

> **New in v1.24.0 — the harness learns (integration plan, Phases A–F):** post-mission **instincts** mine existing ledgers into provenance-carrying facts that weight dispatch and ride the cockpit (≥2 occurrences, contradiction-halving, TTL); a **noise filter** holds platform-rejected findings with advisory reasons (impact always outranks the denylist); a **head-to-head harness** with deterministic judges publishes cost beside pass rate (the governed prober matches the 8x-spray baseline at 1/8th the sends); **injection canaries** prove target content is data-with-provenance, never instruction (forged instructions become recorded facts, bounded confidence penalty); a **default-off intel lane** (Agent-Reach channel architecture, credential-free, transparency-documented) feeds U1/U2 with provenance-tagged external facts; and **antibot honesty** keeps challenge boilerplate out of the business-lens model. Full rationale: [INTEGRATION_PLAN.md](docs/INTEGRATION_PLAN.md). Plus v1.23.0's corpus⇄U-layer regression, v1.22.x's hooks and H2.CL scoring, v1.21.0's capture→replay, v1.20.0's HTTP/2 layer, and the Understanding Layer beneath. See [CHANGELOG.md](CHANGELOG.md).
>
> **v1.23.0 — the corpus feeds on the Understanding Layer:** every scored case can declare the U-stages that must FEED it (`"u_stages": ["U4", "U5"]`); a regression bridge turns those declarations into executable checks over a live mini-mission — declared-stage artifacts, fact-level support per class (idor → object inventory, mass-assignment → privilege fields, business-logic → workflows), absence facts for negative controls — and a vanished model fact fails the gate like a missed finding. `enable_u_regression=True` scores it; hermetic runs stay honest.
>
> **v1.22.1 — H2.CL joins the scoring set:** the benchmark corpus now includes the H2.CL desync as a **lab-backed case pair** — the poisoned victim (expected finding) and the safe-front-end negative control, differing only in the front-end's desync switch, so the vulnerability itself is the scored variable. Evidence = the victim-observed smuggled body, never a bare status. Hermetic CI runs skip lab cases with a recorded reason; `enable_lab=True` scores them live (9 TP / 0 FP / 0 FN, gate PASS).
>
> **v1.22.0 — hooks complete, the harness remembers:** every prompt now carries mission context and a **target-model staleness warning** (3.2); every HTTP-ish tool output auto-captures into a hash-chained evidence ledger with `replay_key` (3.3); session start renders the full **cockpit** — scope, sandbox, leads, mode, and model freshness (3.4). The last master-plan parity gap is closed. Plus v1.21.0's capture→replay loop (mitmproxy addon → byte-exact replay → drift facts), v1.20.0's HTTP/2 pseudo-layer (the **H2.CL desync** demonstrated end-to-end), v1.19.0's predicted chains, v1.18.0's model-slice dispatch, v1.17.0's Understanding Layer pipeline (U1→U9, `/bugwolf-understand`), and the raw-socket replay + browser-confirmed verdicts underneath. See [CHANGELOG.md](CHANGELOG.md).
>
> **v1.21.0 — the capture→replay loop:** capture the target's real traffic through mitmproxy (`-s tools/runtime/capture_addon.py`), replay it byte-exact through the governed engine, and read the **drift** — status/body movement between two identical sends is a behavioral lead (cache variance, session carry-over), recorded as fact. The capture file never widens scope: out-of-scope records are skipped with a counted fact, and an explicitly-bound mission gate refuses rebinding. Plus v1.20.0's HTTP/2 pseudo-layer (HPACK + H2 framing, the **H2.CL desync** demonstrated end-to-end, safe-mode control proving the desync switch genuinely opt-in), v1.19.0's predicted chains (U7 capability × U8 assumption → ranked dispatch **before any probing**), v1.18.0's model-slice dispatch, v1.17.0's Understanding Layer pipeline (U1→U9, hash-chained, `/bugwolf-understand`), v1.16.0's opsec hardening, and the raw-socket replay + browser-confirmed verdicts underneath. See [CHANGELOG.md](CHANGELOG.md).
>
> **v1.20.0 — the HTTP/2 pseudo-layer, the last desync class:** byte-level HPACK (RFC 7541, no-Huffman by doctrine + a non-conformant mode that poisons stateful peer decoders) and H2 framing (RFC 7540) join the replay engine. The **H2.CL desync** is demonstrated end-to-end on the live stub: an attacker's TE-carrying H2 request poisons the pooled backend connection and the next victim's stream returns the internal-gateway admin-token response — a body their route can never produce. The safe-mode control proves the desync switch is genuinely opt-in (it caught the first draft forwarding TE verbatim — the exact real-world bug). Plus v1.19.0's predicted chains (U7 capability × U8 assumption → ranked dispatch **before any probing**), v1.18.0's model-slice dispatch, v1.17.0's Understanding Layer pipeline (U1→U9, hash-chained, `/bugwolf-understand`), v1.16.0's opsec hardening, and the raw-socket replay + browser-confirmed verdicts underneath. See [CHANGELOG.md](CHANGELOG.md).
>
> **v1.3.0 — boundary-hardened orchestrator:** the Phase 0–8 plan is complete — operator scope gate (deny-by-default, enforced at every network choke point), universal subprocess sandbox with a one-command kill switch, OAST public tunnel so SSRF leads close on attributed callbacks from REMOTE targets, auth A/B/C + FIN business-logic + contract/cloud/LLM lanes, all 13 §5.3 performance targets measured, and readiness level **L2 (clean-checkout reproducible)** with zero warnings. See [CHANGELOG.md](CHANGELOG.md).

> **Also in this series:** v1.0.0 brought the LLM / Agentic AI security track (OWASP GenAI LLM Top 10 2026 + Agentic Top 10 ASI01–ASI10), RAG & embedding attacks, MCP security, mobile + cloud-native vectors, and a zero-day LLM attack-surface detector.

> **Operating mode:** Production campaigns run only from an operator-supplied target specification and attestation. The operator defines the exact boundary and Rules of Engagement; BugWolf records that provenance and applies maximum capability inside it. BugWolf ships **no labs**: deterministic stubs under `tests/` (plus optional Anvil/LocalStack on the operator's own machine) validate the pipeline in CI only; they are never the production boundary.

---

## APT Commander — Strict Workflow, Uncensored Execution

BugWolf is architected as an **APT Commander**: a strict workflow layer that
enforces **depth and methodology**, sitting on top of an execution layer that is
deliberately **uncensored** for operational freedom.

- **The workflow enforces depth, not bureaucracy.** The 12-stage pipeline
  (`setup → environment-preflight → authorization → passive-recon →
  asset-intelligence → technology-fingerprint → maps → research →
  coverage-plan → validation → triage → report`) blocks advancement only when
  **artifacts are missing or research is stale**. Every stage has a hash-chained
  artifact prerequisite; tampered or missing artifacts stop the workflow.
- **The execution boundary enforces the operator's scope — deny-by-default.**
  Since v1.3.0, `tools/runtime/scope.py` authorizes the mission target's host
  (operator-declared) plus explicit `--scope` entries, blocks everything else
  at every network choke point (`http_probe`, the race engine's raw sockets,
  the live executor, the browser driver), and honors `--exclude` carve-outs
  (exclusions ALWAYS beat a wildcard — e.g. a bug-bounty program that excludes
  `beta.`/`community.` hosts). Out-of-scope requests fail CLOSED and are
  recorded as policy facts, never as tooling gaps.
- **Every subprocess runs under the sandbox.** `tools/runtime/sandbox.py`
  wraps all spawns: binary allowlist, scrubbed environment, output caps, and
  an operator kill switch (`python3 -m tools.runtime.sandbox kill`) that
  fails the whole release CLOSED.
- **Authorization is the operator's responsibility.** BugWolf is for
  authorized security research; only run it against targets you have explicit
  permission to test. The scope gate enforces what you declared — it cannot
  authorize what you did not.

## Operator-Supplied Target Intake

Every campaign starts with a recorded target spec. No autonomous target discovery is performed beyond the supplied identifier and scope. The operator chooses live validation or replica/fork validation, and supplies the Rules of Engagement; validation is non-destructive by default unless the spec explicitly flags a fully owned target.

```json
{
  "target_identifier": "https://api.example.com",
  "domain": "web/api",
  "authorization_basis": "own-asset",
  "scope_notes": {"in_scope": ["/api/*"], "out_of_scope": ["/admin"], "rate_limits": "1 request/sec", "testing_windows": "09:00-17:00 UTC", "credentials": "operator supplied"},
  "roe_flags": {"no_destructive": true},
  "validation_strategy": "live",
  "operator": "operator@example.com",
  "attestation": "I attest that I am authorized to test this boundary.",
  "campaign_id": "ENG-001"
}
```

Record it and attach it to campaign/evidence lineage:

```bash
python3 tools/target_intake.py --record target-spec.json --json
```

Supported authorization bases are `own-asset`, `bug-bounty scope URL`, `contract`, and `academic approval`; domains are `web/api`, `web3`, `mobile`, and `ai`. Use `"validation_strategy": "replica/fork"` for an Anvil/mainnet fork or equivalent reproducible environment. For academic campaigns, export seeds, pinned versions, environment hashes, Markdown/LaTeX methodology, anonymized aggregate data, baseline-vs-technique statistics, and citation-ready appendices:

```bash
python3 tools/target_intake.py --export-academic --target https://api.example.com --output-dir research/academic --attempts-file attempts.json --json
```

## What It Does

BugWolf runs six core security agents plus applicable domain agents in parallel. Findings are deduplicated, gate-evaluated, CVSS-scored, and formatted into a submission-ready report — only for explicitly authorized targets.

| Agent | Covers |
|---|---|
| Web / API | Auth bypass, IDOR, XSS, SSRF, SQLi, CSV injection, open redirect, path traversal, parameter pollution, GraphQL, CORS |
| Smart Contract | EVM, Move/Aptos, Solana, TRON — structural & chain-specific bugs |
| Access Control | Role bypass, init hijack, confused deputy, proxy admin |
| Business Logic | State machine abuse, workflow skip, limit bypass, payment logic |
| Crypto / Math | Overflow, precision loss, signature replay, EIP-712, nonce issues |
| Race Conditions | Front-running, sandwich, TOCTOU, rotation window races |
| Economic Security | Flash loans, oracle manipulation, inflation attacks, DeFi tokenomics |
| Recon | Subdomain takeover, secret leaks, cloud misconfig, chain explorer recon |

**Supported targets:** web/API, smart contracts, infrastructure, supply chain, internal tooling, binary analysis

**Local tooling:** When Claude Code execution is enabled, BugWolf can orchestrate local CLI tools like `nmap`, `ffuf`, `amass`, `sqlmap`, `gobuster`, `curl`, `httpx`, `wfuzz`, `zap`, `burpsuite`, and other installed scanners/fuzzers.

**Payload coverage:** Designed to explore unlimited payload variants for SQL injection, CSV injection, open redirect, XSS, SSRF, command injection, template injection, path traversal, deserialization, prototype pollution, auth bypass, business logic abuse, IDOR, CSRF, response splitting, and more.

**Reference setup files:** `references/setup.md` and `references/local-tooling.md` contain the actual Deepseek CLI, local tooling, and vulnerability environment instructions the skill uses.

**Report formats:** HackerOne · Bugcrowd · Intigriti · Immunefi · Generic

## Harness-Independent Session Contract

Long skill prompts can be compacted or forgotten by an AI harness. BugWolf therefore ships a short, reloadable `BUGWOLF.md` contract and an offline verifier instead of relying on model memory. The Freebuff installer also creates `AGENTS.md`, `CLAUDE.md` (only when absent), and `.bugwolf/harness.json`; other harnesses can load `configs/harness/BUGWOLF.md` manually.

Start every session with:

```bash
python3 tools/harness_guard.py --verify --json
```

If the verifier reports `ready: false`, reload the contract and stop rather than improvising. The executable tools still enforce the staged workflow and mandatory research independently of the model. No plugin can override a harness's system/developer policy, but this contract makes instruction drift detectable and recoverable across Claude Code, Freebuff/Codebuff, Codex, Cursor, Windsurf, Copilot, and similar hosts.

The contract supports direct conversational commands, so operators do not
need to know BugWolf's internal Python commands:

```text
bugwolf --full attack this target https://TARGET
bugwolf --web audit this target https://TARGET
bugwolf --solidity review this target PROJECT
```

The harness parses the target and mode, verifies or initializes the contract,
starts and inspects the staged workflow, and continues through the existing
workflow gates. It asks only for a missing target or environment declaration;
scope files and confirmations are recorded operator declarations, and the
v1.3.0 scope gate enforces them (deny-by-default) at every network choke point.
“attack” means authorized assessment — the remaining gates are artifact,
evidence, and human-review gates. Its reasoning remains creative through boundary
flips, differential comparisons, state/time and failure-path checks,
negative-space questions, and bounded cross-surface chains, while preserving
uncertainty and evidence state.

## Exhaustive staged startup — no direct hunting

After installation, the harness must initialize the persistent workflow instead
of jumping to `hunt.py`:

```bash
python3 tools/stage_controller.py --target TARGET --mode web --start --json
python3 tools/stage_controller.py --target TARGET --mode web --status --json
```

Every target proceeds through this non-skippable sequence:

```text
setup → environment-preflight → authorization → passive-recon
→ asset-intelligence → technology-fingerprint → maps → research
→ coverage-plan → validation → triage → report
```

State is stored in `.bugwolf/workflows/TARGET.json`. The controller requires
real artifacts for each stage, preserves pending/error status, and blocks
validation when current research is unavailable. It also blocks `hunt.py` until
validation and `zero_day.py` until coverage planning. “APT-level”
means complete, methodical, authorized coverage of the full target surface and
all trust/identity/state/capability boundaries—not unlimited traffic. Scope
files and confirmation flags are operator declarations, recorded for
provenance; the execution boundary itself is enforced by the v1.3.0 scope
gate (deny-by-default) and the sandbox kill switch.

## Lab Runtime Setup (optional, CI/local validation only)

The optional runtime stack is fully local and isolated. It is not part of
any production boundary — BugWolf ships no targets — and runtime-backed
validation reports a missing dependency instead of fabricating results.

```bash
# Start all supplied container runtimes
scripts/lab_setup.sh up

# Inspect readiness for all six runtimes
python3 tools/lab_doctor.py

# Stop and remove the disposable stack
scripts/lab_setup.sh down
```

The compose profile provides browser, Android emulator, Anvil chain node, Ollama, local MCP, and LocalStack services. If Docker Compose is unavailable, the fallback commands are printed by `scripts/lab_setup.sh up`; the host alternatives are Playwright Chromium, Android SDK/emulator, Foundry Anvil, Ollama with an explicitly pinned model, the supplied stdio MCP fixture, and LocalStack. Never treat a `MISSING` runtime as a successful test.

## Claude Code Four-Domain Research Workflow

Use the Claude Code-facing workflow for explicitly supplied local assets:

```bash
python3 tools/claude_workflow.py --target local-project --domain web_api --path src/app.py --json
python3 tools/claude_workflow.py --target local-project --domain web3 --path contracts/Vault.sol --json
python3 tools/claude_workflow.py --target local-project --domain mobile --path app/AndroidManifest.xml --json
python3 tools/claude_workflow.py --target local-project --domain ai --path agent/config.py --json
```

It dispatches to the existing four-domain analyzers, persists candidates through evidence/novelty handling, prioritizes critical/high hypotheses, and returns explicit diagnostics for optional browser, emulator, chain-node, model, MCP, and cloud runtimes. Missing runtimes are never represented as fake results.

## Potentially-Novel Research Track

BugWolf includes a bounded research track for discovering **potentially novel vulnerabilities** across Web/API, smart contracts, Cloud/CI/CD, LLM/agentic systems, and mobile/binary artifacts. It uses differential analysis, invariant testing, mutation lineage, replayable redacted evidence, local/public deduplication, and mandatory human review. It does not label an unreviewed candidate a zero-day.

Local candidate generation is non-networked:

```bash
python3 tools/zero_day.py --target local-project \
  --surface cloud_cicd --path .github/workflows/build.yml --json
```

Research can run **sequentially** — round over round, each round researching
the top ranked candidates and deriving bounded per-bug-class refinements
(deduped through novelty assessment, so only new angles survive):

```bash
python3 tools/zero_day.py --target T --surface web_api --path recon/T/urls.txt \
  --sequential --rounds 3 --per-round 2 --json
```

The `rounds` array in the output shows the lineage narrowing as explored
derivations are skipped (e.g. 5 → 4 → 2 kept per round); the final list is
still pre-ranked for validation with `--spread`/`--top-k`.

The track also synthesizes **chained hypotheses** — pairing input-class
candidates with sink/impact classes (cache-key control → write sink,
daemon input → command sink, untrusted checkout → script pipe, hidden context
→ tool authorization, …). Chains carry the criticals and are registered
through the same novelty dedup. Sequential mode includes them automatically;
standalone runs opt in with `--chains`:

```bash
python3 tools/zero_day.py --target T --surface web_api --path A --chains --json
```

The **Carlini Loop track** (`tools/carlini_loop.py`) applies the 2026 per-file
brute-force discovery pattern (Carlini Loop / nano-analyzer / NOVA — see
`ENHANCEMENT_PLAN.md`) to a local project: it enumerates source files
(bounded, extension-filtered, noise-excluded), builds a deterministic
per-file security briefing (imports, functions, entry points, line-anchored
dangerous sinks), and either emits one research unit per file for the
harness to execute with CTF framing, runs a model-free offline sink-catalog
scan, or intakes harness findings back through the normal
`ZeroDayResearchEngine` (novelty dedup + evidence + chain synthesis):

```bash
# 1. Emit per-file research units for the harness (no network)
python3 tools/carlini_loop.py --target local-project --path . \
  --emit-units research/local-project/carlini-loop/units.jsonl --json

# 2. Offline deterministic floor (no model needed)
python3 tools/carlini_loop.py --target local-project --path . \
  --offline --surface web_api --json

# 3. Intake harness findings and register through novelty/evidence
python3 tools/carlini_loop.py --target local-project \
  --register-result research/local-project/carlini-loop/intake.jsonl --json
```

Repeated intake is idempotent (stable candidate ids are filtered before
registration, near-matches come back as `likely_variant`), candidates stay
HYPOTHESIS until trigger+impact evidence exists, and nothing is labeled a
zero-day without human review.

Every real `hunt.py`, `recon_engine.sh`, and `zero_day.py` run now invokes the deep-research coordinator sequentially: `pre-hunt → post-recon → post-maps → bypass`, then `post-findings → escalation → pre-report`. Each checkpoint is persisted under `research/<target>/` and summarized in `research/<target>/sequence.json`; `latest_ready: false` explicitly means live-search data was unavailable. Configure `SERPER_API_KEY` or an HTTPS `RESEARCH_SEARCH_API_URL` plus `RESEARCH_SEARCH_API_KEY` when current web results are required. Use `python3 tools/research_loop.py --sequential --phase full --target T --mode web --execute --json` to run the same sequence manually.

After each hunt, recon, and potentially-novel journey, newly observed techniques and blocker patterns are added to a quarantined local memory at `state/learning/<target>.jsonl`. Repeated records are deduplicated; only explicitly reviewed records can be reused in future target-specific wordlists. The plugin never self-modifies executable source or auto-approves untrusted research:

```bash
python3 tools/adaptive_learning.py --target T --list --status candidate --json
python3 tools/adaptive_learning.py --target T --review-id ID --decision approve \\
  --reviewer operator --evidence "Confirmed on an authorized disposable fixture" --json
```

See [`references/adaptive-learning.md`](references/adaptive-learning.md).

Live validation runs through the execution controller under the v1.3.0
boundary controls: the scope gate blocks out-of-scope requests (fail-closed,
recorded as policy facts) and every spawn passes the sandbox. Request budgets remain bounded. See [`references/zero-day-research.md`](references/zero-day-research.md).

The cache-key path traversal track (`tools/cache_traversal.py`, CVE-2026-18051 class) plans directory-escape probes from the target's cache-key construction and replays them against a lab with unique marker files:

```bash
# Offline escape plan (no network)
python3 tools/cache_traversal.py --target example.com --spec w3tc-page-cache \
  --urls-file recon/example.com/urls.txt --output-dir recon/example.com/cache-traversal

# Gated lab replay: marker-served vs control-404 confirms the escape
python3 tools/cache_traversal.py --target example.com --spec w3tc-page-cache \
  --urls-file recon/example.com/urls.txt --base-url https://lab.example.com \
  --scope-file scope.json --confirm-active --json
```

For Relay-style GraphQL deployments, `tools/graphql_gid.py` analyzes introspection results for `node(id:)` / `nodes(ids:)` global-id resolvers, harvests `gid://` references already present in the target's own artifacts (never enumerating ids, redacting every harvested id), and builds the bounded candidate list that feeds the two-account validation flow (Account A owns a disposable fixture; Account B replays A's *owned* gid — HackerOne #1618347 pattern):

```bash
python3 tools/graphql_gid.py --target example.com \
  --introspection recon/example.com/introspection.json \
  --artifacts recon/example.com/js recon/example.com/queries.txt \
  --output-dir recon/example.com/graphql-gid --json
```

---

## Recon intelligence: JavaScript and certificate transparency

The recon engine now includes `tools/js_ct_intel.py`, a scoped intelligence phase adapted from the reviewed [Cyber-note/Full-Bug-Bounty-Hunting-Methodology-2026](https://github.com/Cyber-note/Full-Bug-Bounty-Hunting-Methodology-2026) workflow. It uses `crt.name` with date fields and falls back to `crt.sh`, then records certificate names in `ct-records.jsonl` and `ct-subdomains.txt`.

For JavaScript, the phase combines existing `katana`/`hakrawler` URL collection with local `LinkFinder` (when installed), `js-beautify`/`prettier` (when installed), plain `grep`, and built-in extraction. It writes redacted endpoint/secret indicators, source-map references, and business-logic workflow hypotheses; it never validates or prints credential values.

A dedicated `tools/js_token_forge.py` static analyzer also flags client-side token forging — a hardcoded signing secret combined with an in-browser HMAC/sign primitive and client-controlled user/device/role claims (the classic `getSDToken(deviceId, userId, …)` pattern). It emits `token-forge-findings.jsonl` + `token-forge-plans.jsonl` with forgeability grades and remediation, storing only SHA-256 fingerprints of the matched lines (the raw secret is never written).

```bash
# Passive CT collection; scope file is an optional declaration, nothing blocks
python3 tools/js_ct_intel.py --target example.com \\
  --scope-file scope.json --output-dir recon/example.com --ct-only

# Analyze already-collected URLs and local JS without making network requests
python3 tools/js_ct_intel.py --target example.com \\
  --scope-file scope.json --urls-file recon/example.com/urls.txt \\
  --js-dir recon/example.com/js --output-dir recon/example.com/js-intel --js-only
```

Optional crawler execution is a separate mode triggered by `--collect-crawlers` (bounded by a process timeout); `--confirm-active` is an accepted declaration, not a requirement. These outputs are intelligence and hypotheses, not confirmed vulnerabilities or zero-day claims.

## Signal-to-impact methodology playbook

The reviewed 2026 articles are represented as an offline planning layer in `tools/methodology_playbook.py`. It turns URLs and scanner output into human-validation tasks for skipped/repeated/reordered steps, role and ownership boundaries, payment state, one-time tokens, idempotency, file access, server-side validation, IDOR, SQLi, and XSS.

```bash
python3 tools/methodology_playbook.py \\
  --target example.com --scope-file scope.json \\
  --urls-file recon/example.com/urls.txt \\
  --signals-file recon/example.com/nuclei.txt \\
  --output-dir recon/example.com/methodology
```

The generated ffuf/nuclei/SQLMap/XSStrike entries are **non-executing command plans**. SQLMap plans are confirmation-only and exclude database enumeration or dumping. Discovery output is never promoted directly to a finding; each task requires a reproducible trigger, bounded impact, redacted evidence, and human review.

## Defensive and asset intelligence

Additional offline tracks now cover passive asset graphing and diffing, provider query plans for Amass/Shodan/Censys/FOFA/ZoomEye/SpiderFoot, Shodan facet collection via the `ipfinder` CLI (offline facet plans + command lines by default; live collection triggered with `--collect-ipfinder`, `--confirm-active` an accepted declaration), defensive lateral-movement, persistence (TA0003), EDR-evasion *detection* hypotheses, and in-memory shellcode-runner *detection* signals (private allocation, RW→RX transitions, thread start outside a loaded module, mapped-execution variants, import-table signatures) from supplied logs, identity/MFA/OAuth/SAML posture, cloud/IaC boundaries, CVE-reference triage (including `--nuclei` template intake and curated `--seed` records), and deeper IDOR planning across the common-vector surfaces: path ids, file names, `X-Account-Id`-style headers, cookies, GraphQL `gid://` node ids, JWT claims, and PendingIntent mobile surfaces. Persistence/evasion output is detection hypotheses only — no implant, evasion loop, or bypass primitive is built or run.

```bash
python3 tools/asset_intel.py --target example.com --scope-file scope.json \\
  --input-file recon/example.com/subs.txt \\
  --output-dir recon/example.com/asset-intel

# Shodan facet plans + ipfinder command lines (offline; live is uncensored)
python3 tools/asset_intel.py --target example.com --scope-file scope.json \\
  --shodan-facets --output-dir recon/example.com/asset-intel

python3 tools/defensive_detection.py --path exported-security.log \\
  --rules --output-dir defensive-review

python3 tools/identity_cloud.py --path infrastructure/ \\
  --plans --output-dir posture-review
```

These modules are offline by default. They do not contact OSINT providers, execute LOLBAS commands, perform MFA prompts, replay tokens, access metadata, mutate cloud resources, enumerate users, dump data, or run CVE exploit code. See [`references/defensive-intelligence.md`](references/defensive-intelligence.md).

Static high-impact chain analysis is available through `tools/chain_analyzer.py`, and AI/MCP defense analysis through `tools/ai_defense.py`. They produce source-hashed findings and remediation plans for SQLi-to-impact, upload/path consumers, deserialization, XXE file-read-to-credential chains, header/command sinks, prompt injection, indirect content, tool authorization, IFC, plan drift, and MCP OAuth boundaries. They never generate or execute exploit payloads. See [`references/chain-analysis.md`](references/chain-analysis.md).

Research-derived analysis from the supplied security papers and framework notes is available through `tools/paper_intel.py`. It adds offline skill-chain composition scanning, temporal provenance bottleneck ranking, endpoint-specific authentication anomaly triage, CTI-to-Sigma grounding plans, contamination-aware binary reverse-engineering task planning, quarantined defense candidates, STAR-style HTTPS metadata privacy assessment with unknown rejection, and a vendor-neutral Agent control-plane audit across identity, data, tools, memory, telemetry, grounding, and SOC response. It does not execute skills, binaries, payloads, capture/decrypt traffic, attribute unrelated users, or change permissions. See [`references/paper-intelligence.md`](references/paper-intelligence.md).

## Privacy and data governance

`tools/pii_firewall.py` provides deterministic local masking before LLM, tool, log, webhook, or provider egress. It supports nested JSON/XML, request-bound reversible tokens held only in memory with TTL, token consolidation, residual warnings, and optional fail-closed behavior. `tools/data_governance.py` classifies schema fields and produces Kafka/topic encryption, ACL, retention, and field-level audit plans.

```bash
python3 tools/pii_firewall.py \\
  --text 'Patient Jane Doe, email jane@example.com' \\
  --request-id case-123 --policy mask_and_warn

python3 tools/data_governance.py \\
  --schema-file schemas/event.json --topic clinical.events \\
  --output-dir governance-review
```

The privacy layer is an engineering control, not compliance certification. It never sends raw PHI to an LLM, persists reversible mappings, contacts Kafka/KMS/Schema Registry, or substitutes for legal, access-control, retention, and audit review. See [`references/privacy-governance.md`](references/privacy-governance.md).

## Web/API Discovery Core

A deterministic discovery layer between the methodology maps and the authorization controller. It turns recon artifacts into a coverage-aware search for novel bugs without firing anything itself.

No manual schema files needed: pass `--recon-dir recon/example.com` to any of these and `tools/schema_extractor.py` auto-discovers OpenAPI/Swagger and GraphQL schemas from the recon output (URLs, live hosts, `swagger.txt`, JS bundles).

```bash
# Auto-build the model from a completed recon run
python3 tools/schema_extractor.py --target example.com \
  --recon-dir recon/example.com \
  --output recon/example.com/discovery/surface-model.json

# Or schedule directly from recon output
python3 tools/discovery_scheduler.py --target example.com \
  --recon-dir recon/example.com --output-dir recon/example.com/discovery

# 1. Structured surface (OpenAPI/Swagger/GraphQL/URLs + sibling & state inference)
python3 tools/surface_model.py --target example.com --openapi openapi.json \
  --urls-file recon/example.com/urls.txt \
  --output recon/example.com/discovery/surface-model.json

# 2. Structure-aware mutation plans (one variable at a time)
python3 tools/mutator.py --target example.com --openapi openapi.json \
  --output recon/example.com/discovery/mutations.jsonl

# 3. Impact-ranked, coverage-aware plan
python3 tools/discovery_scheduler.py --target example.com --openapi openapi.json \
  --urls-file recon/example.com/urls.txt \
  --output-dir recon/example.com/discovery --budget 200 --min-focus medium
```

The scheduler orders mutations by impact focus (critical first) then untried surface, and its live loop runs each mutation through the oracle and emits the deterministic next step for every ambiguous result. Live execution runs through the execution controller under the boundary controls (scope gate deny-by-default; sandbox on every spawn). See [`references/discovery-core.md`](references/discovery-core.md).

Add `--art` to switch budget allocation to the ART4SQLi selection method (Zhang et al., IEEE Trans. Reliability): SQLi payloads are tokenized, embedded as TF-IDF vectors, and spaced by the `1/cosine` distance, so each probe is picked farthest from everything already evaluated — effective payloads cluster in token space, and the paper measures ~26% fewer attempts before the first successful injection versus random. `--art-fixed-size` (default 10) controls the FSCS candidate-set size; `tools/art_selector.py` also exposes the tokenizer, the payload space, and the paper's F-measure metric for comparing selection strategies.

Sibling surfaces are replayed live by `tools/differential_runner.py`, which sends the identical request to v1/v2 (and other paired) surfaces and scores divergence — offline pair-planning by default, live replay triggered with `--confirm-active` (a declaration, never a gate).

Forwarded/trust headers (IP allowlist, host/vhost confusion, scheme/port override, path/URI rewrite, method override) are covered by `tools/header_trust.py` — a canonical taxonomy plus a baseline-vs-forged probe planner and live replay scored by the oracle. The mutator emits `header_trust` mutations per origin host so the discovery scheduler allocates budget across this surface. Forged values are trust hypotheses, never executed payloads. `recon_engine.sh` emits the offline `header-trust-plan.json` automatically after discovery; live replay runs when requested with `--confirm-active` (a declaration, never a gate).

Host-confusion probes also target the application's own internal vhost candidates: the surface model infers and ranks subdomains like `admin`/`api`/`dev` (grouped by resolved IP), and `header_trust` replays them as `Host`/forwarded-host values instead of only the generic `localhost`/`internal` list.

The surface model also ensures a `GET /sitemap.xml` operation with `offset`/`page`/`limit`/`sort`/`order`/`filter` parameters, and the mutator plans `blind_sqli` time-based detection for those pagination/sort surfaces (`SLEEP`/`PG_SLEEP`/`WAITFOR DELAY`). Those strings are detection *plans*, never auto-fired — live execution still requires the gated controller.

The same coverage loop drives smart-contract state-space exploration via `tools/contract_discovery.py`: bounded sequence/boundary/role/reentrancy mutation plans, a deterministic in-memory invariant executor, and automatic minimization of violating sequences to minimal reproducers. See [`references/discovery-core.md`](references/discovery-core.md) — smart-contract extension.

## Live Execution Harness Loop (Phase 3)

BugWolf is now a *hunter*, not just a planner: research units are executed as
real HTTP probes with recorded, replayable evidence.

```bash
# Drive the full campaign with live probing: unit -> probe -> observe -> adapt
python3 tools/core/campaign_orchestrator.py --target example.com --live-run \
  --base-url https://example.com --max-units 30

# Fuzz a surface with scheduler-ordered mutations; crash/timeout/anomaly
# evidence is published into research threads as FINDING_DISCOVERED events
python3 tools/core/fuzz_bridge.py --target example.com \
  --base-url https://example.com --recon-dir recon/example.com --budget 100

# Novel-class hunting beyond the fixed bug-class templates
tools/zero_day.py --mode diff-analysis   # behavior deltas across versions
#   --mode anomaly-detection             # status/timing/header/error anomalies
#   --mode state-machine                 # workflow skip/repeat/reorder
```

- `tools/core/live_executor.py` — deterministic probe planning + execution
  (baseline + technique probes), WAF detection, bounded retries, and a
  reproducible-evidence block (`replay_key`) per probe. Probes persist to
  `state/sessions/<target>/probes.jsonl`.
- `live_feedback_loop()` adapts: blocked (403/WAF) → `failure_learning`
  bypass quarantine; signal → F0.5 gate with recorded evidence
  (`require_reproducible` forces CONFIRMED to need replayable proof);
  clean → REFUTED; transport errors are observations, never gates.
- `tools/refutation.py` — `verify_reproducibility()` replays a finding's
  recorded request via the live executor for deterministic reproduction.
- Integration tests boot a deterministic stub target in-process and assert the
  real probe → observation → adaptation cycle (`tests/test_live_feedback_loop.py`,
  `tests/test_e2e_deep_dive_campaign.py`).

---

## AI Pentesting Tool — bugwolf.xyz

Take BugWolf hunting without spinning up your own environment. **[bugwolf.xyz](https://bugwolf.xyz)** hosts the same engine in isolated pentesting sandboxes:

- Firecracker microVM per session — your AI key, your box, your report
- Full `recon → hunt → triage → H1-ready report` pipeline in the browser
- No rate limits, no AI slop — clean, isolated execution
- Hosted skill releases managed from this repo

> **Choose your platform:** install the open-source skill here, or hunt in the cloud at [bugwolf.xyz](https://bugwolf.xyz).

---

## Installation

### Claude Code plugin (recommended)

Two lines, inside Claude Code:

```text
/plugin marketplace add youseefhamdi/bugwolf
/plugin install bugwolf@bugwolf
```

All 10 slash commands load namespaced, the 39 `bugwolf:<role>` subagents
dispatch natively through the Task tool, the session/stop hooks wire up,
and the MCP bridge (`bugwolf_status` / `bugwolf_plan` / `bugwolf_run` /
`bugwolf_leads` / `bugwolf_mode`) is available in every session via the
bundled `.mcp.json` — zero extra setup.

### Freebuff / Codebuff (terminal)

BugWolf is a standard skill for the Codebuff skill loader (`npx skills`), which [Freebuff](https://github.com/CodebuffAI/freebuff) and Codebuff read from `.agents/skills/` at session start:

```bash
# Project-local install (loads in this project; also lands in .claude/skills for Claude Code)
npx skills add youseefhamdi/bugwolf --skill bugwolf --copy

# Global install (available in every project)
npx skills add youseefhamdi/bugwolf --skill bugwolf --copy -g

# Or install offline from this repo — no CLI or network needed:
#   Option A: unzip dist/bugwolf-v<version>.freebuff.zip into your project
#            (it creates .agents/skills/bugwolf/)
#   Option B: run ./scripts/install_freebuff.sh [project-dir]
```

Then start a fresh Freebuff session in the project — the skill loads as **bugwolf** and triggers on the same phrases as Claude Code.

### Freebuff + DeepSeek configuration

Freebuff's default model in full mode is **DeepSeek V4 Flash** (V4 Pro is one session a day; the limited tier is MiMo 2.5). The skill ships a ready-to-apply runtime profile for that stack in [`configs/freebuff-deepseek.json`](configs/freebuff-deepseek.json) — install command, model facts, the declared flags (`scope.json`, `--confirm-active`, `--confirm-destructive`), and a toolchain self-test — and a project template at [`configs/freebuff/AGENTS.md`](configs/freebuff/AGENTS.md). To make every Freebuff session in a target project load BugWolf with the DeepSeek operating contract, copy the template to the project root:

```bash
cp configs/freebuff/AGENTS.md /path/to/target-project/AGENTS.md
```

The contract matters because DeepSeek executes instructions literally: run the exact documented command lines, always pass `--json` where supported, and never skip a workflow stage or artifact prerequisite. `SKILL.md` applies it in-session; the config profile and template ship inside both release bundles.

### Claude Code (terminal)

```bash
# Either the npx skills route above (lands in .claude/skills/bugwolf too), or directly:
git clone https://github.com/youseefhamdi/bugwolf.git ~/.claude/skills/bugwolf
```

Start a fresh Claude Code session — skills load at startup.

### Claude.ai (web/app)

1. Go to **Customize → Skills**
2. Make sure **Code execution** is enabled in **Settings → Capabilities**
3. Upload the `.skill` file from [Releases](https://github.com/youseefhamdi/bugwolf/releases)

### Optional: Bug Bounty Intelligence MCP (smart contract scanning)

For automated Solidity scanning with Al-Mizaan v3 7-gate analysis, add the companion MCP server:

```bash
claude mcp add bug-bounty-intelligence -- npx -y bug-bounty-intelligence-mcp@latest
```

Or in `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "bug-bounty-intelligence": {
      "command": "npx",
      "args": ["-y", "bug-bounty-intelligence-mcp@latest"]
    }
  }
}
```

**Tools available:**
| Tool | Cost | Purpose |
|------|------|---------|
| `scan_contract` | $5 USDC on Base | Submit a public Solidity repo for AI security analysis |
| `get_scan_report` | Free | Poll scan status and get report URL |
| `list_vulnerability_patterns` | Free | Acceptance rates from 1,032 reconciled Sherlock findings |

BugWolf auto-detects the MCP and uses `list_vulnerability_patterns` (free) for pre-hunt bug-class prioritization. See `references/bug-bounty-intelligence-mcp.md` for full integration guide.

---

## Enabling Claude Code Execution (local execution)

To allow BugWolf to run local tools and subagents, enable Claude Code (local execution) in your Claude environment and grant the skill permission to execute shell commands.

macOS / Linux (Claude Code client):

1. Start Claude Code with code-execution enabled (follow your Claude Code client docs).
2. Ensure the shell that launches Claude Code has the tools you want on `PATH` (e.g., `nmap`, `ffuf`, `sqlmap`).
3. If using project-specific env vars, source your project file before starting Claude Code:

```bash
source .env            # or project.env
claude start           # or the command your Claude Code client uses
```

Windows (Claude.app / PowerShell):

1. Open PowerShell as the user that runs Claude.
2. Set any project env vars or tokens (example shown in `references/setup.md`).
3. Launch Claude with code execution enabled from the same session so it inherits the environment.

Notes:
- If you are using the web/app variant, go to **Settings → Capabilities** and toggle **Code execution** on. Some deployments require you to enable a "subagent" or "local tooling" checkbox; consult your Claude distribution docs.
- Always start Claude from the shell that has your project environment loaded so `deepseek export`, `nmap`, and other tools are available to the skill.
- For privacy and safety, grant execution permission only for trusted skills and projects.


## Deepseek Pro Setup (Claude CLI)

BugWolf includes `references/setup.md` so the skill can use the same Deepseek CLI environment and local tooling configuration during audit runs.

### Mac / Linux

In your project shell or project file, export:

```bash
export ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
export ANTHROPIC_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash
export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash
export CLAUDE_CODE_EFFORT_LEVEL=max
export ANTHROPIC_AUTH_TOKEN="your-deepseek-pro-token"
```

Then bind the current repo:

```bash
deepseek export --project . --key "$ANTHROPIC_AUTH_TOKEN" --mode pro
```

Start Claude CLI from the same shell so the environment variables are active.

### Windows (PowerShell)

Use these variables in the current session:

```powershell
$env:ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"
$env:ANTHROPIC_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_OPUS_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_SONNET_MODEL = "deepseek-v4-pro"
$env:ANTHROPIC_DEFAULT_HAIKU_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_SUBAGENT_MODEL = "deepseek-v4-flash"
$env:CLAUDE_CODE_EFFORT_LEVEL = "max"
$env:ANTHROPIC_AUTH_TOKEN = "your-deepseek-pro-token"

deepseek export --project . --key $env:ANTHROPIC_AUTH_TOKEN --mode pro
```

For persistence, add the same variables to your PowerShell profile.

> Note: this setup is intended for temporary use inside a project or shell session so the Deepseek CLI export command can be applied without modifying the core skill files.

---

## Usage

### Environment preflight

Before starting reconnaissance or active testing, BugWolf asks whether the agent is running on a local workstation, VPS, container/VM, or unknown base, and whether it may perform a passive local OS/resource inventory. The inventory does not scan the network, read secrets, inspect user files, or contact cloud metadata services.

```bash
# Declaration only
python3 tools/environment_profile.py --location vps --json

# Requires explicit permission for passive OS/resource details
python3 tools/environment_profile.py --location vps --scan-os --confirm-os-scan --json
```

Use the saved profile with the hunt engine:

```bash
python3 tools/hunt.py --target TARGET --scope-file scope.json \
  --environment-profile state/environment.json --active --confirm-active --json
```

### How to use BugWolf

1. **Choose a precise scope.** For bug bounty work, point the skill at the exact contract file, API endpoint list, or web target you are testing.
2. **Enable code execution.** When Claude Code can run locally, BugWolf can orchestrate local tools like `nmap`, `ffuf`, `amass`, `sqlmap`, `gobuster`, `curl`, `httpx`, and `zap`.
3. **Run an audit command.** Use the examples below and include `--file-output` or `--cvss` when you want a formatted deliverable.
4. **Review findings.** The skill will classify and gate each finding, but always validate exploitability before submitting.
5. **Generate a report.** Use the built-in report mode to turn confirmed findings into platform-ready output.

### Audit a contract or repo

```
audit contracts/
```
```
run bugwolf on src/usdc.move --platform immunefi --cvss --file-output
```
>/bugwolf <targetfile>
```
check this contract for vulns --platform h1 --cvss
```

### Web / API target

Declare the authorized scope — the gate **enforces** it (deny-by-default; the
target host is always authorized, everything else is blocked):

```json
{
  "authorized": true,
  "in_scope_domains": ["example.com"],
  "in_scope_wildcards": ["*.api.example.com"],
  "out_of_scope_domains": ["beta.example.com", "community.example.com"]
}
```

Then run a mission — the orchestrator plans the task graph, runs the
mandatory pre-flight, and enforces the scope on every request:

```bash
python3 -m tools.runtime.mission_runner --mission-id demo-001 \
  --target https://api.target.com --paths /api,/ingest \
  --scope scope.json --oast --json
```

Scope extensions and carve-outs (exclusions always beat a wildcard):

```bash
# extra authorized hosts beyond the target
python3 -m tools.runtime.mission_runner ... --scope scope.txt
# program-excluded hosts, even if a wildcard would match them
python3 -m tools.runtime.mission_runner ... --exclude excluded.txt
```

Remote targets attribute out-of-bounds callbacks through the public
tunnel (`--oast` + `BUGWOLF_OAST_TUNNEL=1`); every SSRF lead can close
on an attributed callback instead of staying a hypothesis.

Emergency stop — one command halts every subprocess the engine may
spawn, fail-closed:

```bash
python3 -m tools.runtime.sandbox kill --note "incident"
python3 -m tools.runtime.sandbox status   # inspect / re-arm / verify
```

Skill-level flow (Claude Code / Freebuff) is unchanged:

```
/bugwolf on https://api.target.com --scope-file scope.json
```

```
find vulns in this API — [paste endpoints / Swagger / JS bundle]
```

The IDOR engine tests read-only methods by default. Add `--confirm-destructive` only for an approved test environment when validating PUT/POST/DELETE behavior.

### Generate a report from findings

```
write a HackerOne report for this finding: [paste notes]
```
```
generate immunefi report --cvss: [describe the vuln]
```

---

## Flags

| Flag | Description |
|---|---|
| `--platform h1` | Format output for HackerOne |
| `--platform immunefi` | Immunefi template |
| `--platform bugcrowd` | Bugcrowd format |
| `--platform intigriti` | Intigriti format |
| `--cvss` | Include full CVSS 3.1 vector string + justification |
| `--file-output` | Save report to `bugwolf-report-[timestamp].md` |
| `--full` | Run all applicable agents regardless of detected file type |
| `--scope-file scope.json` | Declared scope — enforced by the v1.3.0 scope gate (deny-by-default) |
| `--confirm-active` | Operator declaration for active testing (recorded; active probes obey the scope gate) |
| `--confirm-destructive` | Operator declaration for state-changing IDOR methods; approved environments only |

---

## How It Works

```
Discover files / scope
        ↓
Build agent bundles (source + agent instructions)
        ↓
Spawn six core agents plus applicable domain agents in parallel
        ↓
Deduplicate findings by (Target | location | bug-class)
        ↓
Gate evaluation: Refutation → Reachability → Trigger → Impact
        ↓
CVSS 3.1 scoring
        ↓
Submission-ready report
```

Every finding passes four gates before it's confirmed:

1. **Refutation** — can the attack be concretely blocked by an existing guard?
2. **Reachability** — can the vulnerable state exist in a live deployment?
3. **Trigger** — can an unprivileged actor execute it profitably?
4. **Impact** — is there material harm to an identifiable victim?

Fail any gate → rejected or demoted to a lead for manual review.

**F0.5 precision-first reporting (default):** findings are scored deterministically from their evidence (reproducible trigger trace, impact trace, evidence refs, endpoint, confirmed behavior). Findings below the confidence threshold are **DEMOTED** and quarantined to `state/learning/<target>.jsonl` for operator review instead of reaching the final report — uncensored *execution* is untouched, only uncensored *reporting* ends. Legacy auto-confirm is preserved with `--no-strict` (`python3 tools/refutation.py --target T --no-strict`).

---

## Tips

- **Target hot contracts.** Point BugWolf at the 2–5 files you're actively reviewing rather than an entire repo. Smaller scope = denser context per agent = higher-signal findings.
- **Run more than once.** LLM output is non-deterministic — each run can surface different vulnerabilities. Two or three passes often catch what a single pass misses.
- **Chain findings.** BugWolf keeps chaining after the first connection: it combines findings with parked/open leads, resolves multi-hop paths, exposes missing links as the next research task, ranks terminal impact, and preserves the chain history. A chain is not reported until every edge is evidenced and reviewed.
- **Use `--file-output`** when submitting. It saves a clean markdown report you can paste directly into the platform.

---

## Updating

```bash
cd ~/.claude/skills/bugwolf
git pull
```

BugWolf checks for updates automatically on each run and will warn you if a newer version is available.

---

## Structure

```
bugwolf/
├── SKILL.md                          # Main orchestrator
├── VERSION                           # Current version
├── CHANGELOG.md                      # Release notes
├── tools/runtime/                    # Orchestrator runtime (v1.3.0)
│   ├── mission_runner.py             # Mission lanes + lead protocol
│   ├── scope.py                      # Deny-by-default operator scope gate
│   ├── sandbox.py                    # Subprocess sandbox + kill switch
│   ├── scheduler.py                  # Durable task-graph scheduler
│   ├── preflight.py                  # Mandatory pre-flight (PF1-PF4)
│   ├── lead_protocol.py              # R1/R3 anti-satisficing lead ladder
│   ├── oast.py / oast_tunnel.py      # Canary attribution + public tunnel
│   └── contracts.py                  # Structural result validation
└── references/
    ├── judging.md                    # 4-gate evaluation rules
    ├── supervisor.md                 # Detailed triage supervisor system
    ├── knowledge.md                  # Disclosed-report knowledge base
    ├── report-formatting.md          # Platform report templates
    ├── research-loop.md               # Mandatory deep-research loop (R1-R5)
    ├── cvss-guide.md                 # CVSS 3.1 scoring guide
    ├── setup.md                      # Deepseek CLI environment guidance
    ├── local-tooling.md              # Local tooling and vuln coverage reference
    ├── al-mizaan-gates.md            # Al-Mizaan v3 7-gate deep validation (from Bug Bounty Intelligence MCP)
    ├── sis-intelligence.md           # SIS-MD passive security intelligence integration
    ├── isolation.md                  # Agent isolation rules and boundary enforcement
    ├── zero-day-research.md          # Potentially-novel research lifecycle and lab workflow
    ├── cwe-knowledge-base.md          # 1,047 CWEs across 16 agent domains with detection patterns
    ├── attack-vectors/
    │   ├── web-api-vectors.md
    │   ├── smart-contract-vectors.md
    │   ├── business-logic-vectors.md
    │   ├── llm-ai-vectors.md
    │   ├── mobile-vectors.md
    │   ├── cloud-vectors.md
    │   └── ...
    └── hacking-agents/
        ├── shared-rules.md
        ├── web-api-agent.md
        ├── llm-ai-agent.md
        ├── smart-contract-agent.md
        ├── access-control-agent.md
        ├── business-logic-agent.md
        ├── crypto-math-agent.md
        ├── race-condition-agent.md
        ├── economic-security-agent.md
        └── recon-agent.md
```

---

---

## Collaboration & Integrated Projects

BugWolf v1.0.0 integrates methodologies from:

| Project | What We Integrated | Reference |
|---------|-------------------|-----------|
| [Bug Bounty Intelligence MCP](https://github.com/holistis/bug-bounty-intelligence-mcp) | Al-Mizaan v3 7-gate deep validation framework, scope-aware filtering methodology, vulnerability acceptance rates from 27,681 Sherlock/Code4rena findings | `references/al-mizaan-gates.md` |
| [3ilm MCP](https://github.com/holistis/3ilm-mcp) | Free vulnerability pattern lookup (sibling project) | Resources section |
| [SIS-MD Security Intelligence SkillMD](https://github.com/prize22/SIS-MD-Security-Intelligence-SkillMD-) | Passive security intelligence modules (metadata, secrets, fingerprinting), boundary enforcement rules, structured report format | `references/sis-intelligence.md` |

**Key lessons integrated:**
- **From Bug Bounty Intelligence:** 100% of Slither's "High" findings on a mature protocol were false positives — 89% were out-of-scope `lib/` noise. Scope-aware, context-aware analysis eliminates this class of error entirely.
- **From SIS-MD:** Passive analysis before active hunting catches metadata leaks, secret sprawl, and technology misconfigurations that active scanners miss. Masked reporting prevents the report itself from becoming a leak vector.

---

## Disclaimer

BugWolf is intended for authorized security research and bug bounty programs only. Only use it against targets you have explicit permission to test. The author is not responsible for misuse.

---

## Company Model

BugWolf is organized as a "security-research AI company" modeled on
the Japanese brain-market convention of **11 departments, 31
employees**. We adopt that framing and extend it:

- **11+ lanes** — the top-level capability areas
- **19 agents** — the focused specialists inside each lane
- **21+ directions** — the bug-class taxonomies each agent owns
- **Tier 1** — the strongest directions (production-ready, full
  evidence chain, regression coverage)

### Lanes (11+)

| Lane               | Scope                                              |
|--------------------|----------------------------------------------------|
| web                | Web/API attack surface                             |
| auth               | OAuth / JWT / SAML / session                        |
| infra              | CI/CD + cloud + supply chain                        |
| llm                | LLM/Agentic AI attack surface                      |
| api                | GraphQL / gRPC / REST                              |
| orchestrator       | Multi-agent + multi-lane dispatch                  |
| scanners           | 68 specialized scanners                            |
| fuzz               | 9 fuzz engines                                     |
| taint              | Source-to-sink flow analysis                       |
| semantic           | Business-logic / auth-flow / diff                  |
| regression         | Baselines + canaries + chains                      |
| chain              | A→B→C attack synthesis (12 H100 chains)            |
| methodology        | 70 patterns + 10 templates                         |
| recon              | 15-phase recon engine                              |
| osint              | Passive intel + transparency                      |
| web3               | EVM/Move/Solana/TRON + 62 EVM patterns             |
| cloud              | Terraform / IAM / S3 / SG / STS                    |
| cicd               | GitHub Actions + runners + artifact poisoning      |
| mobile             | MASVS / MASWE / Frida / deep links                 |
| distributed        | Redis master/worker + IPC + load balancer          |
| benchmarks         | synthlab + adversarial + regression + scoring      |

### Agents (19)

Each agent is a focused specialist. The full list is in
`docs/COMPANY.md`. Examples: `web_xss`, `auth_oauth`,
`web3_reentrancy`, `llm_prompt_injection`, `cloud_iam`,
`mobile_frida`, `cicd_actions`, `fuzz_coverage`,
`taint_python`, `semantic_business_logic`.

### Directions (21+)

Each direction is a bug class that one or more agents own.
Tier 1 directions are production-ready with regression coverage.
Full table in `docs/COMPANY.md`.

### Tier table (top 6)

| Direction              | Tier | Notes                                    |
|------------------------|------|------------------------------------------|
| XSS                    | 1    | Best — full evidence chain                |
| SQLi                   | 1    | Best — multi-DB                          |
| SSRF                   | 1    | Best — DNS rebinding + IPv6              |
| IDOR                   | 1    | Best — object + function-level           |
| OAuth                  | 1    | Best — code interception + ATO chain     |
| JWT                    | 1    | Best — alg confusion + key confusion     |

For the full tier table (21+ directions), see `docs/COMPANY.md`.

Built by [@youseefhamdi](https://github.com/youseefhamdi)
# Changelog

## v1.1.0 — APT-Grade Deep-Hunt Platform (2026-08-26)

- **Modular domain architecture** (`tools/domains/`): the flat tool
  collection became a hierarchical, event-driven APT framework — `core/`
  (stage controller, campaign orchestrator, research loop, signal bus),
  `domains/{web,api,auth,cloud,mobile,smart_contracts,llm}/`,
  `recon/`, `intelligence/`, and `validation/`.
- **Event-driven signal bus** (`tools/core/signal_bus.py`): typed events
  (`RECON_COMPLETE`, `FINDING_DISCOVERED`, `WAF_BLOCKED`, `SMUGGLING_CANDIDATE`,
  `AUTH_CANDIDATE`, `CLOUD_CANDIDATE`, `MOBILE_CANDIDATE`, `ASSET_DELTA`,
  `LLM_CANDIDATE`, `LAB_PLANNED`, `CHAIN_PROPOSAL`, `EVAL_COMPLETE`) with
  canonical listeners; tools react to findings instead of running in a flat
  sequence.
- **Hierarchical research loop**: 3 event-driven dynamic checkpoints
  (`post-chain`, `post-lab-verification`, `blocker-exhausted`) append to the
  mandatory 7; sub-checkpoints (e.g. `graphql-deep-dive`, `waf-profile`,
  `cloud-metadata`) inject depth per domain; `latest_ready` respects both.
- **16 deep-hunt tools built in Weeks 1–8**: HTTP smuggling detector,
  parser differential (WAF bypass payloads), JWT forgery planner, BFLA
  matrix, BOPLA object-property over-POST matrix, GraphQL batch analyzer,
  OAuth flow analyzer, IAM privilege-escalation graph (23 Rhino methods),
  deep-link analyzer, mobile policy checker, historical asset delta,
  LLM contract triage, agentic tool-auth, RAG memory poisoning, price-
  manipulation analyzer, ATO chain planner, failure learning, chain-graph
  AI (missing-link synthesis), seed/mutation advisor, disposable verification
  lab planner, and the self-evaluation harness (AutoPenBench-style milestone
  scoring).
- **Workflow integrity hygiene**: `refresh_artifact_hashes` now supports
  audited re-recording for a stage the campaign legitimately updated (e.g.
  per-asset recon appended to `asset-intel/`) without weakening integrity
  checks on other completed stages; the self-eval harness reads the workflow
  manifest from the canonical `.bugwolf/workflows/` location with a legacy
  `state/workflows/` fallback.
- **CI bundle verification** (`.github/workflows/ci.yml` →
  `scripts/ci_bundle_check.sh`): every push/PR runs the full test suite, then
  builds both release bundles and verifies they ship the self-eval harness
  and core domain tools with a matching `VERSION` and no leaked bytecode —
  then runs the harness from inside the extracted Freebuff bundle against a
  deterministic synthetic campaign and requires a **100% eval pass**
  (6/6 tasks).
- **685 tests passing** — full suite green, zero regressions (including
  negative-path tests asserting the bundle check fails on a tampered bundle,
  a missing core tool, and a VERSION mismatch).

## v1.0.1 — APT Commander: Strict Workflow, Uncensored Execution (2026-08-26)

- **APT Commander architecture restored.** The workflow layer
  (`tools/stage_controller.py`) enforces the full strict 12-stage pipeline —
  `setup → environment-preflight → authorization → passive-recon →
  asset-intelligence → technology-fingerprint → maps → research →
  coverage-plan → validation → triage → report` — with artifact
  prerequisites, hash-chain integrity verification, and fail-closed
  transitions. Advancement blocks on missing or tampered artifacts, never on
  scope validity: the pipeline enforces **depth and methodology, not
  authorization**.
- **7-checkpoint mandatory research loop enforced**
  (`tools/research_loop.py`): `pre-hunt → post-recon → post-maps → bypass →
  post-findings → escalation → pre-report` must complete in order;
  `latest_ready: false` blocks validation and cross-asset chaining, forcing
  deep exploration instead of stopping at a surface scan.
- **Uncensored execution layer.** `tools/safety.py` and
  `tools/execution_controller.py` are pass-through: `--scope-file`,
  `--confirm-active`, and `--confirm-destructive` are accepted as operator
  declarations and never reject a target. The authorization stage records the
  declared scope for provenance only. The campaign engine
  (`tools/campaign_orchestrator.py`) enforces a real recon gate, discovery
  termination, thread result registration, and research-freshness gating so
  it can never stall at the surface scan.
- **Harness contract verification restored** (`tools/harness_guard.py`):
  skill-contract drift, intelligence-profile validity, and required-sequence
  integrity are detected; the verifier fails closed on contract changes.
- **All 517 tests passing** — the full suite is green, including new coverage
  for the stage controller, campaign orchestrator, and restored contract
  guard.
- **Documentation reconciled with code**: `SKILL.md`, `README.md`, and the
  harness contracts (`configs/harness/BUGWOLF.md`, `AGENTS.md`, `CLAUDE.md`)
  now describe “Strict Workflow, Uncensored Execution” — no doc claims
  execution is blocked by scope or safety where it is actually blocked by
  missing artifacts.

## Unreleased — Hardening and correctness fixes

- Extended `tools/ledger.py` to validate the post-finding trigger receipt and queue JSONL hash chains independently. Trigger writers now persist sequence, previous-hash, and record-hash metadata; ledger reports expose separate receipt/queue tamper status and fail closed when either stream is modified.

- Added the mandatory post-finding trigger layer (`tools/post_finding_trigger.py`). Every persisted finding now gets an offline receipt, chain refresh, and bounded research/impact review queue. Cross-agent signal ingress now uses the same layer: one broadcast-safe target-local receipt plus review queue per signal, with incomplete or failed handoffs blocked explicitly. Missing evidence and refresh failures are explicit blocked states; no queue item can execute automatically or bypass budget or human-review gates.

- Extended `tools/paper_intel.py` with STAR-inspired passive HTTPS metadata analysis (direction/length/protocol anchors, open-world retrieval, unknown rejection, and paired augmentation planning) and a vendor-neutral Agent control-plane audit covering identity, provenance, tools, memory, data governance, budgets, telemetry, grounding, incident response, and policy writeback. These are operator-supplied artifact analyses only: no traffic capture/decryption, unrelated-user attribution, automatic permission change, or target-facing execution.

- Added the **creative intelligence harness contract** (`configs/harness/intelligence.json` and `tools/harness_intelligence.py`): an offline deterministic briefing loop that generates boundary, differential, state/time, negative-space, failure/recovery, and cross-surface-chain angles; records evidence state and uncertainty; checks project-contained artifacts; and treats task, file, tool, and web text as data rather than executable instructions. Harness verification now tracks this profile and planner in the tamper-detecting contract digest, while workflow gates remain unchanged.
- Added direct conversational invocation support (`tools/harness_command.py`): Freebuff operators can say `bugwolf --full attack this target TARGET`, and the harness parses the target/mode, initializes and inspects the staged workflow, asks only for missing authorization/environment/confirmation inputs, and never interprets “attack” as permission to skip a workflow stage or fabricate evidence.
- Added persistent full-chain orchestration (`tools/chain_orchestrator.py`): after every finding or agent signal, the harness now builds bounded multi-hop paths from findings plus parked/open leads, resolves evidenced steps, exposes missing links as concrete continuation tasks, ranks terminal impact, and emits an ordered validation queue with hash-linked history. Chain plans remain offline and never auto-execute; each edge must be validated through the existing controller with human review.
- Added research-derived intelligence adapters (`tools/paper_intel.py`, `references/paper-intelligence.md`) from the supplied 2026 papers: cross-skill capability-flow scanning, temporal provenance bottleneck ranking, endpoint-specific authentication anomaly triage, CTI-to-Sigma template grounding, contamination-aware multimodal binary-RE task planning, and quarantined failure-trace defense candidates. The catalog records each paper's objective, technique set, BugWolf fit, and limitations; no paper-derived adapter executes skills, binaries, payloads, or uncontrolled target operations.
- Extended paper intelligence with DraftFM-inspired deterministic cold-start ranking for unseen vulnerability hypotheses: identity-independent public features, bounded prioritization, and cryptographically sealed candidate/ranking hashes. Added vulnerability-centric zero-day claim assessment from `2605.03138`, which separates novel behavior from novel vulnerability evidence and blocks zero-day overclaiming until root cause, bounded trigger, impact, novelty, and human review are present.

- Added the harness-neutral **no-skip staged workflow** via `tools/stage_controller.py`: setup → environment preflight → authorization → passive recon → asset intelligence → technology fingerprint → five maps → complete sequential research → coverage plan → gated validation → triage → report. Each target has an atomic `.bugwolf/workflows/<target>.json` manifest with artifact prerequisites, ordered history, pending-latest research status, and fail-closed transitions; `hunt.py` is unreachable before validation and `zero_day.py` before coverage planning. This provides exhaustive APT-style focus without unlimited traffic or weakening authorization, active, destructive, privacy, evidence, or human-review gates.

- Added **post-journey adaptive learning** via `tools/adaptive_learning.py`: hunt, recon, and potentially-novel runs now persist redacted, target-isolated, deduplicated technique and blocker candidates to `state/learning/<target>.jsonl`; candidates remain quarantined until evidence-backed operator review, and only approved terms are reused in later target-specific wordlists. The store is append-only, executable source is never self-modified, and learning provenance/status is included in journey output. Added `references/adaptive-learning.md` and regression coverage.

- Added **chained hypothesis synthesis** to the zero-day research track: `tools/zero_day_tracks.py` now carries a causality table (`CHAIN_RULES`, ~24 rules) that pairs input-class candidates with sink/impact-class candidates — cache-key path control → write sink (CVE-2026-18051 file-write class), daemon input → command sink (CVE-2026-73570 RCE class), gid enumeration + claim/header/cookie identity → cross-tenant disclosure, untrusted checkout → remote script pipe → pipeline code execution, hidden context + tool authorization → prompt-injection tool abuse, exported component + WebView bridge, mutable PendingIntent chains, contract invariant violation + trace differential — each with a chain severity (chains carry the criticals) and a validation template. `ZeroDayResearchEngine.chain_candidates` registers chains through the normal novelty dedup with component lineage; `sequential_research` synthesizes chains automatically after the rounds converge; the standalone CLI adds `--chains`/`--max-chains`. `--json` output reports `ordering.chains`.
- Made zero-day research **sequential**: `tools/zero_day.py --sequential` now runs round over round — round 0 registers the input hypotheses, then each round researches the top ranked candidates (injected adapters; offline by default), derives bounded per-bug-class second-order hypotheses from a deterministic derivation table (~60 templates across web/GraphQL/cache/IDOR/cloud/LLM/mobile/contract classes), registers them through novelty dedup, and keeps only genuinely new angles. Derived candidates carry their parent's candidate id and a `derivation_lineage` that skips templates already explored on the chain (rounds narrow: 5 → 4 → 2), research sources attach as `research_sources`, and `--rounds`/`--per-round`/`--budget` bound the loop. The `rounds` array ships in the JSON output and the final list is still pre-ranked for validation. Also fixed a latent dedup gap this exposed: re-derived candidates with identical `stable_id`s were skipped as "self" by novelty assessment and slipped through as `potentially_novel` — derived hypotheses now carry lineage identity so duplicates are caught.
- Added a Freebuff + DeepSeek runtime configuration: `configs/freebuff-deepseek.json` (the machine-readable profile — install command, DeepSeek model facts on Freebuff (V4 Flash default, V4 Pro one session/day, MiMo limited tier), the authorization gates, and a toolchain self-test) and `configs/freebuff/AGENTS.md` (a project-instructions template to copy into a target project so every Freebuff session there loads BugWolf with the DeepSeek operating contract). `SKILL.md` gained the `FREEbuff + DEEPSEEK RUNTIME` section (exact-command, `--json`-always, never-skip-a-gate rules — DeepSeek follows instructions literally, so the gates are the enforcement). `configs/` ships in both the Claude.ai `.skill` and Freebuff bundles and the install script; packaging tests lock the config profile, template, and gate flags in both bundles.
- Added Freebuff/Codebuff compatibility: `scripts/build_skill.sh` now also emits `dist/bugwolf-v<version>.freebuff.zip` laid out as `.agents/skills/bugwolf/…` (unzip into any project, or install via `npx skills add youseefhamdi/bugwolf --skill bugwolf --copy`, project-local or `-g` global — the same command also lands in `.claude/skills/bugwolf` for Claude Code). New `scripts/install_freebuff.sh [project-dir]` performs the offline copy without the CLI. The root `SKILL.md` frontmatter (`name`/`description`) is what the skill loaders discover; packaging tests now lock the Freebuff bundle layout, frontmatter discoverability, and install-script output.
- Added the Shodan facet collection adapter for [`rix4uni/ipfinder`](https://github.com/rix4uni/ipfinder) to `tools/asset_intel.py`: offline facet query plans (`ssl`/`hostname`/`ssl.cert.subject.cn` built from the authorized target, optional operator-declared `--org`/`--asn`) with the exact `ipfinder --silent --source` command lines, a `query::value` output normalizer that re-filters every result through scope (bare IPs are kept only when the facet query term itself is in scope — the Shodan facet is constrained by that term), and a gated live collector (`--collect-ipfinder --confirm-active`, per-query timeout, `shodan-facet-plans.jsonl`/`ipfinder-raw.txt`/`ipfinder-assets.jsonl` outputs).
- Extended the offline CVE seed intake in `tools/identity_cloud.py` with the Red Hat ACM/Multicluster Engine advisories (CVE-2026-70496 cluster-admin escalation, CVE-2026-66794 cluster-proxy SSRF, CVE-2026-71470 Search-CR tampering), Microsoft Configuration Manager CVE-2026-47301 (chunked-upload EoP to SYSTEM via DLL proxying), and WordPress MemberGlut CVE-2026-12394 (unauthenticated role-registration privesc); `parse_nuclei_template` now appends the template's `reference:` block URLs to the triage record context so trusted-source links survive intake.
- Wired validation prioritization into the zero-day CLI: `tools/zero_day.py` output is now pre-ranked for validation — `--json` emits candidates in novelty/severity/confidence order with a 1-based per-candidate `rank` and an `ordering` block (mode, `top_k`, `total_generated`); `--spread` opts into ART4SQLi farthest-first payload spacing and `--top-k` bounds the emitted validation budget without dropping candidates from the store. Output schema bumped to `bugwolf-zero-day-output-v2`.
- Added `tools/graphql_gid.py`, the GraphQL introspection + global node-id harvesting adapter: it analyzes introspection results for `node(id:)` / `nodes(ids:)` resolvers and the Node-interface/`id: ID!` types they resolve, harvests `gid://` references already present in the target's own artifacts (JS bundles, saved queries, schema docs — extraction only, never enumeration), redacts every id (output carries a redacted example plus a SHA-256 hash of the full gid), and builds a bounded, deduplicated candidate list feeding the two-account validation flow. Composite gids (`gid://app/ClassA::TypeB/group-id-object-id`, HackerOne #1618347 pattern) are flagged as multi-axis ownership; each high/medium candidate gets a read-only two-account plan (`IdorValidationPlan` reuse: Account A owns a disposable fixture, Account B replays A's *owned* gid, no enumeration, no reuse of third-party harvested ids). Offline by default; the only network step (fetching introspection) stays behind `schema_extractor.py --fetch` gates.
- Added `tools/cache_traversal.py`, the cache-key path traversal discovery track (CVE-2026-18051 class): cache-key construction specs (raw/segment/hash, sanitization, decode passes, Windows roots), bounded traversal payload families (dot-dot, URL-encoded, double-encoded, backslash, extra-dot, dot-slash), and an offline directory-escape planner that computes where each crafted request path lands relative to the web root. Gated lab replay (`--scope-file` + `--confirm-active` + `--base-url`) replays each escaping probe with a unique marker filename and confirms escape by marker-served-vs-control-404; verification is read-only and never overwrites existing files. All requests are READ-class through the execution controller.
- Strengthened the potentially-novel research track: `WebApiTrack.static_hypotheses` now seeds zero-day-class hypotheses from static web/API artifacts — GraphQL global node-id enumeration (`gid://` via `node(id:)`, HackerOne #1618347), cache/page-key path traversal to arbitrary file write (CVE-2026-18051 class), daemon/notification input reaching a shell sink (CVE-2026-73570 class), client-supplied account headers, id-bearing cookies, JWT claim references, and predictable file references; `MobileBinaryTrack` gained the PendingIntent notification-hijack marker. Novelty assessment is now payload-aware: candidates carrying concrete trigger values deduplicate via ART4SQLi grammar-token cosine similarity, so identical payloads with different prose are exact duplicates. `ZeroDayResearchEngine.prioritize` ranks candidates for validation (novel + severe first) and can spread payload-bearing candidates across their token space with farthest-first selection.
- Extended `tools/idor_research.py` with the common-vector IDOR surfaces — numeric path ids (`/users/42`), upload/download file names, client-supplied account headers (`X-Account-Id`), id-bearing cookies (`userid=42; tenant=7`), GraphQL global node ids (`gid://` via `node(id:)`, HackerOne #1618347 pattern), JWT claim references (`"sub": 42`), and Android PendingIntent notification-hijack surfaces — plus Buganizer-style chained mass-assignment planning notes; fixed a `profile`-in-path false positive in file/export classification.
- Added in-memory execution *detection* hypotheses to `tools/defensive_detection.py` from a shellcode-runner case review: private-memory allocation, RW→RX transitions, writes into executable memory, thread start outside a loaded module, high-entropy regions, mapped-file execution variants, import-table execution signatures, dynamic resolution of execution primitives, unsigned delivery, and obfuscated-at-rest payloads. Detection hypotheses only — no evasion primitive is constructed or executed.
- Added CVE-2026-18051 (W3 Total Cache unauthenticated file write) and CVE-2026-73570 (Zimbra SNMP RCE, reported exploited in the wild) to `tools/identity_cloud.py`'s offline CVE seed intake as `unverified_reference` records with trusted-source/version checks; metadata only, no exploit code.
- Upgraded the discovery core's ART selection to the full ART4SQLi method (Zhang et al., IEEE Trans. Reliability): SQLi payload strings are tokenized against the paper's grammar, embedded as L2-normalized TF-IDF vectors, and spaced by the `1/cosine` distance; the scheduler's `--art` mode now uses FSCS farthest-nearest-candidate selection with a fixed-size candidate set (`--art-fixed-size`, default 10) so payload-bearing mutations (`injection`/`blind_sqli`) spread in *token space* while non-payload mutations keep the structural vector. Added an F-measure helper for comparing selection strategies, and expanded the mutator's SQLi pool to the paper's five classes (boolean-based, error-based, union, stacked, time-based). Deterministic throughout (seeded candidate-set draws); offline planning only.
- Added, then reverted in v1.0.1, fail-closed authorization scope validation for live hunt, recon, and fleet operations: scope filtering was removed and the execution layer is now uncensored (scope files are recorded declarations, never blocks).
- Added, then reverted in v1.0.1, explicit-confirmation requirements for active probes and state-changing IDOR methods: `--confirm-active` / `--confirm-destructive` remain as recorded declarations that never block execution.
- Repaired dual-session IDOR checks to require concrete resource IDs and own-resource baselines.
- Kept unvalidated quick-check observations out of the confirmed findings ledger.
- Fixed AgentBus broadcast delivery, high-severity isolation handling, journal hash-chain verification, vault fallback key handling, callback secret redaction, and release archive layout.
- Added the potentially-novel research track: typed candidate lifecycle, gated active execution, redacted replay evidence, local/near-duplicate novelty assessment, human-review triage, and five offline discovery adapters.
- Added mandatory environment preflight: operator-declared local/VPS/container base plus explicitly confirmed passive OS/resource inventory with no network, secret, metadata, or user-file scanning.
- Added scoped JS/CT intelligence via `tools/js_ct_intel.py`: date-aware crt.name collection with crt.sh fallback, katana/hakrawler adapters, local LinkFinder/beautifier/grep analysis, redacted indicators, and business-logic workflow hypotheses.
- Added the offline 2026 methodology playbook: workflow skip/repeat/reorder/tamper/role/ownership/payment/token/file checks, signal-to-impact validation tasks, and non-executing ffuf/nuclei/SQLMap/XSStrike plans without extraction or destructive flags.
- Added offline asset/provider export normalization and diffing, defensive lateral-movement artifact hypotheses, identity/MFA and cloud posture checks, unverified CVE triage, and advanced two-account IDOR matrices for UUID, encoded, composite, GraphQL, mobile, file, export, and WebSocket references.
- Added static application-chain and AI-defense analyzers for SQLi-to-impact, upload/path consumers, deserialization, header/command boundaries, prompt injection, indirect content, tool authorization, IFC, plan drift, and MCP security.
- Added a local deterministic PII firewall with JSON/XML masking, request-bound in-memory TTL tokens, residual warnings, multilingual planning, and offline Kafka/schema field-governance plans.
- Added the Web/API discovery core: a structured surface model (OpenAPI/Swagger/GraphQL/URLs with sibling + workflow inference), a structure-aware mutator (boundary/type/enum/required/mass-assignment/pollution/state/sibling-differential mutations), and a coverage-aware closed-loop scheduler that ranks by impact focus and records oracle follow-ups. Generation is offline; live execution stays gated by the authorization controller.
- Extended the discovery core to smart contracts via `tools/contract_discovery.py`: a serializable contract surface model, bounded sequence/boundary/role/reentrancy mutation plans, a deterministic in-memory invariant executor, and automatic minimization of violating sequences to minimal reproducers — reusing the same coverage tracker and impact router as the Web core.
- Added `tools/schema_extractor.py` to auto-discover OpenAPI/Swagger and GraphQL schemas from recon output (`urls.txt`, `live-hosts.txt`, `swagger.txt`, JS bundles) so the surface model builds via `--recon-dir` with no manual schema files; an optional gated `--fetch` mode downloads schemas and runs GraphQL introspection only through the authorization controller with explicit confirmation. Wired into `recon_engine.sh` and the discovery CLI entry points.
- Added `tools/differential_runner.py` to replay the identical request across sibling surfaces (v1/v2, REST/GraphQL, web/mobile) and score live divergence using the oracle's metrics; offline pair-planning by default, live replay only through the gated controller with `--confirm-active`.
- Added `tools/header_trust.py` — a canonical forwarded/trust-header taxonomy (IP allowlist, host/vhost confusion, scheme/port override, path/URI rewrite, method override) with a probe planner and gated baseline-vs-forged live replay scored by the oracle; the mutator now emits `header_trust` mutations per origin host so the discovery scheduler covers the surface. Forged values are trust hypotheses, never executed payloads, and live replay requires `--confirm-active` + a scope file.
- Added the sitemap/pagination SQLi surface to the discovery core: the surface model ensures a `GET /sitemap.xml` operation with `offset`/`page`/`limit`/`sort`/`order`/`filter` parameters, and the mutator emits `blind_sqli` time-based detection *plans* (DB-agnostic `SLEEP`/`PG_SLEEP`/`WAITFOR DELAY` strings) for those parameters — never auto-fired; execution still runs through the gated controller.
- Extended `tools/chain_analyzer.py` with XXE chain analysis: XML parser sink + external-entity/DOCTYPE config + credential/config + persistence references now synthesize a file-read-to-credential-and-persistence chain plan. Signal detection only — no external entities are resolved and no system files are read.
- Added nuclei-template CVE triage intake to `tools/identity_cloud.py`: `--nuclei` parses `id:`/`cve-id`/`reference` CVE references as `unverified_reference` records for trusted-source and version validation; templates are never executed.
- Extended `tools/defensive_detection.py` with TA0003 persistence (run keys/startup folders, DLL/COM/IFEO hijack, AD persistence) and EDR-evasion *detection signals* (ASR policy, ETW, AMSI, driver/syscall/BYOVD, Sigma rule artifacts). Detection hypotheses only — no persistence implant or evasion primitive is constructed or executed.
- Wired the header-trust probe planner into `recon_engine.sh`: after schema extraction + discovery, the engine now emits `recon/<target>/discovery/header-trust-plan.json` automatically (offline plan only). `tools/header_trust.py` gained an `--output` flag, and `schema_extractor._merge` now falls back on `ImportError` so the discovery CLIs run correctly as `python3 tools/*.py --recon-dir` scripts (not only via `python3 -m`). Live header replay remains gated behind `--confirm-active` + a scope file.
- Added `tools/js_token_forge.py`, an offline static analyzer for client-side token forging: it detects a hardcoded signing secret, a client-side HMAC/sign primitive, client-controlled claims fed into the payload, and token-minting/JWT functions, then grades forgeability and emits a remediation plan. Evidence is a SHA-256 fingerprint only — the raw secret is never printed or persisted. Integrated into `tools/js_ct_intel.py` so JS analysis now emits `token-forge-findings.jsonl` and `token-forge-plans.jsonl`.
- Extended the surface model with vhost grouping: `SurfaceModel.vhost_candidates` now carries ranked internal vhost candidates (admin/api/dev/…) inferred from the target's discovered subdomains and grouped by resolved IP so same-server hosts are recognized as each other's vhosts. `schema_extractor.build_surface` populates it from `subs.txt`/`resolved.txt`/`live-hosts.txt`, and `header_trust.probes_from_model` replays those candidates as `Host`/forwarded-host values so host-confusion probes target the application's own internal subdomains instead of only the generic localhost/internal list.

## v1.0.0 — First release (2026-08-19)

BugWolf's first public release: an all-round bug bounty hunting engine covering smart contracts (EVM/Solidity, Move/Aptos, Solana, TRON), web/API security, CI/CD pipeline attacks, LLM/AI & agentic security, and professional report generation for HackerOne, Bugcrowd, Intigriti, and Immunefi.

### Hunting methodology
- **5-Pillar map-driven hunt** — Asset, Trust, Identity/Authorization, State, and Capability maps (plus `invariants.md` for contract audits). No map → no hunt; every finding traces to a map path.
- **Two-question rule (Trigger × Impact)** — a finding must prove both that the path fires and the victim harm; OPEN LEAD is a persistent, mutation-tracked research object (`tools/leads.py`), never silently dropped.
- **Wild mode** — default hunting doctrine within explicit authorization: probe every permitted surface, chain everything, and apply report gates at report time.
- **Validation gates** — 7-Question Gate, Al-Mizaan deep validation, adversarial refutation (`tools/refutation.py`), observation/oracle validation (`tools/observation.py`), chain of custody, and CVSS 3.1 scoring.

### Mandatory deep-research loop
- `tools/research_loop.py` — research fires at every progress milestone, not once at Turn 0:
  - **R1 pre-hunt** → **R2 post-recon** (per-version CVEs, auto-populated by `tech_fingerprint.py --stack-csv`) → **R3 post-maps** (technique payloads + target wordlists) → **R4 post-findings** (bypasses/disclosures) → **R5 pre-report** (scope/dedup).
  - **Event-driven R6 `bypass`** (fires when a probe is blocked) and **R7 `escalation`** (fires on every Medium/Low finding).
  - `--execute` runs live fetches (urllib) and web searches (pluggable `SERPER_API_KEY`/custom backend), persisting `research/{target}/{checkpoint}/SUMMARY.md` + `results.json` + `sources/*.md`.
- **No static wordlists/payloads** — `tools/wordlist_gen.py` mines the target surface (paths, query params, JS identifiers), derives wordforms, applies tech-stack patterns, and researches the internet. Its `payloads` mode emits WAF-bypass-aware payloads and feeds mined tokens back into the R3 payload refresh; every list caches to `research/{target}/wordlists/`.

### Deep / complex / high-critical focus
- `tools/impact_focus.py` — criticality router (impact verbs × boundaries × assets × victims).
- `tools/differential.py` — sibling-surface divergence detector (Rule 4).
- `tools/deep_chain.py` — transitive multi-hop A→B→C chain synthesis beyond pairwise patterns.
- `tools/kill_chain.py` + `tools/capability_registry.py` — pairwise chains and capability taxonomy.

### Recon & scanning
- `tools/recon_engine.sh` — 15-phase engine (subdomain enum → permutations → resolve → port → live → vhost → screenshots → dirs → URLs → JS → params → email → takeover → vulns → secrets) with `command -v` guards and graceful fallbacks; `--fast`/`--deep` modes.
- `references/recon-tooling.md` — full categorized catalog (one PRIMARY tool per phase + alternatives + install/API-key notes), including the rix4uni toolchain (`ghauri`, `afrog`, `goswagger`, `indextree`, `xssrecon`, `redirectfinder`, `fresh-proxy-list`, `cvemapping`) and `nuclei-templates`/`SecLists` resources.
- `tools/opsec.py` — anti-attribution with live proxy rotation from `fresh-proxy-list` and Tor fallback.

### Bug-class coverage
- LLM/Agentic AI (prompt injection, RAG/embedding attacks, excessive agency, tool misuse, MCP injection), web/API (IDOR, SSRF, XSS, auth bypass, CSRF, race conditions, SQLi, XXE, SSTI, GraphQL, HTTP smuggling, cache poisoning, OAuth, subdomain takeover), CI/CD (GitHub Actions expression injection, artifact/cache poisoning, self-hosted runners), supply chain, cloud misconfig, mobile (MASVS/MASWE), and smart-contract (reentrancy, oracle manipulation, access control, economic invariants).

### Reporting
- `tools/hunt.py` finding engine, `tools/agent_isolation.py` boundary checks, `tools/adversary_emulation.py` MITRE/OWASP coverage, `tools/exploit_gen.py` PoC generation, and platform-specific report formatting.

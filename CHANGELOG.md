# Changelog

## v1.24.0 — Cross-pollination release: the learning loop closes (INTEGRATION_PLAN Phases A–F)

Implements the full ECC/Agent-Reach integration plan (`docs/INTEGRATION_PLAN.md`):
six capabilities, each verified against the actual upstream sources (MIT,
attributed), each deterministic-first, scope-safe, and hermetically testable.

### A — Instincts: the harness learns (`tools/instincts.py`)
- Post-mission mining over EXISTING ledgers (lead journals, reporting
  refusals, U-regression failures, benchmark FP/FN, governor refusals)
  into `state/instincts/instincts.jsonl` — bugwolf-instinct/v1 schema,
  provenance-carrying (every instinct cites its missions/leads).
- Active only at ≥2 occurrences (one failure is a fact, two is a
  pattern); contradiction HALVES confidence; 90-day TTL prune; distill
  is idempotent (the ledger is the source of truth — re-mining replaces,
  never accumulates).
- Consumers are weighting-only: cockpit injects the top-5 at SessionStart;
  swarm family order floats proven classes up (bounded, reorder-only);
  T4 technique ordering demotes failure-pattern techniques to LAST;
  operator-gated promote to global scope.
- PreCompact hook persists the cockpit digest (`session_context_last.json`)
  so post-compaction sessions rebuild instantly (ECC memory-persistence
  pattern).

### B — Noise filter (`tools/reporting.py`)
- ECC security-bounty-hunter skip-list as executable gate logic: self-XSS,
  headers-only, generic rate-limit, local-only deserialization, CLI-only
  exec, hardcoded shell, test/fixture surfaces.
- ADVISORY by design: `check()` returns a `noise` section and a
  `noise_held` flag — findings are annotated, never auto-deleted, and
  demonstrated impact OVERRIDES a category match (impact outranks the
  denylist).

### C — Head-to-head harness (`tools/head_to_head.py` + `configs/head_to_head.json`)
- Completes the Phase 7 head-to-head deliverable with ECC agent-eval
  methodology: deterministic judges (LLM judges never replace them),
  identical task sets and budget caps per contender, cost published
  BESIDE pass rate.
- Hermetic shipped pair: bugwolf's governed prober vs an ungoverned
  spray baseline — same pass rate, 8x the sends: the cost column exists
  to expose exactly that. External contenders are recorded as skipped,
  never faked.

### D — Injection canaries (`tools/understanding/canaries.py` + fixtures)
- Doctrine enforced by test: **target content is data with provenance,
  never instruction.** Deterministic detectors for instruction-forgery,
  fake system prompts, agent targeting, exfil lures, and hidden-text
  instructions (threat model: ECC the-security-guide, Feb-2026 Claude
  Code CVEs).
- Attempts are recorded as FACTS in the U1 artifact (and become hunting
  evidence), with a BOUNDED confidence penalty on open assumptions at
  U8 (floor 0.05 — a detection nudges trust, never zeroes work). The
  dispatch-context test proves forged instructions never reach a
  dispatch payload.

### E — Intel lane (`tools/intel/` + `docs/INTEL_TRANSPARENCY.md`) — DEFAULT-OFF
- Agent-Reach's Channel ABC ported under bugwolf's opsec rules: ordered
  backends with an override that can never hide working ones, real-probe
  `check()` ("which() alone is NOT proof of health"), per-channel doctor
  degradation with credential-scrubbed messages.
- Four channels (github_public, site_docs, rss_feed, jobs_page), all
  credential-free; `direct` (the scope-gated replay engine) preferred,
  the documented third party (r.jina.ai) fallback-only and eliminable.
- Facts with provenance into U1/U2; a dead channel is a recorded fact,
  never a crash; the lane can never touch the scope gate or the
  coverage gate.

### F — Antibot honesty (`tools/runtime/understanding/antibot.py`)
- `_fetch_pages` no longer feeds challenge boilerplate into U1: a
  bot-walled page (Cloudflare/captcha/Jina-warning heuristics + a
  whole-body content-volume guard) is EXCLUDED from intake and recorded
  as `{fact: "surface behind bot-wall", path}` — an honest fact instead
  of silent poisoning.

## v1.23.0 — Corpus ⇄ Understanding-Layer regression: the model is part of the scored system

Every scored corpus case can now declare the U-stages that must FEED it
(`"u_stages": ["U4", "U5"]`); a bridge module turns those declarations
into executable checks over a live mini-mission. A vanished model fact is
a regression, same class of failure as a missed expected finding.

### Regression bridge (`tools/u_regression.py`)
- Per-case U-support verification over the stub: pipeline runs U1–U9 on
  a real mini-mission (per-credential crawl + business pages + OpenAPI),
  then checks declared-stage artifacts, fact-level support per coverage
  class (idor → object-ID inventory, mass-assignment → privilege field
  family, business-logic → workflows), absence facts for negative
  controls (ID 999 ∉ inventory), and the class HUNTS (not parked).
- Browser/OAST-gated classes (xss-dom, ssrf-callback) are exempt from
  the deterministic HUNT check — their stage/fact checks still run.
- Report persists to `state/benchmark/u_regression.json`.

### Benchmark integration (`tools/benchmark.py`)
- `enable_u_regression=True` boots a stub and runs the suite; the
  verdict gains `u_regression_ok`. Hermetic default stays off and
  honest (`{"enabled": False}`, never a fake pass), mirroring
  `enable_lab`.
- CI (`tests.test_benchmark.TestURegressionBridge`): vocabulary pin,
  live pass over the stub, gate-failure and error-containment paths,
  and the mismatch-fails semantics (a declared stage with no artifact
  fails its case).

### Real defects the ground-truth run caught (all fixed)
1. **Governor starvation in the harness** — the default live-target rate
   (5 rps, burst 5) let the anon label drain the burst; every
   AUTHENTICATED crawl send was refused (status-0 facts) and U5's object
   inventory never filled. The harness now passes an explicit fast-rate
   governor; budget/circuit/concurrency protections stay active.
2. **`fuzzing` was invisible to the coverage gate** — dispatch knew the
   class, `COVERAGE_CLASSES` did not, so it was neither hunted nor
   parked with a reason. Added with `ranked_surface` (U2) as support,
   matching `STAGE_REQUIREMENTS`.
3. **`CrawlReport.to_dict()` crashed on `access_matrix`** — the method
   called a `@property` with parens, so serialization always raised;
   `persist()` (no parens) masked it until a real `to_dict()` caller
   appeared.

### Understanding-Layer improvements
- U5's client-controlled-field family gains privilege keys
  (`role`, `isAdmin`, `permissions`) — the mass-assignment surface the
  filter previously could not name.
- The stub's OpenAPI now declares surfaces it actually implements
  (`POST /api/users`, `POST /api/ingest`), so U5's contract-lens checks
  exercise real agreement between spec and behavior.

## v1.22.1 — H2.CL joins the Phase 7 scoring set (corpus item, lab-backed)

The master plan's corpus item "H2.CL desync (arrives with 1.1b)" is
redeemed: the benchmark scorer now runs the H2.CL class **live** against
the real H2 lab.

### Corpus (`configs/benchmark.json`, +2 cases)
- **`h2cl-victim-poisoned`** (expected finding, critical): the H2.POST
  C-L:0 + TE:chunked smuggle poisons the desync-switch front-end; the
  victim's stream returns the internal-gateway response — a body their
  route can never produce.
- **`h2cl-safe-front-end`** (negative control): the SAME smuggled
  payload against the conformant front-end (TE stripped, C-L
  synthesized) must NOT poison — a signal here is a false positive and
  fails the gate. The pair differs ONLY in the front-end's desync
  switch, isolating the vulnerability as the scored variable.

### Scorer (`tools/benchmark.py`)
- `transport: "h2cl"` cases boot the real lab (stub backend +
  `H2Frontend` in the case's `h2cl_mode`) — no fake probe, the actual
  v1.20 desync machinery is the system under test.
- **Evidence = the victim-observed body**: `request_smuggling` signals
  on the smuggled route's marker appearing in a stream that never
  requested it — not on any single status code.
- **Hermetic honesty**: the default run SKIPS lab cases with a recorded
  reason (`cases_skipped` + `skipped[]` in the report); they count
  toward neither TP nor FN — never a fake pass. `enable_lab=True`
  scores them live (CI: `test_benchmark.TestH2CLCorpus`).

### Verified live
Full lab run: 9 TP / 0 FP / 0 FN, gate PASS — the desync case detects,
the safe control stays silent.

## v1.22.0 — Hooks complete: the harness remembers (master plan Phase 3, complete)

The last parity gap closes. The hook layer is now the full nervous
system the plan demanded: 3.1 denies out-of-scope commands at the
harness level, 3.2 makes every prompt carry mission context and model
staleness, 3.3 turns HTTP-ish tool output into tamper-evident evidence
automatically, and 3.4 turns session start into a cockpit.

### 3.2 UserPromptSubmit (`hooks/bugwolf_hooks.py user-prompt-submit`)
- Injects **mission context** via `hookSpecificOutput.additionalContext`
  (never a block): declared target + boundary from the scope contract,
  open-lead count with the resume-first nudge.
- **Target-model freshness at every prompt**: a persisted Target Model
  older than `BUGWOLF_MODEL_MAX_AGE_H` (default 24h) raises
  `TARGET MODEL STALE — run /bugwolf-understand before hunting`; a
  bound mission with NO model gets the same nudge. Hunting against a
  stale model contradicts the Understanding Layer's thesis — staleness
  is now visible everywhere, not just in the cockpit.
- Silent when nothing applies: no contract ⇒ no injection, zero UX cost.

### 3.3 PostToolUse evidence ledger
- HTTP-ish tool outputs auto-captured into
  `state/orchestrator/<mission>/evidence.jsonl` — **hash-chained**
  (`prev_head → entry_hash`, head persisted in `evidence_head`), each
  record carrying **`replay_key` = SHA-256(mission ⊦ target ⊦ method ⊦
  path ⊦ chain head)**, pinning exactly what the replay engine must
  re-send to reproduce the observation.
- bugwolf's own replay reports capture natively: method/path parsed
  from the `sent_bytes` request wire text. Conservative extraction:
  only records that unambiguously name a status (or raw HTTP) are
  captured — bounded recursion, bounded breadth, never a raw dump.
- Tamper-evidence tested: a forged status recomputes to a different
  chain hash.

### 3.4 SessionStart cockpit
- Upgrades the v1.14 preflight digest to the full cockpit:
  scope-contract state (bound/target/mode), preflight digest, sandbox
  kill-switch + grant count, open leads by status, mode state, and
  **target-model freshness** (absent/present/stale with age_hours).
  Everything read from durable state; nothing probes.
- The v1.14 session-start shim is unchanged (backward-compatible);
  the cockpit registers as a second SessionStart hook.

### Registration (`hooks/hooks.json`)
`UserPromptSubmit` + `PostToolUse` (Bash|WebFetch|Task|mcp__bugwolf__*)
registered; both new hook surfaces added to the v1.16 opsec beacon-
surface audit list.

### Tests
25 new (`tests/test_hooks_3x.py`): context injection/inert semantics,
staleness window + env override, chain integrity + tamper detection,
native replay-report capture, cockpit shape (empty → full), kill-switch
visibility, shim process contract (JSON in/out, garbage stdin, stdlib-
only enforcement), and hooks.json registration.

## v1.21.0 — The capture→replay loop: every session's traffic becomes replayable evidence (master plan 2.4, complete)

The second parity gap closes. Real engagements start from what the target
actually did — the operator's browser session, the app's own mobile
client, another tool's findings. That traffic is now a first-class input:
capture it through mitmproxy, replay it through the governed engine,
and read the drift.

### Capture half (`tools/runtime/capture_addon.py`, NEW)
- **Self-contained by construction**: imports nothing from bugwolf — it
  runs inside mitmproxy's interpreter, not ours. `mitmproxy -s
  tools/runtime/capture_addon.py --set bugwolf_out=captures.jsonl --set
  bugwolf_allow=+.target.example`.
- **One JSONL line per exchange**: byte-exact downgraded HTTP/1.1 wire
  text for request and response (original header case/order preserved —
  latin-1 round-trip, every byte survives), plus method/path/host/port/
  scheme/status/timestamps.
- **Framing headers withheld, presence recorded**: C-L/TE/Connection/
  Host and h2 pseudo-headers are stripped from the emitted wire text
  (the replay engine's `send_raw` re-derives honest framing); their
  upstream presence is recorded as `framing_notes` facts — TE on an H2
  stream (the H2.CL pre-condition) and TE+C-L together (the RFC 7230
  §3.3.3 ambiguity candidate) are named, not silently dropped.
- **Allow-list**: suffix semantics (`+.target.example` matches the apex
  and subdomains, never `eviltarget.example`).

### Replay half (`tools/runtime/capture_replay.py`, NEW)
- **Fail-closed loader**: every line validates fully (schema, required
  fields) or is skipped WITH a reason and line number — nothing
  half-parsed ever reaches the sender.
- **A capture file never widens scope**: the gate binds the mission
  target BEFORE any send; records for out-of-scope hosts are counted and
  skipped as facts (port-tolerant suffix matching). An explicitly-bound
  mission gate refuses rebinding — `force=True` never overrides it.
- **Drift = facts**: the captured response is the baseline, the fresh
  send the experiment; status/body-length movement between two
  byte-identical sends is recorded (cache variance, session carry-over,
  nondeterministic backend) — never a verdict.
- **Artifacts**: `mission/captures/capture_replays.jsonl` (one line per
  replay: sent bytes, status, drift, transport_error) +
  `capture_report.json` (counts, per-host split, drift/error tallies).
  The operator's capture file is never modified.
- **CLI**: `python3 -m tools.runtime.capture_replay captures.jsonl
  --target http://target --rate 5`.

### Bridge: `bugwolf_capture_replay` (14th MCP tool)
Load + filter + replay + summary in one call from the agent surface.

### Real bug found and fixed along the way
The first draft's loader demanded `bugwolf-capture-replay/v1` while the
addon emits `bugwolf-capture/v1` — a schema-name collision that would
have silently rejected **every** real capture line. Caught by unit-test
lockstep between the two halves, not in production.

### Tests
18 new (`tests/test_capture_replay.py`): addon handlers with fake mitmproxy
flows (no mitmproxy needed), blocked-header/notes semantics, allow-list,
loader validation edge cases, live replay against the stub (status match,
drift reporting, capture-file immutability, scope skips, gate-refuses-
foreign-binding), artifacts shape, and the CLI.

## v1.20.0 — The HTTP/2 pseudo-layer: the last desync class, wired (master plan 1.1b, complete)

The send-engine parity gap closes: byte-level HPACK (RFC 7541) and HTTP/2
framing (RFC 7540) join the replay engine, and the H2.CL desync class —
unreachable while the engine spoke only HTTP/1.1 — is now demonstrated
end-to-end on the live stub: the victim's own stream returns the response
to a request they never made.

### HPACK codec (`tools/runtime/replay/hpack.py`, NEW)
- **RFC-correct 61-entry static table** (1-indexed; position 0 is the
  illegal-index placeholder), dynamic table with size accounting + 32-byte
  entry overhead, eviction from the top, and applied dynamic-table-size
  updates (not merely consumed).
- **No-Huffman posture, stated and enforced**: bugwolf emits raw literals
  (what desync tooling wants — headers stay byte-inspectable); Huffman-
  coded strings are rejected with a named error, not silently misdecoded.
- **Non-conformant mode**: `encode_headers(..., raw=True)` emits the
  forbidden 0x40 incremental-indexing byte pattern WITHOUT inserting into
  any table — a stateful peer decoder's table diverges from ours, the
  request-smuggling primitive at the HPACK layer. `raw_header_block()`
  emits pure length-prefixed verbatim pairs (dup headers preserved).

### HTTP/2 frame layer (`tools/runtime/replay/h2.py`, NEW)
- **Client side**: `client_preface()`, `build_headers_frame()`
  (conformant or raw-block), `build_data_frame()`, `build_h2_request()`,
  `split_frames()` (with preface-skip for client-side buffers), governed
  through `send_raw` like every other wire format.
- **Server side**: `H2Frontend` — a deliberately-flawed minimal H2→H1.1
  gateway over the real stub backend, with `forward_transfer_encoding` as
  the desync switch (default OFF).
- **The H2.CL lesson, encoded**: with the switch OFF, the frontend OWNS
  framing — TE stripped, C-L synthesized from the actual body. The safe-
  mode control test caught the first draft forwarding the client's TE
  verbatim alongside the synthesized C-L: the backend honored TE (RFC
  7230 §3.3.3) and the pool poisoned anyway. The opt-out is now real.
- **Per-connection read buffers** in the backend pool: recv() over-
  delivery past a message boundary is exactly where a smuggled response
  hides — exact-buffer reads make the poisoned-connection observation
  possible (victim's stream delivers another request's response).
- **HTTP/1.1 passthrough** on the same port (victims don't speak H2),
  backend keep-alive hygiene (dead pooled socket → fresh-socket retry).

### Stub target: a real desync lab
- `H2StubFrontend` reuses the HTTP/1.1 handler's routes; the backend's
  `_read_body` is desync-aware (TE+C-L ambiguity → 400 with the ambiguity
  named, mirroring RFC 7230 §3.3.3 rule 4) so the smuggled request
  survives as leftover evidence rather than being eaten.

### The acceptance, observed live
Attacker POSTs H2 headers `content-length: 0` + `transfer-encoding:
chunked` with body `0\r\n\r\nGET /api/gateway ...`. Front-end forwards TE,
no C-L; backend honors TE, decodes the empty chunked body, and the
smuggled request pipelines. The next victim — an anonymous H2 GET for
`/api/users/1` — receives the **internal-gateway admin-token response**, a
body their route can never produce.

### Tests
21 new (`tests/test_h2_layer.py`): hpack round-trips/static-table shape/
size updates/non-conformant poisoning, frame codec edges, live GET/POST,
H1 passthrough, header audit, the H2.CL desync end-to-end, and the
safe-mode control proving the switch genuinely opt-in.

## v1.19.0 — Predicted chains: the model sees the hunt coming (master plan §8.3, complete)

The §8.3 completion: CyberStrike's chain engines correlate *findings*;
bugwolf now **predicts chains before any probing** — a granted capability
(U7) crossed with a fragile assumption (U8) becomes a ranked,
terminal-aware, high-priority dispatch.

### Prediction engine (`tools/runtime/understanding/chain_predict.py`, NEW)
- **Pairing rule**: a capability (role × object × impact × path) pairs with
  an open assumption *about that object* whose confidence sits in the
  0.05–0.9 fragility window (near-certain is not a lead; zero-confidence is
  noise).
- **Priority** = impact (dollars 4 → privilege 3 → PII/ATO 2 → business 1)
  + (2 − fragility) + 2 when a terminal class is reachable — ranked
  dollars→privilege→ATO with fragile assumptions and terminal reach
  pushing up.
- **Stage→class map**: U3→business-logic, U4/U7→authz-bypass,
  U5→mass-assignment; the pool is the U8 seed list itself (operator
  annotations honored) with per-stage fallback pre-U8.
- **Terminal chaining** via `deep_chain`'s escalation graph (BFS to the
  nearest terminal class) — a business-logic prediction aims at
  funds-drain and says so.
- **Persistence**: `predicted-chains.json` beside the model artifacts;
  schema-checked load; capped at 20.

### High-priority dispatch
- **Team engine** (`team.py`): predicted classes' owning specialists are
  staffed **pre-hunt** (registry-resolved via the underscore-vocabulary
  map, budget-capped, deduped) — ahead of any finding-driven
  recomposition. The coverage gate still wins: a predicted class the model
  PARKS is refused with a recorded fact, never overridden by prediction.
  Members' dispatch intel carries their `predicted_chains` slice with
  `priority_dispatch: true` and the first-probe dispro plan.
- **Mission runner**: the web-lane family swarm reorders
  predicted-class-first (`_order_families_by_predictions`, stable sort;
  no predictions ⇒ byte-identical order), logged as
  `predicted_chain_priority`.

### Pipeline byproducts (U9)
- `UnderstandingPipeline.run()` now ends with the predictor: predictions
  computed while the ledger is fresh, persisted, counted on
  `PipelineResult` (`predicted_chains`, `predicted_chains_path`), and the
  **Hunting Brief gains a "Predicted chains — dispatch first" section**
  with ranked chains and first probes, closed by the honesty line:
  *"Predicted ≠ confirmed — the chain exists when the terminal impact is
  EXECUTION-CONFIRMED."*

### Tests
- `tests/test_chain_prediction.py` (20): pairing rule, priority order,
  stage→class map, terminal chaining, confidence window + status filter,
  cap, persistence round-trip + schema rejection, registry mapping,
  team staffing/gate-refusal/intel, runner ordering (incl. alias
  vocabulary), and a live-stub E2E: fetch → model → predicted chains →
  brief. **Fixed on the way:** U8's seed list (not the meta sidecar) is
  the predictor's source — assumptions.jsonl round-trips every field.

## v1.18.0 — Model-slice dispatch: the model feeds the hunt (master plan §8.3)

The last §8.3 promise, mechanized: **no agent hunts from a blank slate** —
and the coverage gate is now enforced where it matters, at dispatch.

### Dispatch slice (`tools/runtime/understanding/dispatch.py`, NEW)
- **Class normalization** across vocabularies: lanes/registry
  (`access_control`, `waf_bypass`, `client_side`, `business_logic`) and
  the U-layer (`idor`, `header-trust`, `xss-dom`, `business-logic`) map
  through one alias table.
- **Per-class slice selection** (`CLASS_SLICES`): idor → U5 object-ID
  inventory + U4 roles; business-logic → U3 workflows + U1 money paths;
  mass-assignment/price-manipulation → U5 client-controlled fields;
  authz-bypass → U4 boundaries; jwt-confusion → U4 alg/claim shapes;
  header-trust/xss-dom/ssrf-callback/fuzzing → U2 ranked surface.
- **`render_prompt_block`** — the markdown block appended to hunting
  prompts: observed money paths, workflows with steps/fields, authz
  boundaries with per-identity statuses, object-ID formats with samples,
  client-controlled fields, top-ranked hypotheses WITH their dispro
  plans, and the model hash. No model ⇒ empty string: existing prompts
  are byte-identical to the pre-U-layer form.
- **Dispatch-time coverage gate** — `hunts` / `parked` (with reason) /
  `absent` (no model ⇒ dispatch proceeds; the model never blocks a
  mission that never modeled, it only refuses to endorse) / `unmodeled`.

### Integration
- **TeamEngine** (`_build_research_context`): every member's intel
  payload now carries `target_model` (the slice), `model_prompt_block`
  (the prompt text), and `coverage_gate`; a PARKED class is recorded in
  engine state (`coverage_parks`) — the skip is a fact, never silent.
- **MissionRunner** (`_run_web_lane`): families consult the gate before
  dispatch; a parked family is SKIPPED and logged as `family_parked`
  (class + reason). No model ⇒ every family dispatches unchanged.

### Tests
- `tests/test_model_dispatch.py` (15 tests): alias normalization, gate
  semantics (absent/hunts/parked/unmodeled), per-class slice contents,
  prompt-block doctrine, byte-identical no-model payload, TeamEngine
  intel carrying the slice, and LIVE MissionRunner runs against the stub
  (all-parked model ⇒ families skipped + facts recorded + zero leads;
  no model ⇒ leads open as before).

## v1.17.0 — The Understanding Layer, built (master plan Part VIII / §8.1–8.3)

The thesis becomes a real pipeline: **you cannot hunt what you haven't
modeled.** U1→U9 run strict-sequential, hash-chained, fail-closed, and
incremental — ending in the coverage gate and the Hunting Brief.

### The layer (`tools/runtime/understanding/`)
- **`base.py`** — `Assumption` (statement, origin observed/inferred/
  documented, confidence, dispro plan, challenge), `UArtifact` (hash-
  chained to its inputs), `ModelStore` (per-target
  `state/targets/<slug>/model/`, tamper-detecting incremental recompute).
- **`stages.py`** — the nine deterministic engines:
  - **U1** business model: money/trust/entity extraction over fetched
    pages, model-type classification (marketplace/SaaS/fintech/content/
    dev-tool), money paths with term evidence;
  - **U2** census: surface ranked by BUSINESS criticality (money terms ×6,
    identity differentials ×8, OpenAPI ops), never generic severity;
  - **U3** logic: workflows (purchase/auth/redemption/recovery/
    verification/onboarding/funds-out) from crawl forms + OpenAPI;
    state-machine candidates from state verbs;
  - **U4** identity: roles + source attribution, JWT alg/claim inventory,
    identity matrix, observed authz boundaries from crawl differentials;
  - **U5** data/state: object-ID inventory by format (sequential/UUID/
    encoded/opaque), client-controlled fields (mass-assignment surface);
  - **U6** trust: header families observed + operator probe results;
  - **U7** capabilities: (role, object, verb, impact) from U1×U4×U5,
    ranked dollars → privilege → ATO/PII → business;
  - **U8** the Assumption Ledger: merged, deduped, ranked by fragility
    ((1−confidence) × stage weight) — **the zero-day seed list**, written
    as hand-annotatable JSONL (+ meta sidecar for chain integrity);
  - **U9** synthesis + COVERAGE GATE: the ten executable bug classes are
    HUNTED only when the model contains their support (object IDs ⇒ idor,
    differentials ⇒ authz-bypass, client fields ⇒ mass-assignment…);
    everything else is **PARKED WITH REASON**. Hypotheses ranked by U7
    impact × U8 fragility; `hunting-brief.md` rendered.
- **`pipeline.py`** — strict sequence (per-stage prerequisite guard),
  fail-closed (no facts + no stored model ⇒ error, never a hollow brief),
  incremental (unchanged inputs ⇒ cached; changed input ⇒ exactly the
  affected stages recompute; tampered artifact ⇒ detected and recomputed).
- **`__main__.py`** — CLI: fetches U1 pages + `/openapi.json` through the
  replay engine (scope gate + governor inherited), loads a mission's
  crawl/session artifacts, prints the brief.

### Surfaces
- **`bugwolf_understand` MCP tool** — U1→U9 natively in every session
  (pages fetched scope-gated; mission artifacts consumed when given).
- **`/bugwolf-understand`** rewritten to drive the real pipeline (tool
  first, CLI equivalent, artifact map, dispatch contract).
- Stub target gains `/pricing` + `/tos` (real U1 surfaces: plans,
  subscription, voucher, verification, KYC, payouts).

### Tests
- `tests/test_understanding_layer.py` (20 tests): every stage's
  extraction, fail-closed hollow-run, per-stage ordering guard, full
  caching on unchanged inputs, minimal recompute on changed inputs,
  tamper detection, U8 JSONL seed-list contract, coverage parking, brief
  rendering, bridge registration, and END-TO-END over HTTP against the
  live stub (fetch → model → brief; correctly PARKS idor/authz-bypass/
  jwt-confusion when no accounts are bound).

## v1.16.0 — Opsec & supply-chain hardening (master plan Phase 6)

The home-beacon is dead, releases are signed, and every third party in the
data path is documented, bounded, and optional.

### The home-beacon is dead (`SKILL.md`)
- **Removed**: the AUTO-UPDATE SYSTEM that fetched
  `raw.githubusercontent.com/.../VERSION` at the start of EVERY session —
  an unsigned trust channel (whatever that file returns is treated as
  instructions) and an opsec tripwire (a beacon to GitHub before any probe
  fires; exactly what a defensive SOC flags). A third beacon copy inside
  the session-startup steps went with it.
- **Replaced** by the UPDATE POLICY: no network at session start, ever;
  updates are opt-in only, read tagged releases (never a mutable branch
  file), and are facts to act on, never instructions to obey.

### Signed releases (`tools/release_signing.py`, NEW)
- `build_manifest` — deterministic SHA-256 manifest of a tree/bundle.
- `sign_manifest` / `sign_bytes` — Ed25519 (minisign-style armor)
  detached signatures via `cryptography`; **absent key ⇒ honestly
  unsigned, never fabricated**.
- `verify_manifest` / `verify_tree` — fail-closed install verification:
  hash mismatch, missing file, AND unlisted file (the backdoor route) all
  fail; verification artifacts in-tree are exempt from the unlisted rule.
- `verify_bytes` — verify any release file offline.
- `check_update` — the opt-in beacon replacement: GitHub releases API,
  TLS, fails silent, `opt_in: true` in every fact dict.
- CLI: `--build-manifest / --sign / --sign-file / --verify-file /
  --verify-tree / --check-update`.

### Install verification (`tools/harness_guard.py`)
- New `--verify-install`: re-hashes the installed tree against the
  manifest that shipped with it (signature verified when present),
  offline and fail-closed. No manifest ⇒ NOT verified, with the honest
  reason.

### Release workflow (`release.yml`)
- Builds the tree manifest + signs BOTH `SHA256SUMS.txt` and the manifest
  with the `RELEASE_SIGNING_KEY` secret (Ed25519 PEM); no secret ⇒ the
  release publishes **unsigned with the absence stated in the log**.
- Release assets now include `SHA256SUMS(.txt)?.minisig`.

### Tool installs pinned (`references/recon-tooling.md`)
- New supply-chain policy: tagged releases never `@latest`/`main`, no
  pipe-to-shell ever, checksums where published, pinned clones
  (`--branch <tag> --depth 1`), record resolved versions.
- **All 36 `go install …@latest` cells pinned to `@<release-tag>`**
  (duplicates included), all floating `pip install X` cells pinned to
  `X==<pinned-version>`, the two `cargo install` cells version-pinned,
  the `git clone` cell branch-pinned, and the one `curl | sh` cell
  (trufflehog) replaced with verified release binaries.

### OAST transparency (`docs/OAST_TRANSPARENCY.md`, NEW)
- What OAST is for, the loopback default (no third party), the opt-in
  public relay (what crosses it, who sees it), and the self-hosted option
  that eliminates the third party entirely.

### `/bugwolf-doctor`
- Step 5: `harness_guard --verify-install` (offline integrity gate).
- Step 6: `--check-update` — explicitly marked operator-asks-only,
  never unprompted.

### Tests
- `tests/test_phase6_opsec.py` (24 tests): beacon-absence gates across
  every session surface, opt-in contract, offline fail-silent update
  check (mocked), signing round-trip + tamper/missing/unlisted
  fail-closed, verify-tree without manifest, `--verify-install` CLI
  wiring, catalog pin gates (no `@latest`, no floating pip, no
  `curl|sh`), and the OAST trust-model contract.

## v1.15.0 — Operator command surface (master plan Phase 5)

The six commands the plan specifies — including the new front door. Every
command is a reproducible operator runbook: exact backend commands, what to
show, what never to do.

### The six commands (`commands/`)
- **`/bugwolf-leads`** — the lead ledger state machine UI: OPEN → MUTATING →
  FINDING / PARKED / KILLED, half-verdicts with evidence, deterministic
  next-mutation (anti-repeat), the kill guard (a refused kill is a park
  into the chain pool, never a delete), and chain-partner rescan.
- **`/bugwolf-scope`** — intake + LIVE gate preview: bind a `ScopeGate` in a
  heredoc and show ALLOW/DENY verdicts for target/subdomain/excluded/
  lookalike/loopback before anything fires (exclusions beat the wildcard;
  lookalikes never match by suffix). Surfaces the harness contract
  (`state/scope_contract.json`) and the PreToolUse hook's inert/clear
  semantics — never `clear` during a live mission.
- **`/bugwolf-research`** — R1–R7: the sequence checkpoints (R1 pre-hunt,
  R2 post-recon with stack context, R3/R4/R5) plus the event-driven pair
  (R6 blocker→bypass, R7 escalation-before-downgrade), freshness gating,
  and the citation discipline every hunt dispatch must carry.
- **`/bugwolf-chain`** — deep_chain walk × differential signals × impact
  focus: A→B paths from findings + PARKED leads + exploit-feedback
  hypotheses, differential paths from the crawl's access matrix as landing
  zones, ONE ranked list by business impact (dollars/PII/ATO) — and chain
  leads get the partner attached so the hunt tests the combination.
- **`/bugwolf-doctor`** — the 60-second smoke test: lab runtimes with exact
  fix commands, the replay + browser engine suites against the stub's real
  sinks, packaging gates, and honest interpretation (missing Playwright ≠
  broken engine; client-side verdicts go `blocked-browser`).
- **`/bugwolf-understand`** — **the front door**: runs the Understanding
  Layer U1→U9 in strict order (fail-closed, incremental re-runs), grounding
  in the session store + access matrix + capability manifest (deterministic
  captures first), the Assumption Ledger with dispro plans as the zero-day
  seed list, the coverage gate (classes with no model support are parked
  with reason), and the **Hunting Brief** as the final output — what
  `/bugwolf-run` dispatches against.

### Packaging
- All 16 commands registered in `plugin.json` + `marketplace.json`
  (manifest gate validates existence — drift fails CI).

### Tests
- `tests/test_phase5_commands.py` (12 tests): registration in both
  manifests, front-matter contract (description + argument-hint), a
  **backend drift gate** (every `python3 -m` / `python3 tools|hooks` path a
  command cites must exist on disk), per-command doctrine pins, and the
  U1→U9 ordering/coverage-gate/assumption-ledger/Hunting-Brief contract.

## v1.14.0 — Harness-level scope enforcement (master plan Phase 3)

Scope discipline moves **outside the model**: a PreToolUse hook intercepts
every Bash and WebFetch call at the Claude Code harness level and denies
out-of-scope network use before execution.  This is enforcement that
survives model drift, prompt injection, and agent hallucination — the
gate no longer depends on the agent's cooperation.

### PreToolUse scope hook (`hooks/bugwolf_pretool_scope_hook.py`)
- Extracts candidate hosts from Bash commands (curl/wget/nc/socat/ssh
  arguments, `--host`/`--connect-to` flags, scheme:// URLs, Host: header
  overrides) and from WebFetch input URLs; a plain command with no
  network surface is allowed without evaluation.
- Reuses the mission's own scope gate: subdomains allowed under the
  target wildcard, deny entries beat wildcards, lookalike hosts never
  match by suffix, loopback mirrors the engine's rule.  Verdicts:
  allow (exit 0), deny via **exit 2** (un-overridable, stderr fed back
  to the model) plus a structured `permissionDecision: "deny"` JSON.
- **Fail-open on harness errors** (malformed stdin must never wedge a
  session) and **inert without a mission** — zero UX cost outside
  `bugwolf run`.
- Every denial is journaled: `state/orchestrator/<mission>/scope_hook/denials.jsonl`
  (policy fact, command, refused hosts) for audit and F0.5 review.

### Contract persistence (`tools/runtime/scope.py`)
- `write_scope_contract()` / `clear_scope_contract()` — the hook's
  authority is a signed-by-structure contract file at
  `state/scope_contract.json` (targets, deny list, mission, written_at);
  the hook trusts it only while it exists, so the mission lifecycle
  installs and revokes enforcement automatically.
- Honors `BUGWOLF_PROJECT_ROOT` so hooks resolve the contract in any
  working directory.

### Integration
- `hooks.json` registers the PreToolUse matcher for Bash + WebFetch
  (alongside the existing Stop hook); `plugin.json`/`marketplace.json`
  already ship the hooks file to every install.
- `MissionRunner.run()` writes the contract at mission start and clears
  it in the finally block — enforcement exactly spans the mission.

### Tests
- `tests/test_pretool_scope_hook.py` (17 tests): subprocess-driven
  fixtures — allow/deny, deny-beats-wildcard, subdomain suffix rule,
  lookalike refusal, loopback parity with the engine gate, WebFetch
  enforcement, Host-header override detection, malformed-stdin fail-open,
  inert-without-contract, denial journaling, hooks.json registration,
  contract write/clear round-trip.

## v1.13.0 — Session intelligence: authenticated per-credential crawl (master plan Phase 2.2 + 2.3)

Differential access becomes DATA.  With operator accounts bound, BugWolf
now builds a per-credential model of the target's identity layer
automatically — the base map the authz lanes and the U4 understanding
artifact consume.

### Session context store (`tools/runtime/session_context.py`, 2.2)
- Per-credential model: tokens (memory-first, structurally redacted on
  every export — `raw_token` only under explicit `include_tokens=True`),
  **live JWT header+claim decode** (the credential the target actually
  issued, not static analysis), inferred role with source attribution
  (jwt → response → operator), object-ID inventory, endpoint reachability
  per identity, and the label × path identity matrix.
- Claim-shape redaction for export: claim NAMES survive (structural
  facts), identity-bearing claim VALUES are redacted.
- `to_model_dict()` is the U4 identity/authz artifact payload.

### Authenticated crawl (`tools/runtime/authed_crawl.py`, 2.3)
- The same URL space crawled once per identity (anon / A / B / C) through
  the Phase 1 replay engine — scope gate + governor inherited, no separate
  network path.  Governor refusals (circuit/budget/rate) degrade to an
  honest status-0 fact, never a crash.
- Records per page: `status_by_label`, title, links, and **form schemas**
  (action, method, fields).  Differential paths (identities seeing
  different statuses) are the authz hunt's candidate list — a fact, not a
  verdict.
- Session store is fed as a side effect: roles and object IDs accumulate
  while crawling.
- Artifacts: `state/orchestrator/<mission>/crawl/access_matrix.json` +
  `pages.jsonl`.

### Integration
- `MissionRunner.run()` step 2.7: when accounts bind, the session context
  is built and a bounded crawl (≥12 pages or 2× operator paths) runs
  automatically; artifacts persisted, `authed_crawl` event logged with
  differential paths + inferred roles.
- **MCP tool `bugwolf_sessions`**: the identity model (roles, JWT shape,
  object inventory, identity matrix, crawl differentials) natively in
  every Claude Code session — tokens always redacted.
- Stub target: `/login` now issues **role-carrying JWTs** (`admin`/
  `user`), `/dashboard` is identity-rendered HTML, `/admin/panel` is a
  real 200/403 boundary keyed on the token's role claim — the crawl's
  differential has a genuine privilege boundary to find.

### Tests
- 11 new tests: JWT/role inference, redaction (export + claims), object
  inventory, identity matrix, save/load, U4 artifact shape, and the live
  crawl differential (anon/A 403 vs C 200 on `/admin/panel`, uniform 200
  on `/dashboard`, form schema harvest, artifact persistence).

## v1.12.0 — Browser-confirmed client-side verdicts (master plan Phase 2)

The "reflection is not execution" lane now has its browser.  A real
Chromium confirms client-side findings via console/DOM signature capture —
with the scope gate enforced at the navigation layer and honest
blocked-browser semantics when no browser exists.

### The binding (`tools/runtime/browser_driver_playwright.py`)
- **Real Chromium** behind the existing `BrowserDriver` protocol:
  navigate, console capture (console messages + uncaught page errors),
  DOM evaluation (the sink query), and full-page screenshot evidence
  under `state/evidence/browser/`.
- **Own-thread execution model**: Playwright's sync API refuses to run
  inside an asyncio event loop — and BugWolf's hosts (Claude Code MCP
  bridge, mission runner) live on one.  Every public call marshals onto a
  dedicated worker thread; the binding works from any thread, including
  coroutines (regression-tested).
- **Evidence is per-navigation**: the console/dialog buffer resets on
  every `navigate` — a reused driver validating many leads sequentially
  can never let lead N's execution false-confirm lead N+1.
- **Fail-closed**: Playwright missing ⇒ availability fact with install
  hint, lead goes to blocked-browser, never a fabricated verdict.  Scope
  gate runs BEFORE the browser starts — an out-of-scope URL cannot spawn
  a browser process.  Dialogs auto-dismissed (recorded), timeouts capped.

### Integration
- **`browser_driver.load_default_driver()` / `set_default_driver()` /
  `driver_status()`** — binding loader with operator pin support.
- **`MissionRunner` auto-bind**: `browser_driver=None` (default) loads the
  real binding automatically — browser-confirmed verdicts out of the box;
  an injected driver object still wins; `browser_driver=False` forces the
  deterministic no-driver contract (CI/test runs).
- **MCP tool `bugwolf_browser_confirm`** — browser-confirmed validation
  natively in every Claude Code session: EXECUTION-CONFIRMED requires the
  payload signature in console/DOM; reflection alone reports
  `reflection_only` and never confirms.
- **Stub target `/api/notes` is now a REAL HTML page** with unencoded
  stored-note rendering and a script `eval` sink — the client-side lane
  has an executable XSS surface instead of a JSON echo.

### Tests
- 14 browser tests (deterministic fake-driver layer + live Chromium suite
  skipped honestly when Playwright is absent), including the two doctrine
  regressions: reflection ≠ execution, and per-navigation evidence reset.

## v1.11.0 — Raw-socket replay send engine (master plan Phase 1)

BugWolf can now put bytes on the wire itself. A byte-exact HTTP replay
engine replaces the curl-shellout: framing ambiguity is *observable*,
mutations operate on parsed message structures, and every send is
scope-gated (deny-by-default) and governor-throttled. Unlocks the
desync/smuggling and header-ambiguity bug classes that normalized
HTTP clients physically cannot express.

### The engine (`tools/runtime/replay/`)
- **message.py** — byte-exact HTTP/1.1 parser/serializer: header case,
  OWS, duplicate headers, and pipelined trailers round-trip exactly;
  CL+TE coexistence, duplicate/conflicting Content-Length, and mixed-case
  Transfer-Encoding are flagged as observed framing conflicts (facts,
  never auto-resolved).
- **apply.py** — 15 mutation ops over parsed messages (query surgery,
  position-preserving header edits, JSON dot-path body edits, cookie ops,
  positional path rewrite). Body-editing ops repair a stale
  Content-Length — a mutation can no longer hang the target with a
  self-inflicted framing mismatch. `body-set-field` sets values exactly
  (no silent JSON type coercion — type confusion belongs to body-merge).
- **encode.py** — composable codec pipelines (url/url-double/base64/
  html-dec/unicode/…): WAF bypass spaces that string concatenation
  cannot express.
- **backend_socket.py** — the only component that touches the network:
  scope gate authorizes FIRST (fail-closed, lowest layer), governor
  admits second (budget → circuit → concurrency → rate), fresh socket
  per send, TLS via SNI, response read with body cap and an honest
  no-bytes timeout fact (never a silent status=None success).
- **governor.py** — deterministic state machines (CircuitBreaker,
  AIMD concurrency, TokenBucket, GlobalBudget); time is injected, all
  unit-testable without sleeps.
- **observe.py** — facts only: reflections, error-class fingerprints,
  deterministic A/B deltas; verdicts stay with the F0.5 gate.
- **batch.py** — compare (baseline vs mutated variants, the IDOR/authz
  automation) and sweep (one mutation across every query/body/path
  position).
- **engine.py + tools/replay_cli.py** — `replay_request` (structured +
  delta), `replay_raw` (verbatim bytes), `desync_probe` (front+smuggled
  pair); CLI accepts inline or file mutations and reads request files
  byte-exactly (no universal-newline mangling).
- **MCP bridge**: `bugwolf_http_replay`, `bugwolf_http_replay_raw`,
  `bugwolf_http_replay_desync` — the engine is callable natively from
  every Claude Code session.

### Scope-gate integration
- `scope.GATE` is now a PEP 562 module attribute that always resolves
  the live gate (reset-safe for the bridge, CLI, and tests).

### Stub-target acceptance surfaces
- `/api/echo-headers`, `/api/param-echo`, `/api/cached/page` (unkeyed
  header → cache poisoning, X-Cache HIT/MISS), `do_*` catch-all dispatch
  so odd-case verbs sent raw are observable, BrokenPipe-tolerant writes.

### Tests
- 49 replay-engine tests (unit + live in-process integration) including
  regressions for both bugs the CLI smoke caught: stale-CL after body
  mutation, and silent zero-byte responses.

## v1.10.0 — Claude Code plugin packaging + native subagent dispatch (master plan Phase 0 + 4)

BugWolf's engine was ahead of its packaging. This release makes it a
first-class Claude Code plugin and fixes the agent fleet's native
dispatch contract.

### Plugin packaging (Phase 0)
- **Marketplace install**: added `.claude-plugin/marketplace.json` — the
  plugin is now installable with `/plugin marketplace add youseefhamdi/bugwolf`
  then `/plugin install bugwolf@bugwolf`.
- **plugin.json truth**: version synced to the release (was stale at 1.0.0
  while VERSION said 1.9.2), plus `repository`, `homepage`, `keywords`, and
  a structured author identity for the marketplace listing.
- **MCP wiring**: root `.mcp.json` registers `bridge/bugwolf-mcp.py`, so
  `bugwolf_status` / `bugwolf_plan` / `bugwolf_run` / `bugwolf_leads` /
  `bugwolf_mode` are natively available in every Claude Code session with
  zero setup.
- **Manifest integrity gate**: new `tools/plugin_manifest.py` checks
  version sync across VERSION / plugin.json / marketplace.json / CHANGELOG
  (latest `## vX.Y.Z` heading), manifest shape (referenced commands, hooks,
  skills, agents must exist), and agent front-matter shape. CI runs it;
  drift fails the build.
- **Release pipeline**: `.github/workflows/release.yml` — a `v*` tag runs
  the full suite, builds both bundles, emits SHA256SUMS, and publishes the
  GitHub Release with `.skill` + `.freebuff.zip` artifacts.
- **Trust docs**: `SECURITY.md` (scope model, sandbox, kill switch,
  reporting policy) and `CONTRIBUTING.md` (registry-first agent edits,
  test gates, release process).

### Native subagent dispatch (Phase 4)
- **`model-tier:` was silently ignored** by Claude Code's native Task tool
  (the field does not exist); tier routing only worked in the CLI-spawn
  path. The generator now emits the **native `model:` field**
  (`deterministic → haiku`, `local_slm → sonnet`, `frontier → opus`) and
  preserves the router vocabulary in a non-reserved **`x-bugwolf-tier:`**
  key, so `tools/core/model_router.py` and the team engine's CLI pinning
  keep working unchanged.
- **`tools:` now names Claude Code tools** (previously BugWolf module names
  like `runtime.mission_runner`, unresolvable by the Task-tool allowlist).
  Allowlists are derived per lane: verify/report agents are **read-only
  (no Bash)** — lane discipline is enforced mechanically; hunt agents get
  `Bash` + `Task`; workflow agents never dispatch subagents. The BugWolf
  module list moved into the body preamble ("Tool modules:").
- All 39 agent definitions regenerated; `generate_agents.py --check` stays
  green and `plugin_manifest.py --check-agents` locks the new shape.

### Tests
- New `tests/test_plugin_packaging.py`: version sync, manifest shape,
  front-matter shape (39 agents), sync-check drift detection, native-Task
  structural validation (deny-by-default scope + sandbox + verify read-only
  lane asserted in every dispatch payload).

## v1.9.2 — Recon depth surfaced in operator reports (status + preflight)

The depth ledger and its evidence recommendations were visible only to
dispatch payloads and the ledger CLI; operator reports could not answer
"how deep did recon go, and what did its evidence imply?".

### Team engine (`tools/runtime/team.py`)
- **`_recon_depth_report()`**: shared advisory section (never raises,
  never gates) consumed by both `status()` and `preflight()`:
  per-depth covered/total counts with untried + waived lists, honest
  close blockers, and the depth ledger's evidence-driven recommendations
  annotated with **staffing state** (`role` + `staffed` flag) — an
  operator sees not just "bucket surface found" but whether the matching
  specialist is already on the roster.
- **Honest degradation**: a mission with no recon-depth activity reports
  `journal: false` with zero events and no recommendations — reporting
  never fabricates depth intel. Close blockers are claimed only once a
  journal exists (they are the in-flight exit exam, not a pre-failure of
  a mission that hasn't begun).
- **Unstaffed evidence stays visible**: evidence whose specialist was
  never staffed (e.g. recomposition disabled) is reported with
  `staffed: false`, never silently omitted.
- 3 new tests (staffed evidence in both reports, unstaffed honesty,
  no-journal degradation); 19 total in the depth suite, 131 overall.

## v1.9.1 — D3 evidence auto-recomposition (recon census → specialists)

The depth ladder recorded evidence; the recomposition loop consumed only
member-reported recommendations. A recorded census hit (a bucket hostname,
a WAF signature, a secret pattern in a bundle) now staffs its specialist
automatically — no agent handoff required.

### Depth ladder (`tools/recon/depth_ladder.py`)
- **`SIGNAL_RULES`**: evidence patterns mapping census detail/asset text
  to registry bug classes — cloud-bucket hostnames → `s3_misconfig`,
  mobile/deep-link/`/api/` surfaces → `shadow_api`, WAF/CDN signatures →
  `waf_bypass`, secret patterns in bundles → `js_secrets`. Rules are
  technique-scoped (regex on technique + pattern on text).
- **`recommendations()`**: cross-references recorded attempts into
  `{bug_class, reason}` pairs. Evidence-based by construction: blocked
  attempts are excluded, a clean census recommends nothing — silence can
  never staff a specialist. Deduped per (technique, class); reasons are
  prefixed `recon D-evidence:` for provenance.
- CLI `--recommendations` surfaces the cross-reference for operators.

### Team engine (`tools/runtime/team.py`)
- **Single apply path**: `_maybe_recompose` delegates to the new shared
  `_apply_recommendations` (dedupe, budget cap, idempotent ledger);
  `_recompose_hook` merges member recommendations with the depth
  ledger's evidence recommendations. Evidence recommendations ride the
  exact same `recomposed` ledger events, `TEAM_RECOMPOSED` signals,
  re-entry rounds, and `--no-recompose` opt-out.
- Verified end-to-end: pre-recorded D3 bucket evidence staffs
  `cloud-cicd` into the hunt wave with a provenance-carrying reason;
  decisions are idempotent across resume.
- 6 new tests (rule semantics, evidence-vs-silence, blocked-exclusion,
  dedupe/technique-scoping, end-to-end staffing, resume idempotence).

## v1.9.0 — Max-depth recon: D0-D3 depth ladder (anti-satisficing for recon)

Recon had breadth (7 methodology sections, 15-phase engine) but no depth
contract: nothing defined how deep recon must go before it may close, so
depth was improvised — the same anti-satisficing failure mode
lead-protocol eliminated for exploitation ("tried the most plausible
probe once, moved on"), here expressed as "enumerated the obvious once,
stopped shallow".

### Recon depth ladder (`tools/recon/depth_ladder.py`, NEW)
- **D0 passive** (zero target contact): historical churn, CT-log mining,
  code search, package registries, social fingerprinting.
- **D1 resolvable**: resolve-all, port census, wildcard baseline, ASN
  neighborhood.
- **D2 http-surface**: well-known census, admin ladder, API docs, JS
  mining, header fingerprint.
- **D3 deep-surface** (the pass shallow recon always skips): parameter
  surface census, JS route/API-map extraction, cloud-bucket permutations,
  mobile endpoint harvesting, historical cross-reference.
- Append-only JSONL journal (`state/orchestrator/recon-depth/<mission>.jsonl`,
  lever P5): rehydratable, torn-tail safe, offline by construction
  (stdlib + runtime_paths only; a source-import test pins this).
- **Depth discipline**: `untried()`/`close_blockers()` make "stopped too
  shallow" structurally visible; `partial` is never terminal; waivers are
  explicit recorded events with a reason — never silent omissions; each
  level closes via an explicit `close(depth)` declaration.

### Engine wiring (`tools/runtime/team.py`)
- Every recon-lane member's dispatch payload now carries
  `intel.recon_depth`: the D0-D3 slice, live ledger coverage, and current
  close blockers — depth is a **dispatched obligation**, verifiable per
  member and across resume, never a suggestion. Verified for the recon
  workflow agent and lane-declared specialists (shadow-surface).

### Playbook (`references/hacking-agents/recon-agent.md`)
- New mandatory "Depth Ladder" section: ledger commands, per-depth
  technique tables, D3-mandatory discipline (go deeper on signal, never
  stop on silence), `recon_close_blockers` as the recon exit exam, and
  the recommendation handoff to the team's recomposition loop.
- Registry recon tool list extended (`recon.depth_ladder`,
  `historical_asset_delta`); all 39 agent definitions regenerated in sync.
- 10 new tests (ledger semantics + engine wiring).

## v1.8.0 — Orchestrator architecture & operations hardening (team engine)

Architecture: the engine's wave logic existed twice (once in ``run()``, a
stale-prone copy in ``resume()``); operations: the only pre-execution
surface was ``--status``, which reports wave state but not worker binding,
recomposition policy, or re-entry bounds.

### Team engine (`tools/runtime/team.py`)
- **Single wave driver**: ``_drive_waves()`` is now the one execution
  loop shared by ``run()`` and ``resume()``; ``run()`` = plan-if-needed +
  drive + ``_complete()``; ``resume()`` = stale recovery + the same
  driver.  No duplicated wave logic can drift again.
- **Recon joins the feedback loop**: ``recompose_waves`` (default
  ``("recon", "hunt")``) lets recon-wave findings staff hunt specialists
  *before* the hunt wave runs — shadow assets discovered during recon get
  their specialist on the first hunt pass, not after it.
- **Bounded growth**: ``max_recompose_rounds`` (default 3) caps hunt
  re-entry rounds (a round may add several specialists in parallel;
  ``max_agents`` still bounds the roster).  The cap is recorded as
  ``state["recompose_capped"]``, and the rounds actually run surface as
  ``state["recompose_rounds"]`` — capped growth is visible, never silent.
- **Idempotent recomposition ledger**: bug classes already decided on
  (added *or* skipped) are re-evaluated but never re-appended; the
  seen-set rehydrates from ``state.json`` on resume.  A repeat that
  actually adds (budget changed under it) is still recorded.
- **Operational preflight**: ``TeamEngine.preflight()`` and CLI
  ``--preflight`` report status, worker binding ("none (members will
  close BLOCKED honestly)" when unbound), recomposition policy and
  ledger size, re-entry rounds, roster counts, and the coverage gate —
  without executing and without writing state.  The MCP bridge exposes
  the same ``bugwolf_team`` ``preflight`` action.
- 6 new tests: recon-feedback ordering, idempotent ledger across
  re-entry, round cap + cap recording, resume-without-re-recording,
  preflight (fresh + loaded), rounds-run visibility.

## v1.7.2 — Default subagent pinning (native dispatch)

Closes the last orchestrator gap: in the native path, `bugwolf:<role>`
only reached the harness as prompt text — subagent selection required a
hand-written `command_builder`. Headless runs now execute the specialist
playbook by default, not a bare session.

### Native worker (`tools/runtime/native_dispatch.py`)
- **`pin_agent=True` (default)**: the default argv pins
  `--agent bugwolf:<role>` from the dispatch payload's `harness_role`
  (the registry-facing subagent name, matching `agents/bugwolf/*.md`
  frontmatter and the task-tool queue's `subagent_type`).
- **Honest degradation**: a payload without a role stays flagless — the
  worker never invents one (the engine always sets `harness_role`).
- **Opt-out**: `pin_agent=False` restores the flagless spawn for CLIs
  without subagent-type support; `command_builder` still wins whenever
  supplied and remains the extension point for different flag names or
  extra flags.
- 5 new tests: default pin, missing-role flagless, opt-out,
  builder-precedence, argv ordering (model → agent → extra args).

## v1.7.1 — Default tier-to-model pinning (native dispatch)

Closes the second orchestrator gap: tier routing computed a
`model_preference` per member, but the native worker shipped an empty
`model_map`, so the decision never reached `--model` without operator
configuration.

### Native worker (`tools/runtime/native_dispatch.py`)
- **`DEFAULT_MODEL_MAP`**: the router's preference strings pin to
  concrete `--model` ids out of the box — `none` → flagless
  (deterministic members warrant no model call), `slm-fast` → `haiku`,
  `frontier-reasoning` → `sonnet`, plus identity passthroughs
  (`haiku`/`sonnet`/`opus`) for configs that already name concrete
  models. Keys mirror `model_router._DEFAULT_PREFERENCES` and the
  shipped `configs/models.json`.
- **Merge semantics**: an operator `model_map` merges over the defaults
  per key (overrides win, non-overridden keys survive); pinning a key to
  `""` forces the harness default for that preference.
- **Degradation chain**: an unmapped primary preference falls back to
  the member's `fallback_preference`; both unmapped ⇒ no `--model` flag
  at all — the worker pins what it knows and never guesses.
- 7 new tests: default-map resolution, router-preference → argv,
  `none` stays flagless, fallback degradation, both-unknown flagless,
  per-key operator override, empty-value override.

## v1.7.0 — Finding-driven roster recomposition (multi-agent team engine)

The team engine's roster is no longer frozen at plan time. Hunt-wave
members can report finding-backed agent recommendations and unstaffed
specialists join the team mid-mission — the orchestrator's missing
feedback loop (the engine could compose a team, but recon/hunt results
could not reshape it).

### Team engine (`tools/runtime/team.py`)
- **Recommendation contract**: hunt members return
  `recommended_bug_classes` (list of bug-class strings or
  `{bug_class, reason}` dicts) and/or `agent_recommendation` handoff
  messages; `_recommendations_from_results` extracts them, ignoring
  malformed shapes (never raises; FAILED members are not consulted).
- **`_add_specialist`**: registry-deterministic selection (the same
  specialist a planned mission would staff), budget-capped by
  `max_agents`, deduped against the roster, workflow agents never
  re-added. Every decision — added or skipped, with why — is appended to
  `state["recompositions"]` and checkpointed; additions also emit a
  `recomposed` event to the runs ledger and a `TEAM_RECOMPOSED` signal.
- **Hunt re-entry**: after a hunt wave that grows the roster, the engine
  re-enters the hunt wave with the added specialists before verify
  (dedupe + budget bound the loop); verify/report always run last.
- **Opt-out**: `--no-recompose` pins the planned roster; the preference
  persists in `state.json` (`recompose`) and is honored on `--resume`.
  `status()` surfaces `recompositions` for operator inspection.
- New tests (`tests/test_recomposition.py`, 9 cases): forward addition,
  hunt re-entry + budget cap, skip accounting (unknown class / already
  staffed), message-shape extraction, `--no-recompose`, resume
  persistence, registry-resolution parity with plan-time composition.

## v1.3.0 — Boundary-hardened orchestrator: scope gate, sandbox, OAST tunnel, L2 readiness

The Phase 0-8 orchestrator plan (BUGWOLF_ORCHESTRATOR_PLAN_V2) is complete
and release-gated: readiness **L2 (clean-checkout reproducible), VALID,
zero warnings**; capability manifest `releasable: YES`; all 13 §5.3 perf
targets measured and met.

### Execution boundary (readiness R1-R3 closed, functionally proven)
- **Operator scope gate (`tools/runtime/scope.py`, NEW)**: deny-by-default
  authorization at the execution boundary. The mission target's host is
  authorized (operator-declared), everything else is blocked with
  `--scope` allowlists and `--exclude` deny-entries (exclusions ALWAYS
  beat the wildcard — found live on the Plumsail engagement where the
  program excludes `beta.`/`community.`). Enforced at every network
  choke point: `http_probe`, the race engine's raw sockets, the live
  executor, and the injected browser driver; out-of-scope requests fail
  CLOSED and are recorded as policy facts.
- **Subprocess sandbox (`tools/runtime/sandbox.py`, NEW)**: every spawn
  in the shipped tree routes through `sandboxed_run` — binary
  allowlist, scrubbed env, kill-switch circuit breaker, output caps,
  process-group timeout kills. Operator CLI
  (`python3 -m tools.runtime.sandbox status|kill|arm|grant|revoke|verify`);
  an engaged kill switch fails the release gates CLOSED. Long-lived
  daemons (interactsh, ngrok, lab fixtures) gate before their streaming
  Popen; the hook shim and MCP bridge are pinned spawn-free; a
  repo-wide sweep test fails on any raw spawn outside the audited
  choke points.

### Remote-campaign attribution
- **OAST public tunnel (`tools/runtime/oast_tunnel.py`, NEW)**:
  `BUGWOLF_OAST_TUNNEL=1` auto-arms an SSH reverse tunnel (serveo) so
  the canary listener's public route works for REMOTE targets — SSRF
  leads close on attributed callbacks. Verified end-to-end: a public
  fetch through the tunnel attributes 100%.

### Mission runner hardening (live-engagement fixes)
- **R1 negation-aware validation**: honest negative summaries ("0 leads
  open", "findings=0") no longer false-positive the anti-satisficing
  validator; structured hypotheses stay strictly gated.
- **Credential redaction at the persistence boundary**: `--accounts`
  passwords/tokens never reach `graph.json`; a resumed mission treats
  redacted values as absent (degrade with disclosure, never replay).
- **Race engine TLS on by default**; hook journal input allowlist; OAST
  public-route override (`BUGWOLF_OAST_PUBLIC_URL`) splitting bind from
  advertisement; runner event-log init before OAST arming; `--oast`
  mission CLI flag; deterministic listener teardown.

### Lanes
- Contract / cloud / LLM domain lanes; auth A/B/C account-matrix
  differential lane; FIN business-logic lane with the race engine bound
  to voucher/replay techniques; pass@k technique-matrix swarms for the
  WAF-bypass family.

### Measured performance (§5.3: 13/13, each with `measurement_basis`)
- All targets now measured offline on the deterministic harness,
  including the four former NOT_MEASURED ones: first specialist
  dispatch 0.02s (<10s), signal-to-escalation 0.008s (<5s), context
  duplication 0.0 (<20%), frontier-call reduction 0.51 (≥40%, P3
  router vs keyword baseline over a discordant-bucket population). The
  operator-environment residual (model inference) is excluded by the
  documented basis and audited during live campaigns.

### Readiness L2 (clean-checkout reproducible)
- **`tools/reproducibility.py` (NEW)**: a bare clone of HEAD reproduces
  the deterministic product — offline preflight, the deterministic test
  subset, and two perf runs with identical outcome fields (latency
  values are deliberately not invariants). `validate_manifest`
  re-proves the claim on every validation: L2 without the control is an
  ERROR; the control without working code is an ERROR. Probe results
  are disk-cached per HEAD (TTL 1 day) so release gates stay fast; the
  probe carries a re-entrancy guard (env + committed-code check) so its
  own test subset can include the manifest tests safely.

### Tests & gates
- 1331 passing (up from 940 at v1.2.11): scope gate, sandbox coverage,
  OAST tunnel, reproducibility (incl. live full probe), negation-aware
  contracts, audit-fix pins. Perf gate PASS; capability manifest 34
  modules + 10 commands, `releasable: YES`.

## v1.2.11 — Carlini Loop track: per-file brute-force discovery

- **`tools/carlini_loop.py` (NEW)**: applies the 2026 per-file brute-force
  zero-day discovery pattern (Carlini Loop / nano-analyzer / NOVA — see
  `ENHANCEMENT_PLAN.md`) to a local project. `enumerate_files` walks the
  project deterministically (surface extension filter, noise dirs excluded,
  size/line/file caps); `brief_file` builds a per-file security briefing
  (imports, functions, entry points, line-anchored dangerous sinks from a
  NOVA-style catalog — command exec, eval/deserialization, SQLi, SSRF, file
  write, path traversal, prototype pollution, header trust, SSTI,
  cache-key control); `build_units` emits one research unit per file with
  CTF framing for the harness to execute; `offline_scan` runs a model-free
  sink-catalog + existing surface-track floor; `register_results` intakes
  harness findings through `ZeroDayResearchEngine` (evidence + novelty
  dedup + optional chain synthesis). Repeated intake is idempotent (stable
  candidate ids filtered pre-registration; near-matches return
  `likely_variant`); candidates stay HYPOTHESIS until trigger+impact
  evidence exists; nothing is labeled a zero-day without human review.
- **Tests** (`tests/test_carlini_loop.py`, 20 tests): bounded enumeration
  (extension filters, noise exclusion, caps), briefing sink/entry-point
  extraction, one-unit-per-file dispatch with redacted briefing context,
  offline floor candidates, idempotent intake through the zero-day engine,
  near-match dedup, and a repo-wide self-scan bound check. Full suite: 940
  passing.

## v1.2.10 — Operator-approved bypass exploitation scored

- **`tools/intelligence/failure_learning.py` — `approve_candidate` (NEW)**:
  the operator gate between quarantine and reuse. Loads
  `research/<target>/learning/failure-bypass-candidates.json`, stamps the
  candidate `approved` (+`approved_by`/`approved_at`), persists back, and
  returns the updated `BypassCandidate`. Idempotent for already-approved
  candidates; raises `ValueError` for unknown ids or a missing ledger.
  `BypassCandidate` gains `approved_by`/`approved_at` fields.
- **`campaign_orchestrator.py` — `exploit_approved_bypass` (NEW)**: replays
  an operator-approved bypass payload live against a `fuzz_blocked`
  thread's blocked endpoint — the recorded request is rebuilt with the
  payload applied (`Name: value` → header, `?…` → query, else body /
  `?q=` for GET) and re-sent via `execute_exploit`; the outcome lands in
  `state/sessions/<target>/exploits.jsonl` as a `kind="bypass-approval"`
  record (`candidate_id`, `technique`, `approved_by`, `reproduced` =
  got through the defense, `demonstrated_impact`). The thread stays BLOCKED
  (the operator decision is untouched); advisory — failures never gate.
- **Self-eval Task 10 — `bypass-approval-exploited` milestone (NEW)**: the
  exploitation-phase task now scores the operator-approved bypass cycle —
  an approved candidate in the failure-learning ledger + a reproduced
  bypass-approval exploit with demonstrated impact (vacuous pass when no
  fuzz_blocked thread ever arose, mirroring Task 9's rate milestone).
- **Lab fixture**: `GET /api/gateway` — a deterministic WAF surface that
  403s fuzz-mutated `q` requests (`access denied` → akamai) unless the
  `X-Original-URL` bypass header is present, returning an admin gateway
  record (the failure-learning catalog's header-based path access
  technique).
- **Tests** (+7): `test_week6` approve-candidate unit tests (quarantine,
  approve+persist, idempotence, unknown/missing raises);
  `test_live_feedback_loop` full cycle test (blocked thread → approve →
  exploit → ledger + scored milestone) + no-approval negative test; the E2E
  deep-dive now drives the real cycle against the lab gateway (fuzz blocked
  → approve `X-Original-URL` candidate → 200 admin record) and scores the
  full 10-task eval at 100%. Bundle check seeds the approved candidate +
  blocked thread + bypass exploit so the milestone scores from inside the
  bundle. Full suite: 861 passing.

## v1.2.9 — Exploit feedback refines zero-day novelty

- **`tools/zero_day.py` — `hunt_exploit_feedback` (NEW)**: feeds a
  reproduced exploit's demonstrated impact into the novel-class hunter. The
  impact-reveal anomaly (the endpoint demonstrably returned data it should
  not) plus one candidate per derived chain-hypothesis class are generated,
  stamped with exploit provenance (`finding_id`, `replay_key`,
  `replayed_status`), confidence 0.8 (outranks fuzz crashes), severity bumped
  one tier for unlocks, and deduped per (bug_class, endpoint) so pass@k
  variants of the same finding never pile up. The novelty refinement:
  unlock candidates are built **impact-bounded** (impact half proven by the
  replay), so `NoveltyEngine.apply` promotes them into `NOVELTY_PENDING`
  with impact evidence — human-review-ready — instead of bare hypotheses;
  surfaces already in the pool come back `EXACT_DUPLICATE` and confirm the
  known candidate.
- **`campaign_orchestrator.py` — wiring**: `_feed_exploit_to_chains` now
  also calls `_feed_exploit_to_zero_day`, registering the candidates through
  the novelty engine and persisting them to
  `research/<target>/zero-day/exploit-feedback.jsonl`; the impact record
  carries `zero_day_novel` and the loop summary gains an `exploit_novel`
  counter. Advisory: feed failures never gate the exploitation phase.
- **Tests** (`tests/test_zero_day_research.py` +5,
  `tests/test_live_feedback_loop.py` +0 extended): reveal + unlock
  generation, novelty refinement to human-review-ready, skip rules
  (unreproduced / empty impact), pass@k dedup, determinism; live-loop test
  now asserts `exploit_novel` ≥ 1 and the persisted
  `exploit-feedback.jsonl` (unlocks at `novelty_pending` with impact trace).
  Full suite: 854 passing; CI bundle check 10/10.

## v1.2.8 — Exploit feedback feeds chain hypotheses

- **`tools/leads.py` — data-unlock derivation (NEW)**: deterministic
  `derive_data_unlock_classes` scans a demonstrated impact body for what it
  unlocks (role/admin → `privilege-escalation-web`, balance/amount →
  `business-logic`, email/SSN/PII → `mass-data-breach`, credentials/tokens →
  `account-takeover`/`api-key-exposure`, session/OAuth → `account-takeover`,
  SQL/shell surface → `rce`), falling back to the source class's deep-chain
  `EDGES` escalation targets when the body has no textual signal.
  `chain_hypotheses_from_exploit` builds OPEN-LEAD chain-pool records from
  those classes (stable `lead_id`, `bug_class`, `evidence_state=hypothesis`,
  source finding as chain partner, impact as trace) — pure, deterministic,
  no I/O.
- **`campaign_orchestrator.py` — exploit → chain feedback**: after a
  reproduced exploit records its `demonstrated_impact`, the loop persists the
  derived hypotheses as OPEN-LEAD records
  (`state/sessions/<target>/leads.jsonl`, `source: "exploit-feedback"`),
  rebuilds the chain graph via `chain_orchestrator.refresh_target` so the new
  classes join chain proposals, stamps `chain_hypotheses` on the impact
  record (`live_exploit` + `exploits.jsonl`), and publishes a `CHAIN_PROPOSAL`
  event. Advisory: feedback failures never gate the exploitation phase.
- **Tests** (`tests/test_leads.py` +8, `tests/test_live_feedback_loop.py`
  +1): unlock heuristics (financial/credentials/role/PII, EDGES fallback,
  determinism, cap, chain-consumable record shape) + the live loop writing
  feedback leads and rebuilding the chain graph end-to-end against the lab
  (2 exploited findings → 6 hypotheses → graph contains the new classes).
  Full suite: 849 passing; CI bundle check 10/10.

## v1.2.0 — Phase 3: Live Execution Harness Loop (Planner → Hunter)

- **`tools/core/live_executor.py` (NEW)**: real probe execution. `execute_probe`
  derives a deterministic probe set (baseline + technique probes) from a
  research unit and sends real HTTP requests, capturing status/headers/body/
  timing, WAF fingerprints, bounded retries, and a replayable
  `replay_key` evidence block per probe. `execute_exploit` replays a
  confirmed finding's recorded request for impact demonstration.
- **`campaign_orchestrator.py` — live feedback loop**: `live_feedback_loop()`
  (CLI: `--live-run`) drives unit → live probe → observation → adapt: blocked
  → `failure_learning` blocker + bypass quarantine; signal → COMPLETE with
  recorded evidence through the F0.5 gate; clean → REFUTED; transport errors
  are observations, never gates. Probes persist to
  `state/sessions/<target>/probes.jsonl`.
- **`tools/refutation.py` — reproducible-evidence gate**: new
  `require_reproducible` flag (default off for backward compat) + confidence
  bonus for recorded request/response evidence, and `verify_reproducibility`
  delegating to the live executor. `ThreadRecord` gains a `live_evidence`
  field so live threads carry recorded proof through serialization.
- **`tools/core/fuzz_bridge.py` (NEW)**: coverage-aware fuzz campaigns —
  scheduler-ordered mutations executed over the live transport; crash
  (5xx) / timeout / timing-anomaly evidence published as
  `FINDING_DISCOVERED` into research threads; summaries to
  `state/fuzz/<target>/runs.jsonl`. Deterministic core, injectable transport.
- **`tools/zero_day.py` — novel-class modes**: `diff_analysis_mode`
  (version/snapshot behavior deltas, optional live re-probe),
  `anomaly_detection_mode` (status/timing/header/error-pattern anomalies),
  `state_machine_probing` (workflow skip/repeat/reorder → business logic).
- **Fix (found by the integration test)**: `build_probe_specs`' idor
  object-reference sweep used `str.replace("/1", ...)` which matched the
  `//1` inside `http://127.0.0.1/...` and rewrote the **request host** to
  WAF-bypass variants (`227.0.0.1`, octal `027.0.0.1` → unroutable
  `23.0.0.1`, causing a 30s transport hang). The id is now replaced at the
  end of the path only; regression test added. The live-feedback loop's
  per-unit probe time dropped from ~30s to ~0.01s.
- **Tests**: `tests/test_live_executor.py` (+31), `tests/test_fuzz_bridge.py`
  (+15), `tests/test_live_feedback_loop.py` (+4, boots the lab fixture
  in-process and asserts real probe → observation → adaptation),
  `tests/test_zero_day_research.py` (+7 novel-class modes),
  `tests/test_f05_strict_validation.py` (+6 reproducibility-gate),
  plus the idor-host regression. Full suite: 822 passing.
- **CI**: `tools/core/live_executor.py` and `tools/core/fuzz_bridge.py`
  added to the bundle REQUIRED list; bundle check still 7/7 (100%).

## v1.2.1 — Fuzz bridge wired into the live feedback loop

- **`live_feedback_loop(..., fuzz_budget=N)`** (CLI `--fuzz-budget N`):
  when the research queue drains, one coverage-aware fuzz pass runs against
  the campaign's own surface (`_fuzz_mutations` builds deterministic
  boundary/injection/mass-assignment mutations per registered endpoint) and
  **every crash / timeout / anomaly observation spawns a new research
  thread** targeting that endpoint with the recorded fuzz evidence attached
  (`live_evidence`, objective names the signal).
- **Reproduction cycle**: the fuzz value is embedded in the mutation URL, so
  when the loop dispatches a spawned thread its re-probe hits the same
  crashing request and *reproduces* the 500 — the thread COMPLETES with
  recorded evidence through the F0.5 gate instead of refuting on a generic
  probe. Spawns are deduped per (endpoint, state); exhausted assets are
  re-activated so spawned threads dispatch.
- **Tests** (`tests/test_live_feedback_loop.py`, +4): fuzz crash spawns a
  thread the loop probes; spawned threads reproduce the crash (complete +
  `live_evidence` + 500 in `confirmed_behavior`); spawns dedupe across runs;
  `_fuzz_mutations` is deterministic/bounded. Full suite: 826 passing.

## v1.2.7 — Self-eval Task 10: exploitation phase

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `exploitation-phase` scores the live exploitation stage with 3 milestones
  — `exploits-recorded` (impact demonstrations persisted under
  `state/sessions/<target>/exploits.jsonl`), `reproduction-rate` (at least
  half of the recorded exploits reproduced: same input, second recorded
  response), and `impact-recorded` (at least one record carries
  `demonstrated_impact` — the data the replay actually returned). The
  harness is now 10 tasks / 100%.
- **E2E test** now asserts the fuzz-cycle exploitation ledger directly
  (≥1 record, all reproduced, impact captured) and scores the full 10-task
  self-eval at 100% — Task 10 artifacts produced by the live loop, not
  seeded.
- **Bundle check** seeds two exploit demonstrations (crash replay + data
  extraction, both reproduced with `demonstrated_impact`) so the eval passes
  from inside the bundle — 10/10 tasks, 100%.
- Full suite: 840 passing (task-count assertions bumped 9 → 10; the
  live-loop exploitation test also scores the task through the eval).

## v1.2.6 — Fuzz-blocked observations spawn bypass threads

- **`tools/core/fuzz_bridge.py` — WAF/blocked detection**: `classify_fuzz`
  now reuses `live_executor.detect_waf` (403/406/429 + known header/body
  fingerprints) and returns a first-class `blocked` state with
  `blocked by <defense> (<status>)` as the signal; the defense name is
  recorded in the observation evidence (`evidence["waf"]`). `FuzzSummary`
  gains a `blocked` counter; blocked observations publish on the bus like
  other signals.
- **`campaign_orchestrator._fuzz_and_spawn_threads`**: blocked observations
  now **spawn a `fuzz_blocked` bypass thread** instead of being ignored:
  the blocker is recorded through `failure_learning.learn` and bypass
  candidates are quarantined to
  `research/<target>/learning/failure-bypass-candidates.json`, and the
  spawned thread's objective names the bypass mission (carrying the blocked
  evidence as `live_evidence`). Deduped per (endpoint, fuzz state) like
  crash spawns; counted in `summary["fuzz"]["blocked"]` and `signals`.
- **Loop fix**: `_build_blocked_unit` no longer mislabels its operator-
  decision unit as `researching` (it has no `thread_id` — the live loop
  would crash on it); it is `research` phase, and the loop defensively
  stops on any thread-id-less unit instead of raising.
- **Self-eval Task 9**: `fuzz-to-thread-cycle` counts `blocked` observations
  as signals and scopes `reproduction-rate` to `fuzz_crash` threads
  (vacuous pass for blocked/timeout-only cycles — there is no 5xx to
  reproduce when the target blocks instead).
- **Tests**: +6 (blocked classification: bare 403, WAF header, precedence
  over timing anomaly, clean-with-headers, defense name recorded; live-loop
  blocked→spawn→failure-learning integration). Full suite: 840.

## v1.2.5 — Self-eval Task 9: fuzz-to-thread cycle

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `fuzz-to-thread-cycle` scores the Phase-3 fuzz bridge loop with 5
  milestones — `fuzz-ran` (runs persisted under `state/fuzz/<target>/runs.jsonl`
  with mutations), `signals-recorded` (crash/timeout/anomaly observations),
  `spawn-count` (a `fuzz_*` research thread exists), `reproduction-rate` (at
  least half of the spawned fuzz threads COMPLETED with recorded evidence and
  a 5xx in confirmed behavior), and `dedup` (threads unique per (endpoint,
  fuzz state)). The harness is now 9 tasks / 100%.
- **Lab fixture**: `lab/vulnbank/server.py` gains `GET /api/ingest` — a
  deterministic crash surface (500 on over-long or SQL-ish `q` input) so a
  real fuzz pass finds a crash, spawns a thread, and the loop reproduces it.
- **E2E test** now runs a genuine fuzz→spawn→reproduce cycle against the lab
  (fuzz pass → spawned thread → loop re-probes the crashing URL → 500
  reproduces → COMPLETE with evidence, deduped) and scores the full 9-task
  self-eval at 100% — Task 9 artifacts produced honestly, not seeded.
- **Bundle check** seeds a fuzz run + reproduced fuzz thread so the eval
  passes from inside the bundle — 9/9 tasks, 100%.
- Full suite: 834 passing (task-count assertions bumped 8 → 9; the E2E and
  live-loop tests now also assert the cycle end-to-end).

## v1.2.4 — Novel-class hunting consumes fuzz signals

- **`tools/zero_day.py` — `hunt_fuzz_signals` (NEW)**: feeds fuzz
  crash/timeout/anomaly evidence from `tools/core/fuzz_bridge` into the
  Phase-3 novel-class modes. Every signal becomes an **anomaly** candidate
  (the deterministic fuzz classifier's `signal` is now a first-class reason
  in `anomaly_detection_mode`, so a pure timeout with no status/timing delta
  still surfaces) and every crash becomes a **behavior-differential**
  candidate (same endpoint, oracle vs mutated input). Every candidate is
  stamped with fuzz provenance (`mutation_id`, `kind`, `state`, `replay_key`)
  and confidence is scaled by signal strength (crash 0.7 / timeout 0.6 /
  anomaly 0.55). Accepts `FuzzObservation` dataclass instances or dicts;
  deterministic and pure (no persistence, no live probing).
- **Orchestrator wiring**: `_fuzz_and_spawn_threads` now registers the fuzz
  candidates through the zero-day engine (novelty-assessed, deduped) and
  persists them to `research/<target>/zero-day/fuzz-signals.jsonl`;
  `live_feedback_loop` reports them as `summary["fuzz"]["novel"]`. Advisory
  — a feed failure never gates the fuzz pass.
- **Tests**: +5 zero-day fuzz-feed tests (anomaly signal reason, both modes,
  clean-ignored, dataclass duck-typing, determinism) + live-loop assertion
  that fuzz crashes produce registered novel candidates. Full suite: 834.

## v1.2.3 — Self-eval Task 8: live execution loop

- **New eval task** (`tools/validation/self_eval_harness.py`):
  `live-execution-loop` scores the Phase-3 live loop with 4 milestones —
  `probes-recorded` (evidence persisted under `state/sessions/*/probes.jsonl`),
  `probe-count` (≥3 records), `adaptation` (>1 distinct verdict, mirroring
  `live_executor.classify_probe` semantics: strong anomalies + bug-class
  confirmations are signals, generic header fingerprints are not), and
  `reproducible-evidence` (records carry `replay_key` + recorded request).
  The harness is now 8 tasks / 100%.
- **Bundle check** seeds deterministic probe records (signal/clean/blocked)
  so the eval still passes from inside the bundle — 8/8 tasks, 100%.
- **E2E deep-dive test** now runs a genuine live probe pass against the lab
  (idor → 200 signal, sql-injection → 404 clean, auth_bypass → 200 signal)
  with recorded request/response evidence, then scores the full 8-task
  self-eval at 100% — Task 8 artifacts are produced honestly, not seeded.
- Full suite: 829 passing (all task-count assertions bumped 7 → 8).

## v1.2.2 — Live exploitation phase

- **Exploit-after-confirm**: `live_feedback_loop` now replays every
  gate-CONFIRMED finding's recorded request via
  `tools/core/live_executor.execute_exploit` (same input → second recorded
  response). The impact demonstration — `replayed_status`, `reproduced`,
  `demonstrated_impact` (the data actually returned) — is stored on the
  thread (`ThreadRecord.live_exploit`, serialized + round-tripped) and
  appended to `state/sessions/<target>/exploits.jsonl`. Only findings the
  F0.5 gate marked report-eligible are exploited; refuted threads never are.
  Opt out with `--no-exploits` (or `run_exploits=False`).
- **Verified against the lab**: the idor + auth_bypass findings on
  VulnBank reproduce live → both exploited (`reproduced=True`, status 200,
  `demonstrated_impact` carries the user record), ledger written.
- **Tests** (`tests/test_live_feedback_loop.py`, +3): confirmed findings are
  exploited + recorded; `run_exploits=False` produces zero exploits; refuted
  threads are never exploited. Full suite: 829 passing.

## v1.1.1 — Phase 2: F0.5 Validation + Core Upgrades (U1–U5)

- **E2E integration test**: `tests/test_e2e_deep_dive_campaign.py` turns the
  manual deep-dive driver into a repeatable, isolated test — it boots the
  VulnBank lab fixture in-process on an ephemeral port (no fixed port, no
  external process), runs the full campaign (U4 pass@k variants → U2
  artifact bridging → U3 strict gate → U1 fast-path → U5 routing → 12-stage
  workflow with append-only triage hash-chaining → 7-task self-eval) and
  asserts every upgrade: 7/7 eval tasks at 100% milestones, 21 threads
  split 7/7/7 across variants, quarantine vs. ledger split (3 findings,
  2 report-eligible, 1 demoted), both model tiers routed, all 7 fast-path
  checkpoints fired, 12 evidence families bridged. Skips cleanly when the
  lab fixture is absent (e.g. from inside a bundle, which does not ship
  `lab/`). ~1.5s per run.

- **Fix (E2E-verified)**: `GRAPHQL_CANDIDATE` is now a registered signal-bus
  event type. `graphql_batch_analyzer` publishes it, but the bus previously
  rejected unknown types, so the `except Exception: pass` guard silently
  swallowed every GraphQL candidate signal — the event-driven layer never
  saw them. Registered in `EVENT_TYPES` + `CANONICAL_LISTENERS`; regression
  test added (`test_graphql_candidate_event_registered_and_persisted`).
- **Fail-loudly bus publishing**: every domain/intelligence/validation tool
  that publishes to the signal bus now goes through a single
  `tools.core.signal_bus.publish_or_warn()` helper. Environmental failures
  (unwritable event log → `OSError`) remain advisory — reported to stderr,
  never gating the tool — but *programming* errors (an unregistered event
  type → `ValueError`, a malformed payload → `TypeError`) now propagate
  loudly instead of vanishing inside `except Exception: pass`. All 20
  publish sites updated (oauth/jwt/smuggling/graphql/bopla analyzers,
  ato/rag/tool-auth/contract-triage/price-manip, iam/deep-link/mobile,
  seed/failure-learning/chain-ai, verification-lab, asset-delta, self-eval,
  campaign orchestrator). This is what let the unregistered
  `GRAPHQL_CANDIDATE` bug ship silently; it would now fail CI immediately.

- **F0.5 precision-first validation (U3, approved)**: `tools/refutation.py`
  is now confidence-gated by default — deterministic evidence-derived scoring
  (reproducible trigger trace, impact trace, evidence refs, endpoint,
  confirmed behavior);  below-threshold findings are DEMOTED,
  `eligible_for_report=false`, and quarantined as candidate records to
  `state/learning/<target>.jsonl`. `--no-strict` preserves the legacy
  UNCENSORED auto-confirm mode. `tools/triage.py` gained strict confidence
  bands and quarantine for sub-threshold candidates. The quarantine store is
  hash-chained into the workflow: when non-empty it is recorded as an
  append-only supplementary artifact of the `triage` stage — a
  `lines:N:sha256` prefix digest that must stay intact while later
  quarantine appends (tampering/truncation) never invalidate the stage.
  The gate is now wired into the campaign: `register_thread_result` runs
  every completed thread through the strict gate automatically —
  evidence-rich findings are CONFIRMED, appended to
  `state/sessions/<target>/findings.jsonl` (also a hash-chained
  triage-stage artifact) and counted in `report_eligible_findings`;
  unit dispatch records advisory routing decisions as `unit_routed` audit
  events (read by the self-eval harness's pass@k/routing task);
  low-confidence findings are DEMOTED + quarantined and never reach the
  findings ledger or the report. Evaluation is idempotent per thread and
  the verdict rides on `FINDING_DISCOVERED` events. Reporting gates only —
  uncensored execution is untouched.
- **Intelligent model routing (U5)**: new `tools/core/model_router.py`
  classifies every research unit into deterministic / local_slm / frontier
  tiers with an advisory `model_preference` hint in unit context; routing
  never gates and degrades gracefully when a model tier is unavailable.
- **Elicitation gap bridging (U2)**: thread/recon/discovery research units
  now carry `context["deterministic_evidence"]` + `artifact_paths` pointing
  at the WAF payload families, smuggling plans, JWT/OAuth/GraphQL/ATO plans
  that exist for the target — grounding harness intent in deterministic
  execution details.
- **Fast-path hypothesis engine (U1)**: `research_loop.py` gained a
  non-blocking `on_checkpoint` hook (fires after every executed checkpoint,
  handler failures logged and swallowed) plus deterministic
  `fast_path_signals()` trigger detection (`waf-bypass-payloads`,
  `canonical-source-fresh`, `search-signal`) — parallel deep-dive research
  without touching the mandatory-7 sweep or `latest_ready`.
- **Test-time compute scaling (U4)**: `campaign_orchestrator.py` gained
  `--pass-at-k <k>` / `--deep-dive` (preset 3); each threat spawns `k`
  diverse variant threads (`pass_variant` 0..k-1, shared `pass_group`) with
  rotated `system_prompt` + `suggested_approaches`, dispatched
  deterministically (variant-aware dedupe, default `pass_at_k=1` unchanged).

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
- **Self-eval harness grew to 7 tasks**: new `test-time-compute-routing`
  task scores pass@k variant threads (`pass_variant >= 1` with shared
  `pass_group` in `state/campaigns/<t>/threads/*.json`) and model-routing
  diversity (`unit_routed` audit records with ≥2 distinct `model_tier`s in
  `state/campaigns/<t>/audit.jsonl`). Unit dispatch now audits routing
  decisions via `CampaignManager.log_event`; CI bundle check requires
  **7/7 tasks (100%)**.
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

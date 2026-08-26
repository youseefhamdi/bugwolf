# 🐺 BugWolf Enhancement Plan — APT-Grade Autonomous Hunting Platform

> **Plan Mode deliverable** · v1.0.1 baseline · Architecture: **Strict Workflow, Uncensored Execution**
> Research window: **2026-focused** — 2026 literature, talks, bounty platforms, and tooling (with 2025 foundations cited where 2026 research builds on them). Every citation is dated; 2026 sources are marked ★.
> All enhancements below integrate with the 12-stage pipeline + 7-checkpoint research loop and never re-introduce execution-layer gates.

---

## 1. Executive Summary

BugWolf is already a strong platform: a strict 12-stage workflow (depth enforcement via artifact prerequisites and hash-chain integrity), a mandatory 7-checkpoint research loop, an uncensored execution layer, ~75 deterministic tools, and a self-driving campaign engine. The 2025–2026 security research landscape shows exactly where the next generation of depth comes from:

1. **Semantic, agentic analysis beats rule-based scanning.** OpenAnt (arXiv 2606.19149) cut analysis surface by up to 97% via reachability-filtered code decomposition, applied adversarial verification to cut false positives, and validated findings with sandboxed dynamic execution. OpenAI's Aardvark (Oct 2025) and AISLE (12 OpenSSL CVEs by Feb 2026) prove LLM-driven discovery finds real 0-days. **Gap:** BugWolf's zero-day track is rule/template-driven; it needs an LLM-assisted verification and decomposition layer on top of its deterministic cores.
2. **Protocol/parser differentials are the highest-value web frontier.** PortSwigger's "HTTP/1.1 Must Die" line (0.CL via `Expect: 100-continue` CVE-2025-32094, TE.0, H2.CL/H2.TE, browser desync) earned $350K+ in 2025 bounties; WAFFLED (arXiv 2503.10846) confirmed 1,207 WAF bypasses via structural parsing discrepancies. **Gap:** BugWolf has a smuggling *agent doc* but no deterministic smuggling/parser-differential detector.
3. **Authorization flaws remain the #1 API/mobile class** (OWASP API Top 10: BOLA/BFLA; HackerOne 2025 HPSR shows a rise in "understand the system" categories — business logic over payloads). **Gap:** BugWolf has strong IDOR matrices; needs BFLA/privileged-function matrices and business-logic state-machine analysis.
4. **Identity/auth research is deep and current.** USENIX Security 2025 (OAuth 2.0 integration platforms — COAT cross-app account takeover, request forgery), JWT algorithm/key confusion. **Gap:** BugWolf has no JWT forgery or OAuth flow analyzer.
5. **Cloud privesc catalogs are now actionable.** Rhino Security's 21 AWS IAM privesc methods, ECS-cape (Black Hat USA 2025), K8s init-container policy evasion. **Gap:** BugWolf has cloud *posture* tooling but no IAM privesc graph engine.
6. **LLM-guided fuzzing is proven.** LLAMAFUZZ (better coverage than AFL++), directed greybox fuzzing via LLM (arXiv 2505.03425), semantic-aware mutation (arXiv 2509.19533). **Gap:** BugWolf's ART4SQLi selector is static; an LLM-guided seed/mutation advisor would deepen coverage.
7. **Agentic AI security has its own taxonomy now** (OWASP Top 10 for LLM 2025/2026 + Top 10 for Agentic Applications 2026 — goal hijack, tool misuse, identity/privilege abuse, memory poisoning). **Gap:** BugWolf maps ASI01–10 but lacks tool-auth-flow and memory-poisoning analyzers.
8. **The LLM contract track is mainstream.** Smart-contract LLM detectors show high recall/low precision (ACM 3702973) — the answer is LLM + symbolic/formal verification hybrids, plus price-manipulation lifecycle analysis (arXiv 2608.15518). **Gap:** BugWolf needs an LLM-assisted triage layer over its existing invariant executor and formal-verify bridge.
9. **Multi-agent orchestration research converges on planner-orchestrator patterns** (arXiv 2601.13671; MDPI survey 2026) — exactly BugWolf's campaign architecture. **Gap:** add LLM plan synthesis, failure-driven self-healing, and graph-based chain synthesis.

### 1.1 The 2026 Landscape — What Changed This Year

The 2026 research window (through Aug 2026) sharpens the plan in five ways:

1. **Agent4Pentest matured into a taxonomy.** A systematic survey of 81 papers (2023–Jun 2026, ★ arXiv 2607.02605) codifies a six-category taxonomy and a **four-phase architectural evolution**: text-only reasoning → tool-augmented → multi-agent → **RLVR-trained** (reinforcement learning with verifiable rewards). Each transition was driven by a distinct capability bottleneck; RLVR marks the shift from imitating human demos to reward-driven discovery of undocumented attack strategies. **BugWolf sits at phase 3 (multi-agent campaign); phase 4 — reward-driven self-improvement of its research/chain heuristics — is the 2026 upgrade path for `adaptive_learning.py`.**
2. **Benchmarks are now the honest scoreboard.** The 2026 benchmark pass (★ Stingrai, Jul 2026): XBOW topped HackerOne's US leaderboard (~1,060 reports / 90 days, human-reviewed before submission); ARTEMIS placed 2nd of 11 vs. human pros on a live 8,000-host network (82% valid, but higher false-positive rate than every human, ~$59/hr); on CVE-Bench the best agent exploited only **13% of critical web CVEs zero-day (25% one-day)**. The field's open challenges are evaluation reliability, multi-stage attack chains, and training-data scarcity. **BugWolf should build an AutoPenBench-style milestone-scored harness so its depth gains are measurable, not claimed.**
3. **Business logic is the documented AI weak spot.** HackerOne's 9th HPSR (Oct 2025): 58% of researchers name business logic as the class AI tools are weakest at identifying — precisely where BugWolf's state-machine/race-condition plan (§4.1) differentiates.
4. **Agentic-AI security has a numbered taxonomy.** ★ OWASP Top 10 for Agentic Applications 2026 (ASI01–10): goal hijack, tool misuse, identity/privilege abuse, memory poisoning — while BOLA remains ~40% of API attacks (★ OWASP API Top 10 2026) and AI-powered API attacks rank as the #1 exploited 2026 vector (★ CybelAngel).
5. **The parser/desync frontier continues.** ★ Kettle's "Can AI Do Novel Security Research? Meet the HTTP Terminator" (Black Hat USA 2026 / DEF CON 34) keeps smuggling/smuggling-adjacent "raw gadget" attacks the highest-value web class; ★ 23 new 403-bypass techniques succeed in 61% of tested apps (CTI Labs 2026).

**The strategy:** keep every deterministic core (hash-chained artifacts, invariant executors, ART4SQLi, state machines) and wrap them with **LLM-as-advisor layers** that produce hypotheses, decompositions, and verification plans — all flowing through the existing 12-stage artifacts and 7 research checkpoints. Execution stays uncensored; depth enforcement grows.

---

## 2. Phase 1 — Deep Research Findings

### 2.1 Automation & Orchestration (cross-cutting)
**Top findings**
1. **OpenAnt** (Knostic; arXiv 2606.19149, Jun 2026) — repo-scale LLM vuln discovery via (a) code decomposition filtered by reachability from external entry points (**97% surface reduction**), (b) **adversarial verification** (constrained attacker simulation, cuts false positives), (c) **dynamic verification** in throwaway sandboxed containers. Found real 0-days in OpenSSL, WordPress, Flowise.
2. **Aardvark** (OpenAI, Oct 2025) — autonomous security researcher that finds, validates, and fixes vulnerabilities; confirms the closed-loop pattern.
3. **AISLE** (Ken Huang, Apr 2026) — began analyzing OpenSSL Aug 2025, 12 new CVEs in OpenSSL 3.6.1 by Feb 2026 — long-horizon autonomous analysis works.
4. **AutoPen** (ACM 3772886.3772899, Dec 2025) — LLM-agent pentesting with high task stability; validates planner-agent loops.
5. **Multi-agent orchestration surveys** (arXiv 2601.13671, Jan 2026; MDPI Future Internet 18(6):326, 2026) — orchestrator-as-brain, specialist agents, shared memory, recovery loops. BugWolf's `campaign_orchestrator.py` already implements this shape.
6. ★ **Agent4Pentest taxonomy & four-phase evolution** (arXiv 2607.02605, Jul 2026) — 81 papers (2023–2026) in six categories; text-only → tool-augmented → multi-agent → **RLVR-trained**; RLVR = reward-driven self-improvement that discovers undocumented attack strategies (vs. imitation of demos); CTF platforms double as RL training substrates.
7. ★ **Benchmark reality check** (Stingrai scoreboard, Jul 2026) — XBOW #1 on HackerOne US (~1,060 reports/90d, human-reviewed); ARTEMIS 2nd/11 vs. pros on live 8,000-host net (82% valid, higher FP than humans); CVE-Bench 13% zero-day / 25% one-day; HackerOne 210% YoY valid AI reports + 540% prompt-injection reports. Lessons: measure with milestone partial-credit, state the setting, keep a human confirmation gate.
8. ★ **Memory-activated & stateful orchestration** (Shell-or-Nothing benchmark + memory-activated agents, May 2026; LangGraph stateful multi-agent frameworks 2026) — durable, checkpointed state and persistent memory are what let agents hold multi-stage attack chains; matches BugWolf's deterministic campaign state machine.

**Emerging trends:** closed-loop discover→verify→validate pipelines; long-horizon (multi-month) autonomous agents; sandboxed dynamic validation as the FP killer; planner/executor separation; ★ reward-driven (RLVR) capability acquisition; ★ evaluation harnesses as first-class engineering artifacts.

**Tool gaps:** most tools are either rule-based SAST (high FP) or pure LLM chat wrappers (no verification). Few combine deterministic cores + LLM reasoning + dynamic validation with a strict workflow.

### 2.2 Reconnaissance & OSINT
**Top findings**
1. **Historical DNS & certificate transparency analysis** — AI models mine historical DNS data (passive, zero packets to target) to find subdomains/infrastructure changes; CT log analysis (crt.name/crt.sh) is standard but historical apex/dns-history (SecurityTrails-style) adds forgotten-infrastructure finds.
2. **Passive-first recon doctrine** — passive OSINT minimizes detection (Cognyto/securelayer7 guidance, 2025); DNS zone transfers, WHOIS pattern analysis, and naming-convention extrapolation ("new registrations resembling the group's naming convention").
3. **AI-assisted asset correlation** — LLMs infer brand/product wordforms and org-relationships to seed wordlists (BugWolf's `wordlist_gen.py` does this deterministically; LLM seeds would improve recall).
4. **Radar / historical DNS platforms** — subdomain enumeration over time reveals removed-then-reattached infra (Classic DNS rebinding of assets).
5. ★ **AI-powered OSINT automation** (ShadowDragon 2026; chs.us 2026) — LLM-assisted intelligence gathering extends to historical DNS, blockchain, and social layers; an automated OSINT pipeline fusing CT logs + passive DNS + AS announcements reaches near-real-time asset discovery (MDPI Computers 14(10):430, Oct 2025) — exactly the shape of BugWolf's planned `historical_asset_delta.py`.

**Emerging trends:** historical data as first-class recon source; LLM-driven enumeration planning; asset graph correlation (org → subsidiaries → infra); ★ near-real-time passive fusion pipelines.

**Tool gaps:** most recon tools are snapshot-based (one moment in time); few track *deltas* over time; almost none do LLM-driven "what would this org name next?" discovery.

### 2.3 Web Application Security
**Top findings**
1. **Protocol desync / request smuggling frontier** — PortSwigger (James Kettle) "HTTP/1.1 Must Die": 0.CL via `Expect: 100-continue` (CVE-2025-32094, Akamai/LastPass), TE.0, H2.CL/H2.TE, browser desync; $350K+ in 2025 bounties from a two-week sprint (jsmon.sh, May 2026; vulnsy cheat sheet).
2. **Parser-differential WAF bypass** — WAFFLED (arXiv 2503.10846) confirmed **1,207 bypasses** via structural parsing discrepancies across WAF/framework combos; taxonomy: header/line-ending/whitespace/parameter-parsing divergence.
3. **HTTP/2-specific attacks** — request tunneling, H2.TE desync, connection-level smuggling (PortSwigger; decryptiondigest WAF-bypass guide 2026).
4. **Business logic as the 2025-26 bounty driver** — HackerOne 2025 HPSR: rise in categories requiring understanding how systems work (workflow skip/repeat/reorder, state machines, race windows) over payload mechanics.
5. **LLM-guided greybox fuzzing** — LLAMAFUZZ (LLM structured mutation + greybox, beats AFL++ coverage), directed greybox via LLM (arXiv 2505.03425), semantic-aware mutation (arXiv 2509.19533).
6. ★ **"Meet the HTTP Terminator"** (James Kettle — Black Hat USA 2026, Aug 5 / DEF CON 34, Aug 7) — smuggling raw gadgets into frameworks/platforms; the parser/desync frontier continues past 2025's `Expect: 100-continue` class.
7. ★ **403-bypass catalog** (CTI Labs, 2026) — 23 new access-control circumvention techniques succeed in 61% of tested web apps (header/verb/extension/path-normalization divergences).
8. ★ **Top 10 Web Hacking Techniques, 19th ed.** (PortSwigger community, Feb 2026) — blind SSTI via polyglot payloads (Korchagin) revives template-injection hunting with delay/oracle-free detection.
9. ★ **TRIGFUZZ** (IEEE S&P 2026) — triggering-condition-guided directed fuzzing generates high-quality conditions for 96.67% of target vulnerabilities; the web analog is race-condition/state-machine trigger construction for business-logic flaws.

**Emerging trends:** parser differentials over payload volume; smuggling via edge/HTTP2; business-logic/state-machine depth; LLM mutation for coverage; ★ generated access-control bypass catalogs (403 → 61%); ★ trigger-condition planning for races/state machines.

**Tool gaps:** smuggling detection is manual (Burp extension exists but no deterministic CLI); WAF-bypass catalogs are static lists (BugWolf's 15 techniques) not *generated* per-parser; race-condition tooling is immature — ★ TRIGFUZZ-style trigger-condition planning is the 2026 approach; business-logic detection is doc-driven only (★ the #1 AI-weak class per HackerOne 9th HPSR: 58%).

### 2.4 API Security
**Top findings**
1. **BOLA/BFLA dominate** (OWASP API Security Top 10 2023/2026 lens; Wiz 2026) — object-level and **function-level** authorization failures; BOLA via ID manipulation, BFLA via privileged-endpoint invocation (Invicti 2026: combined chains).
2. **GraphQL attack surface** — introspection abuse, **batching/alias abuse (DoS, rate-limit bypass)**, field-duplication DoS, SSRF via URL-typed fields, gid enumeration (HackerOne #1618347 class — already in BugWolf).
3. **Mass assignment / object property level authorization (API3)** — over-POSTing fields; BugWolf's `mutator.py` has mass-assignment plans; formal BOPLA matrices are missing.
4. **Agentic-API lens (2026)** — APIs now front LLM agents; OWASP API Top 10 through the agentic lens (Aptori 2026): broken object property auth becomes "agent-controlled params".
5. ★ **2026 API risk landscape** (CybelAngel, Dec 2025; xhack OWASP API Top 10 2026 guide, Jun 2026) — AI-powered API attacks rank #1 exploited vector for 2026; shadow APIs and supply-chain compromise rising; BOLA still ~40% of API attacks.

**Emerging trends:** BFLA/BOPLA tooling catching up to BOLA; GraphQL batching as a first-class check; agent-callable API abuse; ★ shadow-API discovery and AI-driven abuse as 2026 vectors; ★ BOLA persistence (~40%) keeps object-level matrices the top priority.

**Tool gaps:** BugWolf covers BOLA + GraphQL gid + mass assignment; missing **BFLA matrices** (role A calls role-B function), GraphQL batching/alias analyzers, and rate-limit bypass planning.

### 2.5 Authentication & Authorization
**Top findings**
1. **OAuth 2.0 integration-platform attacks** — USENIX Security 2025 (Luo et al.): **COAT** (cross-app OAuth account takeover) and request forgery in integration platforms due to lack of app differentiation.
2. **JWT algorithm/key confusion** — `alg=none`, RS256→HS256 confusion, jwk header injection, key confusion via public key as HMAC secret (PortSwigger; Doyensec 2025; DataDog rule def-000-t6u).
3. **SSO stack audit** — SAML/OAuth/OIDC/JWT flaw catalog (guptadeepak 2025): CSRF in auth flows, redirect_uri validation gaps, state/Nonce reuse, token-in-URL leakage, PKCE downgrade.
4. **ATO chains** — account takeover via email-change flows, MFA bypass (recovery flows, backup codes), session fixation (bug-bounty writeup corpus).
5. ★ **2026 OAuth bypasses** — CVE-2026-48611 OAuth authentication bypass (SentinelOne VDB, Jun 2026); bug-bounty OAuth misconfiguration → full ATO via PKCE + open client registration (InfosecWriteups, Jun 2026).

**Emerging trends:** cross-application identity confusion; JWT library misconfiguration as top issue; MFA bypass via recovery flows; ★ PKCE/redirect_uri misuse as a recurring 2026 ATO root cause.

**Tool gaps:** BugWolf has `identity_cloud.py` (posture/CVE triage) and dual-session IDOR; **no JWT forgery/confusion checker**, no **OAuth flow state-machine analyzer**, no **ATO chain planner**.

### 2.6 Cloud Security
**Top findings**
1. **AWS IAM privesc catalog** — Rhino Security Labs: **21 privesc methods** (iam:PassRole, iam:CreatePolicyVersion, lambda:CreateFunction with existing role, glue/cloudformation/sagemaker service-role hijack); hackingthe.cloud 2025 techniques.
2. **ECS-cape** (Black Hat USA 2025) — low-privileged ECS task hijacks IAM privileges via `amazon-ecs-agent`/docker socket & credential endpoints; container-escape → IAM-boundary crossing.
3. **Serverless & K8s** — Lambda cold-start privilege escalation; K8s init-container policy evasion (ResearchGate 2025).
4. **Exposure management** — continuous asset/IAM drift detection over one-off scans (Cognyto 2025).

**Emerging trends:** IAM-graph privilege escalation modeling (pmapper-style); container-escape → IAM pivot chains; drift-aware scanning.

**Tool gaps:** BugWolf has cloud *posture* + CI-CD vector catalogs; **no IAM privesc graph engine**, no container-escape planner, no serverless-attack planner.

### 2.7 Smart Contracts & DeFi
**Top findings**
1. **LLM detectors: high recall, low precision** (ACM 3702973, "When ChatGPT Meets Smart Contract Vulnerability Detection") — LLMs alone flood FPs; must pair with program analysis.
2. **Price-manipulation lifecycle detection** (arXiv 2608.15518, Aug 2026) — lifecycle-oriented framework for oracle-manipulation/price-manipulation in DeFi; pairs economic modeling with invariant checks.
3. **OWASP Smart Contract Top 10** — reentrancy, access control, arithmetic, unchecked external calls, bad randomness, DoS, front-running, time manipulation, insecure upgradeability, oracle issues.
4. **LLM + symbolic/formal hybrids** — combining LLM reasoning with symbolic execution, relational value analysis (reentrancy), Medusa/Echidna fuzzing, Certora CVL (BugWolf's `formal_verify.py` already bridges).
5. ★ **CyberChainBench** (arXiv 2606.26216, Jun 2026) — a three-task LLM-agent benchmark for smart-contract security; the evaluation harness BugWolf's contract track should target.
6. ★ **Analyzer coverage audit** (arXiv 2603.00890, MSR '26) — commercial analyzers detect oracle-manipulation attacks <40% of the time; quantifies the price/oracle-manipulation gap BugWolf's analyzer would fill.
7. ★ **Agentic attack synthesis + RAG formal verification** (arXiv 2607.15673, Jul 2026; arXiv 2608.13191, Aug 2026) — LLM agents synthesize/simulate contract exploits; RAG-retrieved invariants drive formal property generation. OWASP Smart Contract Top 10: 2026 released.

**Emerging trends:** LLM-assisted audit → formal verification pipeline; economic/invariant-aware analysis (not just code patterns); cross-chain (Move/Solana) parity; ★ RAG-property-driven formal verification; ★ agentic exploit synthesis.

**Tool gaps:** BugWolf has `contract_discovery.py` (invariant executor) + `formal_verify.py` (CVL/fuzz harnesses); missing LLM-assisted candidate triage (FP killer), price/oracle manipulation analysis, and upgradeability-pattern checks.

### 2.8 LLM / Agentic AI Security
**Top findings**
1. **OWASP Top 10 for LLM Apps 2025/2026** — prompt injection (direct + **indirect**), training-data poisoning, supply chain, sensitive-info disclosure, excessive agency.
2. ★ **OWASP Top 10 for Agentic Applications 2026 (ASI01–10)** — ASI01 agent goal hijack, ASI02 tool misuse/exploitation, ASI03 identity & privilege abuse, ASI04 memory poisoning, plus excessive agency, insecure MCP tool boundaries, and supply chain (Human Security 2026; Cycode 2026; Deepteam 2026).
3. **Indirect prompt injection via RAG/memory/tool output** is the dominant real-world vector (Aembit 2025; Simuna 2026).
4. **Tool/memory poisoning** — attacker-controlled data in agent memory or RAG corpus alters agent behavior (OWASP ASI).

**Emerging trends:** agent identity/privilege (ASI03) as the new "broken auth"; memory as an attack surface; MCP (Model Context Protocol) tool-authorization boundaries.

**Tool gaps:** BugWolf maps the taxonomies (`llm_attack_surface.py`, `ai_defense.py`) but lacks **tool-authorization flow analysis** (which tool calls carry attacker-influenced args), **memory/RAG poisoning planners**, and **MCP OAuth/token boundary checkers** (paper_intel has control-plane audit; needs execution-oriented planning).

### 2.9 Mobile Security
**Top findings**
1. **OWASP Mobile Top 10 2025** — improper credential usage, inadequate supply-chain security, insecure auth, insufficient cryptography, inadequate binary protection, code tampering.
2. **Deep-link attacks** (MASTG-TEST-0028) — link hijacking, sensitive navigation via deep links, App Links verification bypass.
3. **Certificate-pinning bypass** — Frida/objection-based runtime patching; pinning as defense-in-depth (MASTG discussion).
4. **OWASP MASVS** — verification standard; binary/static + dynamic pairing.
5. ★ **2026 MAST tooling landscape** (Appknox, Jun 2026) — cert-pinning bypass + MASVS compliance are table stakes; 175+ Android vulnerability categories → informs `mobile_policy_checker.py`'s check catalog.

**Emerging trends:** deep links as auth/state attack surface; supply-chain (SDK/3P lib) risk; hybrid apps (WebView bridges) as web-to-mobile pivot; ★ pinning-bypass as table-stakes MAST coverage.

**Tool gaps:** BugWolf has `mobile-vectors.md` + PendingIntent/WebView markers in the zero-day track; **no deep-link analyzer** (scheme/host/path → intent → exported activity), no manifest/plist policy checker, no pinning-bypass planner.

---

## 3. Phase 2 — BugWolf Gap Analysis

### 3.1 Gap table (current vs. missing)

| Domain | Current capability | Missing capability | Impact | Feasibility |
|---|---|---|---|---|
| **Automation** | Campaign engine, thread lifecycle, result registration | LLM plan synthesis per unit; failure-driven self-healing; sandboxed dynamic verification | **High** | Medium |
| **Recon** | Multi-source enumeration, CT, wordlist_gen, tech fingerprint | Historical DNS/CRT delta tracking; LLM-assisted naming extrapolation; asset drift detection | Medium | Medium |
| **Web** | Smuggling *doc/agent*, 15 WAF bypasses, ART4SQLi | Deterministic **smuggling detector** (CL.TE/TE.CL/TE.TE/H2/0.CL/TE.0); **parser-differential WAF bypass generator** (WAFFLED-style); race-condition engine; business-logic state machine | **High** | High (detector), Medium (logic) |
| **API** | IDOR matrices, GraphQL gid, mass assignment, ART4SQLi | **BFLA matrices** (function-level); GraphQL **batching/alias** analyzer; BOPLA over-POST matrix; rate-limit bypass planner | **High** | High |
| **Auth** | identity_cloud posture, dual-session diff | **JWT forgery/confusion checker**; **OAuth flow analyzer** (COAT-style, redirect_uri, PKCE); ATO chain planner | **High** | High |
| **Cloud** | cloud posture, CI-CD vectors, identity_cloud | **IAM privesc graph** (21 Rhino methods); container-escape planner; serverless/Lambda planner | **High** | Medium |
| **Smart contracts** | invariant executor, formal_verify bridges, economic agents | **LLM-assisted candidate triage** (FP killer); **price/oracle manipulation analyzer**; upgradeability checks | **High** | Medium |
| **LLM/Agentic** | taxonomy mapping, ai_defense, control-plane audit | **Tool-authorization flow analyzer** (ASI03); **memory/RAG poisoning planner**; MCP token/boundary checker | **High** | Medium |
| **Mobile** | vectors doc, PendingIntent/WebView markers | **Deep-link analyzer**; manifest/plist policy checker; pinning-bypass planner | Medium | High |

### 3.2 Priority ranking (impact × feasibility)

1. **P0 — HTTP smuggling detector + parser-differential WAF bypass** (High×High) — the 2025–26 frontier (★ Kettle "HTTP Terminator", DEF CON 34; WAFFLED), deterministic, testable.
2. **P0 — Business-logic state machine + race/trigger-condition planner** (High×High) — ★ the #1 class AI tools miss (58% per HackerOne 9th HPSR); TRIGFUZZ-style trigger-condition construction is the 2026 method.
3. **P0 — BFLA matrices + GraphQL batching analyzer** (High×High) — top OWASP API class after BOLA (★ ~40% of API attacks).
4. **P0 — JWT forgery/confusion + OAuth flow analyzer** (High×High) — self-contained static/offline analyzers; ★ 2026 OAuth bypass CVEs (CVE-2026-48611).
5. **P1 — IAM privesc graph** (High×Medium) — catalog-backed, offline (21 Rhino methods).
6. **P1 — LLM-assisted triage layer over zero-day + contract tracks** (High×Medium) — OpenAnt-style adversarial verification to cut FPs; ★ CyberChainBench as the contract-track eval target.
7. **P1 — LLM-guided seed/mutation advisor for discovery_scheduler** (Medium×Medium) — LLAMAFUZZ-style.
8. **P1 — Tool-authorization flow analyzer + memory-poisoning planner (agentic)** (High×Medium) — ★ ASI02/ASI03/ASI04.
9. **P1 — BugWolf self-evaluation harness** (Medium×High) — ★ AutoPenBench-style milestone partial-credit scoring + "three-question" setting discipline (CTF vs live / what's handed to the agent / who confirms), so agent-depth gains are measured (CVE-Bench 13% lesson).
10. **P2 — Deep-link analyzer, mobile manifest checker** (Medium×High).
11. **P2 — Price/oracle manipulation analyzer (DeFi)** (High×Medium) — ★ analyzers detect <40% today (MSR '26).
12. **P2 — Historical DNS delta tracker** (Medium×Medium).
13. **P2 — Dynamic research checkpoints + failure-driven self-healing** (Medium×Medium).
14. **P2 — Race-condition engine** (High×Low feasibility — absorb into #2 as trigger-condition planning).

---

## 4. Phase 3 — Comprehensive Development Plan

> All tools follow existing conventions: deterministic core, `--json` output, artifact writes into the 12-stage layout, integration with research-loop checkpoints, **no scope/confirmation gates** (uncensored execution preserved).

### 4.1 Web Application Security
- **Current:** smuggling/waf-bypass agent docs; mutator with 15 WAF bypass techniques; ART4SQLi payload selection; header_trust; cache poisoning.
- **Enhancements (research-backed):**
  1. **`tools/http_smuggling_detector.py`** (NEW) — deterministic probe generator + differential/time-based oracle for **CL.TE, TE.CL, TE.TE (obfuscated TE), H2.CL, H2.TE, 0.CL (Expect: 100-continue), TE.0** (PortSwigger 2024–25 frontier; CVE-2025-32094 class). Outputs `recon/<t>/discovery/smuggling-plan.jsonl` + candidate leads via `--json`. Feeds the **coverage-plan** stage artifact; live replay routes through the pass-through execution controller.
  2. **`tools/parser_differential.py`** (NEW) — WAFFLED-style (arXiv 2503.10846) structural-parsing discrepancy generator: header folding, CR/LF variants, tab-in-header, whitespace/parameter splitting, chunked framing, HTTP/2 pseudo-header order. Generates WAF-bypass payload families *per detected stack* (from tech-fingerprint artifact) instead of a static 15-item list. Emits payloads into the `bypass` research checkpoint + mutator pools.
  3. **Enhance `tools/mutator.py`** — consume parser-differential payload families; add HTTP/2-aware mutation kinds.
  4. **`tools/race_engine.py`** (NEW, P2) — race-window planner (TOCTOU, payment race, coupon reuse) with parallel-request orchestration plans and deterministic replay fixtures; keeps the 5-minute rule in mind.
- **Integration:** `coverage-plan` artifact (smuggling/differential plans); `bypass` checkpoint (WAF payload refresh); leads ledger.
- **Expected impact:** detects the highest-value 2025 web class (smuggling/desync) and replaces static WAF lists with generated ones.

### 4.2 API Security
- **Current:** IDOR matrices (direct/UUID/encoded/composite/second-order/file/GraphQL/mobile/WebSocket), GraphQL gid, mass-assignment mutation, ART4SQLi.
- **Enhancements:**
  1. **Extend `tools/idor_research.py`** — add **BFLA matrices**: privileged function inventory (from OpenAPI/surface model) × role sets (operator-declared), producing "call function X as role Y" validation plans. (OWASP API1/API2; Invicti BOLA-vs-BFLA 2026.)
  2. **`tools/graphql_batch_analyzer.py`** (NEW) — introspection-derived operation inventory → batching/alias abuse plans (N× batching to bypass rate limits), field-duplication DoS, circular-fragment depth, SSRF via URL-typed fields (PortSwigger GraphQL; aw-junaid methodology).
  3. **BOPLA matrix** — over-POST candidate fields from OpenAPI request schemas (mass-assignment to *object property* level, OWASP API3).
- **Integration:** `asset-intelligence`/`technology-fingerprint` artifacts feed the surface model; plans → `coverage-plan`.
- **Expected impact:** closes the BFLA/BOPLA gap — the top OWASP API class after BOLA.

### 4.3 Authentication & Authorization
- **Current:** `identity_cloud.py` posture/CVE triage; dual-session IDOR diffing; auth bypass hunting in mutator/hunt.
- **Enhancements:**
  1. **`tools/jwt_forgery.py`** (NEW) — static/offline analyzer: JWT decode → `alg` header inventory; plans for **alg=none, RS256→HS256 confusion, jwk header injection, kid path traversal, key confusion** (PortSwigger; Doyensec 2025). Emits forged-token *plans* (never executes by itself) + validation steps.
  2. **`tools/oauth_flow_analyzer.py`** (NEW) — parse OAuth/OIDC endpoints from JS/schema/recon → flow state machine: redirect_uri validation, state/Nonce usage, PKCE downgrade, token-in-URL, cross-app COAT patterns (USENIX Sec 2025). Produces two-account validation plans.
  3. **`tools/ato_chain_planner.py`** (NEW, P2) — chains email-change, password-reset, MFA-recovery, session endpoints into ATO plans (reuses lead ledger + chain_orchestrator).
- **Integration:** findings feed `triage` + `chain_orchestrator`; plans land in `coverage-plan`.
- **Expected impact:** first-class coverage of the identity flaw classes that dominate 2025–26 bounty payouts.

### 4.4 Cloud Security
- **Current:** `identity_cloud.py` (policy posture), `asset_intel.py` (provider plans), CI-CD vector catalog.
- **Enhancements:**
  1. **`tools/iam_privesc_graph.py`** (NEW) — encode the 21 Rhino AWS privesc methods + Azure/GCP equivalents as a directed capability graph; ingest an IAM policy dump (operator-supplied) → compute reachable privilege escalations (pmapper-style, offline). Output `state/capability/iam-privesc-<target>.json`.
  2. **`tools/container_escape_planner.py`** (NEW) — from a supplied container/image config or manifest: escape-vector planning (privileged mode, docker socket, capabilities, hostPID/hostNetwork, K8s init-container policy evasion; ECS-cape class — Black Hat USA 2025). Plans only; execution is operator/lab.
  3. **Enhance `tools/identity_cloud.py`** — serverless (Lambda) privilege escalation + cold-start patterns.
- **Integration:** capability registry + `state/capability/`; findings → chain_orchestrator (container-escape → IAM pivot chains).
- **Expected impact:** turns cloud posture docs into executable IAM privesc analysis.

### 4.5 Smart Contracts & DeFi
- **Current:** `contract_discovery.py` invariant/sequence executor, `formal_verify.py` (CVL + Medusa/Echidna harnesses), economic/crypto-math agents, Al-Mizaan MCP.
- **Enhancements:**
  1. **`tools/llm_contract_triage.py`** (NEW) — LLM-assisted candidate triage over static findings: given a candidate + code slice, produce constrained adversarial verification (OpenAnt-style) to rank by exploitability, cutting the high-FP problem (ACM 3702973). Deterministic inputs, JSON verdicts, human review preserved.
  2. **`tools/price_manipulation_analyzer.py`** (NEW) — lifecycle-oriented oracle/price-manipulation analysis (arXiv 2608.15518): spot AMM/LP/oracle dependencies in the invariant model; plan manipulation scenarios (flash-loan price moves, TWAP windows, mint/burn ratios).
  3. **Enhance `formal_verify.py`** — add upgradeability-pattern checks (proxy storage collisions, initializer re-entry) and OWASP SC Top-10 mapping.
- **Integration:** `maps/invariants.md` (contract targets) + `contract_discovery` executor; findings → triage.
- **Expected impact:** LLM+formal hybrid = the FP-killing pipeline the research prescribes.

### 4.6 LLM / Agentic AI Security
- **Current:** `llm_attack_surface.py` (GenAI/ASI taxonomy), `ai_defense.py` (prompt injection, tool auth, MCP OAuth), paper_intel control-plane audit.
- **Enhancements:**
  1. **`tools/agentic_tool_auth.py`** (NEW) — from an agent code/config inventory: map tool-call sites → which arguments are attacker-influenced (ASI02 tool misuse, ASI03 identity/privilege abuse); produce "tool X with attacker-controlled arg Y" plans. Extends ai_defense.
  2. **`tools/rag_memory_poisoning.py`** (NEW) — given RAG corpus/memory-store descriptions: rank poisoning vectors (indirect prompt injection via ingested docs, memory write-back abuse) with concrete payload-injection scenarios (OWASP ASI04; indirect-injection corpus).
  3. **Enhance `tools/ai_defense.py`** — MCP tool-authorization boundary checker (which tools are exposed to which agent identity; token scopes).
- **Integration:** `llm-ai` mode artifact in `technology-fingerprint`; plans → `coverage-plan`; control-plane audits → `maps`.
- **Expected impact:** moves from taxonomy mapping to actionable agentic-attack planning.

### 4.7 Mobile Security
- **Current:** mobile-vectors doc; PendingIntent/WebView markers in zero-day track.
- **Enhancements:**
  1. **`tools/deep_link_analyzer.py`** (NEW) — parse AndroidManifest intent-filters / iOS deep links → exported activities/URL schemes → link-hijacking and sensitive-navigation plans (MASTG-TEST-0028; OWASP Mobile Top 10 2025).
  2. **`tools/mobile_policy_checker.py`** (NEW) — manifest/plist static policy checks: backup allowed, network security config cleartext, exported components, pinning config, minSdk — deterministic.
  3. **Enhance `zero_day_tracks.py` (MobileBinaryTrack)** — certificate-pinning-bypass planning and hybrid WebView-bridge pivots.
- **Integration:** `asset-intelligence`/`technology-fingerprint` (binary artifacts) → plans → coverage-plan.
- **Expected impact:** closes the mobile static-analysis gap cheaply and deterministically.

### 4.8 Reconnaissance & OSINT
- **Current:** multi-source enumeration (`asset_intel.py`), CT via `js_ct_intel.py`, `tech_fingerprint.py`, `wordlist_gen.py`, resolvers.
- **Enhancements:**
  1. **`tools/historical_asset_delta.py`** (NEW) — operator-supplied historical DNS/CRT exports (SecurityTrails-style dumps, passive DNS JSONL) → asset delta tracker: added/removed/reattached infra, forgotten subdomains; writes `recon/<t>/asset-intel/history.jsonl` and diffs into `asset-intelligence`.
  2. **Enhance `tools/wordlist_gen.py`** — LLM-assisted naming extrapolation: given org/brand/product terms, propose candidate subdomains/servers (research-backed "naming convention extrapolation") as *additional* seeds (deterministic wordforms remain the base).
  3. **Enhance `tools/js_ct_intel.py`** — CRT delta tracking across runs (first_seen/last_seen already captured → derive churn).
- **Integration:** `passive-recon` + `asset-intelligence` artifacts.
- **Expected impact:** finds the forgotten infrastructure that snapshot scanners miss.

### 4.9 Automation, Orchestration & Adaptive Learning
- **Current:** campaign engine (discover→prioritize→recon gate→threads→chain), research_thread lifecycle, adaptive_learning quarantine, chain_orchestrator multi-hop, post_finding_trigger.
- **Enhancements (research-backed — OpenAnt, Aardvark, multi-agent surveys):**
  1. **LLM plan synthesis for research units** — `campaign_orchestrator.py` gains an optional `--llm-advisor` mode: for each unit, an LLM proposes the top-k probes/approaches (seeded from deterministic suggested_approaches); the deterministic core still decides and records. Keeps determinism; adds semantic depth.
  2. **`tools/verification_lab.py`** (NEW) — sandboxed dynamic verification planner (OpenAnt-style): for high-value candidates, plan a disposable lab (container/dir), auto-generate the exploit-environment steps, verify, discard. Plans only; the lab is operator-run.
  3. **`tools/failure_learning.py`** (NEW) — extends `adaptive_learning.py`: when a thread blocks (403/WAF/rate-limit), record the blocker + what worked, and feed the `bypass` checkpoint with fresh, provenance-tracked bypass candidates (auto-quarantined, operator-reviewed before reuse — preserves the existing review gate).
  4. **`tools/chain_graph_ai.py`** (NEW) — LLM-assisted chain synthesis on top of `deep_chain.py`'s deterministic compatibility graph: propose missing links between parked leads + findings (the "chain pool" idea, now LLM-surfaced) → validated through the deterministic edge-checker.
  5. **Dynamic research checkpoints** — `research_loop.py` gains optional event-driven checkpoints beyond the mandatory 7 (`post-chain`, `post-lab-verification`, `blocker-exhausted`) that append to `sequence.json` without weakening `latest_ready` semantics (mandatory 7 stay required).
  6. **Self-healing workflow** — `stage_controller.py`/orchestrator: on `blocked_trigger_error`/`blocked_missing_evidence`, auto-generate a repair unit (already partially present in post_finding_trigger) — formalize as `repair_unit` with deterministic retry policy.
- **Integration:** every enhancement writes through existing artifacts (research sequence, leads ledger, coverage plans, campaign state).
- **Expected impact:** the "world-class autonomous platform" delta — closed-loop discover→verify→learn, with LLM depth on top of deterministic trust.

---

## 5. Phase 4 — Execution Roadmap (8 weeks)

```
W1 ─┬─ P0: smuggling_detector skeleton (CL.TE/TE.CL/TE.TE) + probe oracle
    ├─ P0: parser_differential v1 (WAFFLED taxonomy subset) + mutator hook
    └─ P0: jwt_forgery (alg=none, RS256→HS256) + unit tests
W2 ─┬─ P0: BFLA matrices in idor_research + OpenAPI role inventory
    ├─ P0: graphql_batch_analyzer (batching/alias/field-dup)
    └─ P0: oauth_flow_analyzer v1 (redirect_uri, state, PKCE)
W3 ─┬─ P1: IAM privesc graph (21 Rhino methods, policy parser)
    ├─ P1: deep_link_analyzer + mobile_policy_checker
    └─ P1: historical_asset_delta (passive DNS JSONL ingestion)
W4 ─┬─ P1: llm_contract_triage (adversarial verification prompt pipeline)
    ├─ P1: agentic_tool_auth + rag_memory_poisoning
    └─ P1: verification_lab planner
W5 ─┬─ P1: LLM-guided seed/mutation advisor (discovery_scheduler hook)
    ├─ P2: price_manipulation_analyzer (AMM/oracle dependency scan)
    └─ P2: dynamic research checkpoints (post-chain, post-lab)
W6 ─┬─ P2: chain_graph_ai (LLM missing-link proposals on deep_chain graph)
    ├─ P2: failure_learning (blocker → bypass-checkpoint feedback)
    └─ P2: ATO chain planner
W7 ─┬─ Integration: wire all new artifacts into 12-stage prerequisites
    ├─ Integration: research-loop checkpoint wiring + campaign units
    └─ Docs: methodology/vector/agent updates + harness contracts
W8 ─┬─ Testing: full suite + new regression modules (target 600+ tests)
    ├─ ★ Self-evaluation harness: AutoPenBench-style milestone scoring on a fixed task set
    ├─ Live validation: synthetic + safe-lab campaign end-to-end
    └─ Release: v1.1.0 bundles rebuilt, tagged
```

**Milestones & deliverables**
- **M1 (end W2):** smuggling + parser-differential + JWT forgery ship with tests → "2025–26 web frontier" coverage; ★ business-logic state-machine v1 + trigger-condition planner scaffolded (P0).
- **M2 (end W4):** BFLA/GraphQL/OAuth/cloud/mobile analyzers + LLM triage pipeline → broad class coverage.
- **M3 (end W6):** LLM advisor modes (plan synthesis, chain synthesis, failure learning) → autonomous depth.
- **M4 (end W8):** full integration, 600+ tests green, ★ self-evaluation harness scoring, v1.1.0 release.

**Risk assessment & mitigations**
| Risk | Likelihood | Mitigation |
|---|---|---|
| LLM features inflate false positives | High | OpenAnt-style adversarial verification; deterministic cores decide; LLM = advisor only |
| Context/cost blow-up on large repos | Medium | Reachability-filtered decomposition (97% surface cut); per-unit bounded prompts |
| Determinism regression in test suite | Medium | LLM outputs quarantined like adaptive_learning; deterministic paths unit-tested |
| Smuggling probes trigger noisy live behavior | Medium | Plans + differential oracles; live replay stays operator-triggered (uncensored but explicit) |
| Scope creep across 9 domains | Medium | P0-first roadmap; each tool ships with tests + artifact wiring before next begins |
| Research-loop semantics weakened by dynamic checkpoints | Low | Mandatory 7 remain required; dynamic checkpoints append-only, `latest_ready` untouched |

---

## 6. Appendix — Sources Consulted

**Academic / conferences**
1. OpenAnt — LLM-Powered Vulnerability Discovery (arXiv 2606.19149, Jun 2026) — decomposition, adversarial verification, dynamic testing.
2. AutoPen — Towards Autonomous Penetration Testing Using LLM-Powered Agents (ACM 3772886.3772899, Dec 2025).
3. WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs (arXiv 2503.10846) — 1,207 bypasses.
4. Hybrid Fuzzing with LLM-Guided Input Mutation (arXiv 2511.03995) / LLAMAFUZZ — LLM mutation + greybox beats AFL++.
5. Directed Greybox Fuzzing via Large Language Model (arXiv 2505.03425).
6. Semantic-Aware Fuzzing: LLM-guided mutation framework (arXiv 2509.19533).
7. Exploiting and Securing OAuth 2.0 in Integration Platforms (USENIX Security 2025, Luo et al.) — COAT + request forgery.
8. When ChatGPT Meets Smart Contract Vulnerability Detection (ACM 3702973) — high recall / low precision.
9. A Lifecycle-Oriented Detection and Defense Framework for Price Manipulation in DeFi (arXiv 2608.15518).
10. The Orchestration of Multi-Agent Systems (arXiv 2601.13671); LLM-Based Multi-Agent Orchestration Survey (MDPI Future Internet 18(6):326, 2026).

**Industry / frameworks**
11. OWASP API Security Top 10 (BOLA/BFLA/BOPLA) + 2026 agentic lens (Aptori, Wiz, Invicti, Radware).
12. OWASP Top 10 for LLM Applications 2025/2026 + OWASP Top 10 for Agentic Applications 2026 (ASI01–10).
13. OWASP Smart Contract Top 10; OWASP Mobile Top 10 2025; OWASP MASTG (deep-link testing, MASVS).
14. PortSwigger Web Security Academy — request smuggling, JWT algorithm confusion, GraphQL attacks; Kettle "HTTP/1.1 Must Die / Desync Endgame" coverage (jsmon.sh, vulnsy cheat sheet).
15. HackerOne 2025 HPSR researcher signals; HackerOne top-ten vulnerabilities; smart-contract bounty stats (H1 paid $81M Jun-2024→Jun-2025, +13% YoY).

**Tooling / vendor research**
16. Rhino Security Labs — AWS IAM Privilege Escalation (21 methods); ECS-cape (Black Hat USA 2025).
17. OpenAI Aardvark (Oct 2025); AISLE → 12 OpenSSL CVEs (Ken Huang, Apr 2026); Kodem agentic red teams (2025).
18. hackingthe.cloud (IAM privesc); Sweet Security ECScape analysis; ResearchGate serverless cold-start / K8s init-container evasion (2025).
19. Doyensec — Common OAuth Vulnerabilities (Jan 2025); guptadeepak SSO flaw catalog (2025); DataDog JWT-confusion rule.
20. MDSec WAF evasions (2024); decryptiondigest WAF bypass 2026; hetmehta advanced WAF bypass (2025).

**2026-focus additions ★**
21. ★ A Survey of LLM-Driven Penetration Testing: Taxonomy, Co-Evolution, and Open Challenges (arXiv 2607.02605, Jul 2026) — six-category taxonomy of 81 Agent4Pentest papers (2023–Jun 2026); four-phase architectural evolution (text-only → tool-augmented → multi-agent → RLVR); CTF-as-RL-substrate.
22. ★ AI Pentesting Benchmark Results 2026: Scoreboard (Stingrai, Jul 2026) — XBOW (HackerOne US #1, ~1,060 reports/90d, human-reviewed), ARTEMIS (2nd/11 vs. pros, live 8,000-host net, 82% valid, higher FP than humans), CVE-Bench (13% zero-day / 25% one-day), HackerOne 9th HPSR (210% YoY valid AI reports, 540% prompt-injection reports, 58% business-logic weakness).
23. ★ CyberChainBench (arXiv 2606.26216, Jun 2026); Where Do Smart Contract Security Analyzers Fall Short? (arXiv 2603.00890, MSR '26 — oracle-manipulation detection <40%); Agentic Attack Synthesis & Simulation for Smart Contracts (arXiv 2607.15673, Jul 2026); LLM-Driven Formal Verification via RAG Property Generation (arXiv 2608.13191, Aug 2026); OWASP Smart Contract Top 10: 2026.
24. ★ OWASP Top 10 for Agentic Applications 2026 (ASI01–10) — Human Security, Cycode, Deepteam breakdowns; OWASP GenAI Security Project (LLM Top 10 2026).
25. ★ James Kettle — "Can AI Do Novel Security Research? Meet the HTTP Terminator" (Black Hat USA 2026 / DEF CON 34, Aug 2026, PortSwigger Research).
26. ★ CTI Labs — 403-bypass: 23 new techniques, 61% of tested apps (2026); PortSwigger community — Top 10 Web Hacking Techniques, 19th ed. (Feb 2026, blind SSTI polyglots).
27. ★ TRIGFUZZ: Triggering Conditions Guided Directed Fuzzing (IEEE S&P 2026).
28. ★ CVE-2026-48611 OAuth authentication bypass (SentinelOne VDB, Jun 2026); OAuth PKCE misconfiguration → ATO writeup (InfosecWriteups, Jun 2026).
29. ★ CybelAngel — API Security Risks 2026 (AI-powered API attacks #1, shadow APIs, supply chain); xhack OWASP API Top 10 2026 guide (BOLA ~40%).
30. ★ Serverless Cold Start Privilege Escalation & Kubernetes Init Container Policy Evasion (ResearchGate, Dec 2025); Rhino Security Labs — AWS IAM Privilege Escalation: Methods and Mitigations (2026 refresh, 21 methods).
31. ★ Shell-or-Nothing: Real-World Benchmarks and Memory-Activated Agents for Automated Penetration Testing (May 2026); LangGraph stateful multi-agent orchestration frameworks (2026).
32. ★ 2026 OSINT guidance — ShadowDragon (What Is OSINT, 2026), chs.us OSINT guide (2026); Automated OSINT Techniques for Digital Asset Discovery and Cyber Risk Assessment (MDPI Computers 14(10):430, Oct 2025).

*Note: several 2026-dated sources (e.g., arXiv 2606.19149, 2607.02605, 2608.15518) are treated as current within this project's timeline (Aug 2026).*

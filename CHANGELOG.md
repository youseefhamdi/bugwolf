# Changelog

## v1.0.0 — First release (2026-08-19)

BugWolf's first public release: an all-round bug bounty hunting engine covering smart contracts (EVM/Solidity, Move/Aptos, Solana, TRON), web/API security, CI/CD pipeline attacks, LLM/AI & agentic security, and professional report generation for HackerOne, Bugcrowd, Intigriti, and Immunefi.

### Hunting methodology
- **5-Pillar map-driven hunt** — Asset, Trust, Identity/Authorization, State, and Capability maps (plus `invariants.md` for contract audits). No map → no hunt; every finding traces to a map path.
- **Two-question rule (Trigger × Impact)** — a finding must prove both that the path fires and the victim harm; OPEN LEAD is a persistent, mutation-tracked research object (`tools/leads.py`), never silently dropped.
- **Wild mode** — default hunting doctrine: probe everything, chain everything, gates only apply at report time.
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

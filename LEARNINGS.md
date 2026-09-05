<!-- bugwolf/docs — second-brain
     SCHEMA: bugwolf-secondbrain-learnings-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Learnings

Lessons learned across all phases. This is the institutional memory
that keeps BugWolf from regressing on closed audit findings.

## 1. Audit findings (all remediated)

### 5 CRITICAL (Phase 0)

- **C-1**: `subprocess.run(..., shell=True)` allowed shell injection.
  Closed by `ci_anti_patterns.sh` A-1/A-4 gate.
- **C-2**: `requests.get(..., verify=False)` disabled TLS verification.
  Closed by `ci_anti_patterns.sh` AP-XP-5 gate.
- **C-3**: `from scrapling.parser import` pulled a malicious package.
  Closed by `ci_anti_patterns.sh` AP-XP-6 gate.
- **C-4**: Scope gate accepted decimal-IP as 127.0.0.1. Closed by
  decimal/octal/hex normalization in `bugwolf/governance/scope.py`.
- **C-5**: Hash chain was not checked on journal restart. Closed by
  `prev_hash` check in `bugwolf/governance/evidence.py`.

### 18 HIGH (Phase 0 / 1.4)

- **H-1**: `alias bypass=...` and `alias yolo=...` in tools/.
  Closed by `ci_anti_patterns.sh` A-8 gate.
- **H-2**: `## Description:` frontmatter in agents/bugwolf/ (prompt
  injection smuggling). Closed by `ci_anti_patterns.sh` A-13 gate.
- **H-3**: `POUET` / `UNCHECKOUT` kill-switch markers. Closed by
  `ci_anti_patterns.sh` AP-XP-8 gate.
- **H-4**: Missing audit log on state transition. Closed by
  `bugwolf/governance/audit_log.py`.
- **H-5**: LLM judge skippable on backend error. Closed by
  deterministic fallback in `bugwolf/governance/question_gate.py`.
- **H-6**: CVSS vector truncation. Closed by verbatim vector
  serialization in `bugwolf/governance/cvss.py`.
- **H-7**: OPSEC proxy file mode too open. Closed by `chmod 0o600`
  in `bugwolf/governance/opsec.py`.
- **H-8**: Capability digest non-determinism. Closed by
  canonical-JSON serialization in `bugwolf/governance/capability_digest.py`.
- **H-9**: Contract invariant bypass. Closed by invariant checks
  in `bugwolf/governance/contracts.py`.
- **H-10**: Lab profile env leak. Closed by per-process opt-in in
  `bugwolf/governance/safety.py`.
- Plus 8 more HIGH findings (H-11..H-18) closed in Phase 1.4.

### 36 MEDIUM (Phase 4.D)

Covered in `PHASE_4_D_MEDIUM_REMEDIATION.md`. Every one is closed
and verified by a regression test.

## 2. 26 anti-patterns

- `subprocess.run(..., shell=True)` — shell injection.
- `requests.get(..., verify=False)` — TLS bypass.
- `from scrapling.parser import ...` — known malicious package.
- `POUET` / `UNCHECKOUT` markers — kill-switch bypass.
- `## Description:` frontmatter in agents — prompt injection smuggling.
- `alias bypass=...` / `alias yolo=...` — unsafe confirmation aliases.
- `LAB=1` env inherited from parent shell — destructive op accidental.
- Hardcoded UA string — fingerprintable.
- Hardcoded credentials in source — credential leak.
- Proxy file with mode `0o644` — credential leak.
- `verify=False` in `requests`/`urllib3` — TLS bypass.
- `import yaml.load` (without `Loader=`) — code execution.
- `pickle.loads` on untrusted input — code execution.
- `eval()` / `exec()` on user-supplied input — code execution.
- `os.system()` / `os.popen()` — shell injection.
- `subprocess.Popen(..., shell=True)` — shell injection.
- `pathlib.Path` with `..` traversal — path traversal.
- `input()` used as a shell arg — shell injection.
- `open(path)` without sanitization — path traversal.
- `chmod 0o777` on sensitive files — credential leak.
- `print(secrets)` in production — credential leak.
- `assert` for input validation — bypassable with `python -O`.
- `try/except: pass` swallowing security errors — silent failure.
- `random.random()` for security tokens — predictable.
- `md5` / `sha1` for security — broken hash.
- `time.time()` for token generation — predictable.

## 3. 78 skills from Claude-Red

78 specialized skills inherited from the Claude-Red skill library.
Indexed in `references/claude-red-skills.md`. Highlights:

- `web_xss` — reflected, stored, DOM, mutation XSS.
- `web_sqli` — union, boolean, time, error-based.
- `web_ssrf` — DNS rebinding, IPv6, filter bypass.
- `web_idor` — object-level, function-level.
- `auth_oauth` — code interception, redirect URI, scope escalation.
- `auth_jwt` — alg confusion, key confusion, none algorithm.
- `web3_reentrancy` — single-function, cross-function, read-only.
- `llm_prompt_injection` — direct, indirect, jailbreak.
- `cloud_iam` — privilege escalation, trust policy abuse.
- `cicd_actions` — expression injection, artifact poisoning.
- `mobile_frida` — dynamic instrumentation, bypass.
- Plus 67 more — see `references/claude-red-skills.md`.

## 4. 14 OSINT refs from Claude-OSINT

14 OSINT references inherited from the Claude-OSINT skill library.
Indexed in `references/claude-osint-refs.md`. Highlights:

- `osint_subdomain_enum` — amass, subfinder, assetfinder.
- `osint_email_harvest` — theHarvester, h8mail.
- `osint_tech_fingerprint` — wappalyzer, whatweb.
- `osint_credential_leak` — dehashed.com, leak-lookup.
- `osint_dns_history` — SecurityTrails, DNSHistory.
- Plus 9 more — see `references/claude-osint-refs.md`.

## 5. 12 H100 chains

12 proven A→B→C chains from the H100 corpus. YAML sources in
`bugwolf/methodology/chains/`:

1. `01_oauth_to_ato.yaml` — OAuth code interception → ATO.
2. `02_ssrf_to_rce.yaml` — SSRF → IMDS → RCE.
3. `03_graphql_to_mass_leak.yaml` — introspection → batch → mass leak.
4. `04_cache_poison_xss.yaml` — cache key confusion → XSS.
5. `05_http_smuggle_hijack.yaml` — TE/CL desync → connection hijack.
6. `06_credspray_to_admin.yaml` — credential spray → admin takeover.
7. `07_subdomain_takeover.yaml` — dangling DNS → subdomain takeover.
8. `08_idor_pii_leak.yaml` — IDOR → mass PII leak.
9. `09_race_double_spend.yaml` — race condition → double spend.
10. `10_jwt_to_admin.yaml` — JWT confusion → admin.
11. `11_supply_chain_rce.yaml` — dependency confusion → RCE.
12. `12_cicd_secrets_leak.yaml` — CI/CD token leak → repo access.

## Where to read next

- `decisions.md` — architectural decision log.
- `docs/GOVERNANCE.md` — current governance modules.
- `docs/SECURITY.md` — threat model + findings.
- `PHASE_4_D_MEDIUM_REMEDIATION.md` — 36 MEDIUM findings.
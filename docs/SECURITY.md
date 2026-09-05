<!-- bugwolf/docs — security
     SCHEMA: bugwolf-docs-security-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Security Model

This is the deep-dive security model. The top-level `SECURITY.md`
at the repo root gives the policy summary; this file documents
the threat model, the audit findings, the defense-in-depth
guarantees, and the OPSEC posture.

## 1. Threat model

**Adversary.** An attacker who controls either (a) the network
between BugWolf and a target, (b) a malicious bug bounty target
designed to exploit the scanner, or (c) a piece of third-party
content that the scanner is asked to ingest (a poisoned JS bundle,
a malicious YAML, etc.).

**Adversary capabilities.**
- TLS interception (when BugWolf is run without cert pinning).
- Arbitrary response bodies (HTML, JSON, JS) returned from the
  target.
- Arbitrary file system access on the lab profile (controlled
  by the operator via `BUGWOLF_LAB_PROFILE=1`).
- Network reachability to a private IP range (via SSRF).

**Attack surface.**
- The HTTP fetcher (`bugwolf/governance/opsec.py`).
- The YAML loader (`bugwolf/methodology/chain_loader.py`).
- The LLM backend prompt (`bugwolf/runtime/`).
- The Rust FFI (`bugwolf-rs/src/lib.rs`).
- The Redis IPC (`bugwolf/distributed/redis_client.py`).

## 2. Audit findings (all remediated)

### 5 CRITICAL (Phase 0)

| ID  | Finding                                                    | Remediation                       |
|-----|------------------------------------------------------------|-----------------------------------|
| C-1 | `subprocess.run(..., shell=True)` allowed injection        | Refused by `ci_anti_patterns.sh`  |
| C-2 | `requests.get(..., verify=False)` disabled TLS             | Refused by `ci_anti_patterns.sh`  |
| C-3 | `from scrapling.parser import` pulled a malicious package  | Refused by `ci_anti_patterns.sh`  |
| C-4 | Scope gate accepted decimal-IP as 127.0.0.1                | Normalization in `scope.py`       |
| C-5 | Hash chain ignored on journal restart                      | `prev_hash` check in `evidence.py`|

### 18 HIGH (Phase 0/1.4)

The HIGH findings cover: bypass / yolo aliases (A-8),
`## Description:` frontmatter in agents (A-13), `POUET` /
`UNCHECKOUT` kill-switch markers (AP-XP-8), missing audit log
on state transition (H-1), LLM judge skippable on backend
error (H-2), CVSS vector truncation (H-3), OPSEC proxy file
mode (H-4), capability digest non-determinism (H-5),
contract invariant bypass (H-6), lab profile env leak (H-7),
state-machine skip-state (H-8), chain YAML SSRF (H-9),
adversarial app binding (H-10), and seven additional issues
closed in Phase 1.4.

### 36 MEDIUM (Phase 4.D)

The MEDIUM findings cover: missing input validation in the
reporting layer, race conditions in the unified state machine,
missing edge-case handling in the harness guard, log
redaction gaps, and 31 additional issues closed in Phase 4.D.

## 3. Defense-in-depth

The governance layer is layered so that any single failure
is caught by another layer.

1. **Scope gate.** Deny-by-default; refuses decimal/octal/hex
   IP bypass; refuses IDN bypass.
2. **Question gate.** LLM-as-judge with seven questions and
   `recorded_evidence_block` per question; deterministic
   fallback when the LLM backend errors.
3. **Capability digest.** SHA-256 of the registry at every CLI
   start; CI drift-check refuses to merge a digest change
   without updating `scripts/capability_digest.txt`.
4. **Hash-chained journal.** SHA-256 of
   `prev_hash || canonical_json(entry)`; tampering breaks
   the chain and the audit refuses the report.
5. **Lab profile opt-in.** Destructive actions require
   `BUGWOLF_LAB_PROFILE=1` or
   `BUGWOLF_EXECUTION_PROFILE=lab-uncensored`.

## 4. STUB-SAFE contract

Any external service that is missing (HTTP endpoint down,
Redis unreachable, LLM backend offline) returns the literal
string `"unavailable"`. It never raises. This contract is
enforced by:

- `bugwolf/governance/opsec.py` — `FetchResult(status="unavailable")`.
- `bugwolf/distributed/redis_client.py` — returns `"unavailable"`
  on connection failure.
- `bugwolf/runtime/` — LLM backend returns
  `LLMResult(text="unavailable", confidence=0.0)`.

The `STUB-SAFE` contract is tested in
`tests/test_antibot.py` and `tests/test_reliability.py`.

## 5. OPSEC posture

- **UA pool rotation.** `bugwolf/governance/opsec.py` rotates
  the User-Agent header on every request from a configurable
  pool.
- **Proxy rotation.** Live proxy list from
  `fresh-proxy-list`; Tor fallback with cookie auth.
- **No hardcoded credentials.** `bugwolf/governance/opsec.py`
  refuses to load a proxy file with mode other than `0o600`.
- **Audit log.** Every state transition is recorded as an
  evidence block in the unified state journal.

## 6. Reporting vulnerabilities

Contact: `security@bugwolf.xyz` (or via the GitHub Security
tab on the repo).

SLA: 24 hours for an acknowledgement; 7 days for a triage
decision; coordinated disclosure timeline agreed case-by-case.

We follow the HackerOne "coordinated disclosure" model:
- We confirm receipt within 24 hours.
- We confirm a triage decision within 7 days.
- We credit the reporter in the release notes (unless the
  reporter prefers anonymity).

## Where to read next

- Top-level summary: `../SECURITY.md`
- Architecture overview: `docs/ARCHITECTURE.md`
- Governance contracts: `docs/GOVERNANCE.md`
- Operator runbook: `docs/OPERATIONS.md`
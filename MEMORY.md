<!-- bugwolf/docs — second-brain
     SCHEMA: bugwolf-secondbrain-memory-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Memory

This file is auto-loaded by Claude Code as the long-term core info
for the BugWolf project. Keep it short (≤80 lines) and durable.

## What BugWolf is

BugWolf is a security-research AI company. Modeled on the Japanese
brain-market convention of 11 departments and 31 employees, BugWolf
operates 11+ lanes, 19 agents, and 21+ directions at Tier 1 quality.

## Target user

Senior security engineers, red-teamers, and bug bounty hunters who
need a governed, auditable, fail-closed scanner for authorized
research.

## Current phase

**Phase 5 — Integration & Polish.** Phases 0–4 are complete.
- 5.1 — unified CLI
- 5.2 — reporting (JSON / MD / HTML / SARIF / H1 / BC / Intigriti / Immunefi)
- 5.3 — unified state (hash-chained journal, state machine)
- 5.4 — documentation (this file + `docs/ARCHITECTURE.md`,
  `docs/GOVERNANCE.md`, `docs/METHODOLOGY.md`, `docs/BENCHMARKS.md`,
  `docs/OPERATIONS.md`, `docs/SECURITY.md`, `docs/COMPANY.md`)
- 5.5 — second-brain convention adoption (this file + `LEARNINGS.md`
  + `decisions.md` + `tools/second_brain_validator.py`)

## Key decisions (fail-closed, no third-party deps, append-only)

1. **Fail-closed by default.** Any missing dependency, empty scope,
   or malformed contract produces an error, never a default-pass.
2. **No third-party dependencies.** Python stdlib only. No `requests`,
   no `click`, no `jinja2`, no `torch`, no `selenium`, no `playwright`.
3. **Hash-chained append-only journal.** SHA-256 of
   `prev_hash || canonical_json(entry)`. No `delete`, `update`, or
   `clear` on the state journal.
4. **Capability registry digest.** SHA-256 of the registry at every
   CLI start; CI drift-check refuses to merge a digest change
   without updating `scripts/capability_digest.txt`.
5. **STUB-SAFE contract.** Any external service that is missing
   returns `"unavailable"`, never raises.
6. **Lab profile opt-in.** Destructive actions require
   `BUGWOLF_LAB_PROFILE=1` or
   `BUGWOLF_EXECUTION_PROFILE=lab-uncensored`.

## Cross-references

- `SKILL.md` — top-level skill manifest (auto-loaded).
- `README.md` — project overview + Company Model.
- `LEARNINGS.md` — audit findings, skills, OSINT refs, H100 chains.
- `decisions.md` — architectural decision log.
- `docs/COMPANY.md` — 11+ lanes × 19 agents × 21+ directions.
- `docs/ARCHITECTURE.md` — seven-layer architecture.
- `docs/GOVERNANCE.md` — governance modules.
- `docs/SECURITY.md` — threat model.

## How this file is used

Claude Code auto-loads `MEMORY.md` from the project root on every
session start. Keep it short, declarative, and durable. Operational
details belong in `docs/OPERATIONS.md`; architectural decisions
belong in `decisions.md`; lessons learned belong in `LEARNINGS.md`.
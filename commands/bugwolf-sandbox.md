---
description: Inspect or control the BugWolf subprocess sandbox and kill switch
argument-hint: "[status|kill|arm|grant|revoke|verify] [--note ...] [binaries...]"
---

# BugWolf sandbox / kill switch

1. Determine the subcommand from the operator's arguments (default: `status`).
2. Run exactly one command via Bash and show the raw output:

   - `status`: `python3 -m tools.runtime.sandbox status`
   - `kill`: `python3 -m tools.runtime.sandbox kill --note "<reason>"`
   - `arm`: `python3 -m tools.runtime.sandbox arm`
   - `grant`: `python3 -m tools.runtime.sandbox grant <binary> [binary...]`
   - `revoke`: `python3 -m tools.runtime.sandbox revoke <binary> [binary...]`
   - `verify`: `python3 -m tools.runtime.sandbox verify`

3. Safety rules:
   - NEVER run `arm` unless the operator explicitly asked to re-arm.
   - `kill` blocks ALL subprocess execution in the workspace immediately
     (fail-closed, including a corrupt marker file) and fails the release
     capability gate closed — say so when engaging it.
   - `grant` extends the spawn allowlist durably; confirm the binary name
     with the operator before granting.

4. Report the resulting state (kill switch armed/ENGAGED, allowlist size,
   grants) and the audit-log location (`state/sandbox/audit.jsonl`).

---
name: bugwolf:ato-chain
description: ATO-Chain Specialist -- 2026 ATO escalation: OAuth account fusion/linking abuse, PKCE downgrades on open client registration, 0-click reset chains, email-verification ATO windows, token-entropy feasibility proofs.
model: opus
tools: Read, Grep, Glob, WebFetch, WebSearch, Bash, Task
x-bugwolf-tier: frontier (preference via tools/core/model_router.py)
scope: operator-declared (deny-by-default, tools/runtime/scope.py)
sandbox: required (tools/runtime/sandbox.py)
playbook-digest: e4f5ee3026a897cb
---

You are ATO-Chain Specialist, a specialized BugWolf subagent dispatched as
`bugwolf:ato-chain` inside a multi-agent security team.

Non-negotiable operating rules (apply to every dispatch):

1. **Scope** -- you operate ONLY inside the operator-declared scope
   (tools/runtime/scope.py, deny-by-default). A `scope-blocked:` sentinel is
   a hard stop, never a puzzle.
2. **Sandbox** -- every spawn goes through tools/runtime/sandbox.py. No
   direct subprocesses.
3. **Evidence** -- an "insight" without a lead ref is a contract violation
   (R1). Terminal states are PWNED / REFUTED / BUDGET-EXHAUSTED -- nothing
   else closes a lead.
4. **Honesty** -- never fabricate a result. If a capability is missing,
   return blocked evidence and move on.
5. **Handoff** -- return structured messages (`to_role`, `kind`, `body`)
   instead of prose handoffs; the team engine routes them.
Tool modules (BugWolf internals driven via Bash -- always through tools/runtime/sandbox.py): domains.auth.oauth_flow_analyzer, domains.auth.jwt_forgery, domains.auth.ato_chain_planner, runtime.mission_runner

# Account-Takeover Chains — 2026 Edition

Distilled from live research: 2026 HackerOne/infosecwriteups/Medium ATO
writeups (OAuth misconfig ATO, OAuth account fusion pre-takeover, email
confirmation → full ATO, 0-click password-reset ATO), the corpus's own
CH-01..15 catalog (this file extends it with 2026 patterns).

## New/escalated ATO patterns (2026)

### OAuth fusion & confusion
- **Account fusion pre-takeover** — OAuth identity merging that lets an
  attacker's IdP identity graft onto a victim account via
  unverified-email linking or client-controlled `redirect_uri` on
  dynamically-registered clients. Test every "Sign in with X" plus every
  "Connect account" flow; watch for `email_verified` never being checked
  *at link time* (only at login time).
- **PKCE downgrades on open client registration** — self-service OAuth
  client signup + `plain` PKCE + permissive redirect matching = code
  interception chain. Test S256→plain downgrade even when PKCE is
  "enforced".
- **Fusion via shared callback** — mix-up between login and connect flows
  on the same redirect URI; state valid across both.

### Password-reset escalation ladder
- 0-click reset ATO: reset link leakage via analytics/Referer/prefetch —
  prove with your own trace (proxy/CDN log canary), never a victim.
- Host-header poisoning on reset emails remains the top-server payout:
  `Host`, `X-Forwarded-Host`, `X-Forwarded-Port`, absolute-URI forms.
- Token entropy quantification is mandatory: `charset^length ÷ (rate
  limit × TTL)` = feasibility verdict with evidence.
- Rebinding: old token valid after password change; reset revoking
  *sessions* but not *refresh-token families* (rotation without reuse
  detection).

### Email-verification ATO (frequent "standard link" miss)
- Register with victim email → change to attacker email → verify → revert;
  pre-ATO windows across each step.
- Verification link not bound to account or session; parallel
  email-change races; reusable links after re-initiation.

## Chain composition rules

1. Every link individually validated (G0–G6) BEFORE composing.
2. End-to-end demo on owned accounts only; severity = demonstrated impact.
3. ATO payout order (empirical, 2026): reset poisoning → OAuth
   code theft (redirect + callback XSS) → fusion/linking → session
   fixation/rotation → cache deception → IDOR+mass-assignment → JWT
   jwk/jku → email-change races.
4. GDPR multiplier on EU programs: cross-user PII access raises severity —
   cite it in impact, never exploit it beyond one canary.


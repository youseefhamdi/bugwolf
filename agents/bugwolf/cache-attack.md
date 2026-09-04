---
name: bugwolf:cache-attack
description: Cache-Attack Agent -- 2026 WCD/WCP playbook: delimiter ladder (;, %3B, .;, ..;), unkeyed-input sweeps, gadget chaining, H2-era desync poisoning, CPDoS variants; second-account impact verification.
model: sonnet
tools: Read, Grep, Glob, WebFetch, WebSearch, Bash, Task
x-bugwolf-tier: local_slm (preference via tools/core/model_router.py)
scope: operator-declared (deny-by-default, tools/runtime/scope.py)
sandbox: required (tools/runtime/sandbox.py)
playbook-digest: c5b3fbce044f2f8f
---

You are Cache-Attack Agent, a specialized BugWolf subagent dispatched as
`bugwolf:cache-attack` inside a multi-agent security team.

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
Tool modules (BugWolf internals driven via Bash -- always through tools/runtime/sandbox.py): cache_traversal, header_trust, hunt, runtime.browser_driver

# Web Cache Attack Vectors — 2026 Edition

Distilled from live research: PortSwigger Web Security Academy (web cache
deception), Intigriti research blog (poisoning exploitation), zhero-web-sec
(cache-deception→CSRF chain writeup), HackTricks cache-deception entry,
advanced deception guides (2026).

## Web Cache Deception (WCD)

Trick the cache into storing a victim's dynamic/authenticated content under
an attacker-fetchable key.

### Path-based variants (extend beyond the classic `.css` suffix)

```
/api/me.css            /api/me/.css          /api/me;%0a.css       (semicolon)
/api/me/nonexistent.js /api/me%2f            /api/me;.js
/api/me?.css           /api/me#.css          /api/me?.css?cachebust
```

Rule: the cache keys on the *extension/path suffix*, the origin routes on
the *prefix*. Any decoder disagreement is a deception primitive.

### Delimiter variants (framework-specific)

`;` (Java/Oracle paths) · `%3B` · `:` (older Tomcat) · trailing `.` ·
`..;` (Tomcat path params) · unicode separators per CDN.

### Cache-key abstractions to probe

- Normalized-path vs original-path discrepancies
- Header-based keying: `X-Forwarded-Host`, `X-Original-URL`, fat GET
- Query-parameter inclusion/exclusion drift between layers
- `Vary:` misconfiguration (user-agent/accept-encoding variance)

## Web Cache Poisoning (WCP) — current playbook

1. **Unkeyed input discovery** — Param Miner-class sweeps: headers,
   cookies, body-on-GET. Confirm reflect-to-cache (not just reflect).
2. **Storage confirmation** — the poisoned response must be served to a
   *fresh context* (second account/incognito), not merely echoed back.
3. **Gadget chaining** — poisoned redirect → open redirect → XSS;
   poisoned JSONP → script-gadget XSS on same-origin hosts.
4. **Cache-Control interplay** — `no-cache` in the smuggled prefix forces
   origin refresh on existing objects (Squid behavior); cache purging
   limits via error differentials.
5. **HTTP/2-era poisoning** — H2.CL desync poisoning, header
   normalization differentials (`\r` in header names), method scheme
   abuse. Pair with smuggling playbook.

## Safety rails (unchanged doctrine)

- Poison/deceive ONLY your own canary requests with fresh cache keys.
- Never poison real-user traffic or shared caches.
- Verify impact with a second account before reporting (deception:
  attacker-fetchable PII = the finding; screenshot from fresh context).

## Chain map

- WCD → session/PII theft → ATO (zhero-web-sec: WCD + CSRF full chain)
- WCP → XSS → token theft → ATO
- Smuggling → WCP (request-prefix injection) → auth bypass
- WCD on GraphQL (`/graphql/me.css`) — cached authenticated responses on
  query endpoints frequently bypass cache-key auth assumptions


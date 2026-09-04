---
description: Bind or preview the BugWolf operator scope (deny-by-default gate + harness contract)
argument-hint: "<target> [--scope extra.host,other.host] [--exclude beta.target,community.target]"
---

# BugWolf scope

Scope is the contract that makes everything else legal. The engine gate
(`tools/runtime/scope.py`) authorizes every network touchpoint; the
PreToolUse hook enforces the same boundary at the harness level for any
Bash/WebFetch the model improvises. Nothing fires before the operator
declares the boundary.

1. Intake. From the operator's argument and any program policy:
   - target host (the authorization anchor),
   - allowed extra hosts (`--scope a,b` — e.g. API or CDN hosts),
   - EXCLUDED hosts (`--exclude x,y` — bug-bounty carve-outs).
   Ask for anything missing. An exclusion beats every allow rule, including
   the target wildcard — surface carve-outs explicitly before continuing.
2. Live gate preview (deterministic, no network):
   ```bash
   python3 - <<'EOF'
   from tools.runtime.scope import ScopeGate
   g = ScopeGate()
   g.bind("<target>", ["<extra>", "..."], deny_entries=["<excluded>", "..."])
   for u in ["https://<target>/", "https://api.<target>/", "https://<excluded>/",
             "https://<lookalike>.example/", "https://127.0.0.1:9/"]:
       try:
           print("ALLOW", u, "->", g.check(u))
       except Exception as e:
           print("DENY ", u, "->", type(e).__name__, getattr(e, "policy", ""))
   EOF
   ```
   Verify the doctrine holds: subdomains under the target allowed by the
   suffix rule; excluded hosts denied even under the wildcard; lookalike
   hosts never match by suffix; loopback mirrors the engine rule.
3. Harness contract: while a mission runs, `state/scope_contract.json`
   carries this boundary to `hooks/bugwolf_pretool_scope_hook.py` (PreToolUse
   on Bash + WebFetch). Confirm the file exists for the active mission —
   `MissionRunner` writes it on bind and clears it on close. To verify the
   hook's deny behavior OUTSIDE a mission (it is inert without a contract):
   `python3 hooks/bugwolf_pretool_scope_hook.py clear` removes a stale
   contract. Never `clear` during a live mission — that revokes harness
   enforcement until the runner rewrites it.
4. Print the boundary as the operator will see it in denials: target,
   allowed extras, exclusions with the reason they were declared, and the
   journal location for hook denials
   (`state/orchestrator/<mission>/scope_hook/denials.jsonl`).

If the operator asks to widen scope mid-mission, that is a NEW declaration:
stop, re-confirm, rebind explicitly. Silent scope growth is the classic
accident this gate exists to prevent.

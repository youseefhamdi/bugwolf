---
description: Show BugWolf mission status (graph, leads, modes, preflight digest)
argument-hint: "[mission-id]"
---

# BugWolf status

1. Graph status: `python3 -m tools.runtime.scheduler --status --mission-id <id>` (node counts by state, runnable next).
2. Lead ledger: load `state/orchestrator/<id>/leads.jsonl` — count PWNED / REFUTED / BUDGET-EXHAUSTED / OPEN, list OPEN leads with tier + exhaustion blockers (`closeability()`).
3. Mode journal: tail `state/orchestrator/<id>/modes.jsonl` — last mode, tick cursor, completions.
4. Preflight digest: read `state/preflight/manifest.json` (cached, no probing).
5. Print everything; hide nothing. A mission with open leads is never "done" — say so.

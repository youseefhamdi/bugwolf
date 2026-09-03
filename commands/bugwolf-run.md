---
description: Execute (or resume) a BugWolf mission through the task graph
argument-hint: "[mission-id] [target] [paths] [--domains ...] [--accounts accounts.json]"
---

# BugWolf run

1. If `mission-id` exists on disk (`state/orchestrator/<mission-id>/graph.json`), resume it — open leads re-dispatch FIRST (R6), completed deterministic work never re-runs (P5):
   `python3 -m tools.runtime.mission_runner --mission-id <id> --target <target> --paths <paths> [--accounts <file>] --json`
2. Otherwise start fresh (same command; preflight runs inside `run()` before any lane).
3. On exit print: findings / refuted / open (with tiers), per-lane summaries, and any `blocked-browser` / blocked-capability leads.

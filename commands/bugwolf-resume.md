---
description: Resume a BugWolf mission after stop/context-reset (open leads first, never re-run finished work)
argument-hint: "[mission-id]"
---

# BugWolf resume

1. Replay the JSONL tail (modes + hooks + graph) — rebuild state from disk, never from conversation memory:
   `echo '{}' | python3 hooks/bugwolf_stop_hook.py resume` then `python3 -m tools.runtime.scheduler --status --mission-id <id>`
2. Re-dispatch open leads FIRST (R6), then active chains, then new-surface recon — in that order.
3. Completed deterministic work is never re-run (P5): finished tasks stay finished; leads with terminal states (PWNED / REFUTED / BUDGET-EXHAUSTED) stay terminal.
4. Continue with the mode the journal shows, or `/bugwolf-run <mission-id> <target>` to drive the graph again.

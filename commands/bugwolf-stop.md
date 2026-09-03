---
description: Freeze BugWolf mission state (persistent-mode stop hook)
argument-hint: "[mission-id]"
---

# BugWolf stop

1. Freeze mode state (stop hook contract — thin, millisecond, JSONL):
   `echo '{}' | python3 hooks/bugwolf_stop_hook.py stop` (with `BUGWOLF_MISSION_ID=<id>` in the environment)
2. Confirm the freeze line landed in `state/orchestrator/<id>/hooks.jsonl` and the mode journal recorded `action=stop`.
3. Report: open leads count (they re-dispatch FIRST on resume), current mode + tick cursor. Nothing is lost — context is disposable RAM; the filesystem is the memory.

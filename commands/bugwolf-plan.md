---
description: Plan a BugWolf mission graph without executing (scheduler dry-run)
argument-hint: "[target] [--domains recon,web_api,verify,report]"
---

# BugWolf plan

1. Build the task graph and show lane roots + preflight gate (no dispatch):
   `python3 -m tools.runtime.scheduler --target <target> --plan`
2. Show which lanes will run, their dependencies, and the preflight gate position (nothing dispatches before `PREFLIGHT_COMPLETE`).
3. List the technique matrices that will bind per domain (see `SKILL.md`).

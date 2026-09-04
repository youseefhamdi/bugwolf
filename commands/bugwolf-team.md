---
description: Plan, run, resume, or inspect a multi-agent BugWolf team (specialized subagents in waves)
argument-hint: "[plan|run|resume|status] [mission-id] [target] [--domains d1,d2] [--bugs class1,class2]"
---

# BugWolf team

Multi-agent execution: a composed roster of specialized subagents
(`bugwolf:<role>`, defined in `agents/bugwolf/`) driven through waves —
**recon → hunt (parallel specialists) → verify → report** — by
`tools/runtime/team.py`, with tier-routed model preferences per member and
crash-safe resume.

## 1. Compose (no execution — always safe)

```bash
python3 -m tools.core.agent_registry --team --domains <domains> --bugs <classes> --json
python3 -m tools.runtime.team --mission <id> --target <target> --domains <domains> --plan --json
```

Print the roster with composition reasons, per-member tier and model
preference. Verify playbooks are intact before dispatch:

```bash
python3 -m tools.core.agent_registry --verify
```

## 2. Run / resume — live Task-tool dispatch

Bind the **task-tool worker** to enqueue member dispatches to the durable
file queue, then drain it from this session:

```bash
# terminal 1 — the engine (blocks per member until results arrive):
python3 -m tools.runtime.team --mission <id> --target <target> \
  --worker task-tool --timeout 900 --run --json

# terminal 2 — the harness drain loop (this Claude Code session):
python3 -m tools.runtime.team_dispatch --mission <id> --next --json
#   -> {"job": {..., "harness_role": "bugwolf:waf-bypass", "prompt": ...}}
#   invoke: Task(subagent_type="bugwolf:waf-bypass", prompt=<job.prompt>)
#   feed the subagent's report back:
python3 -m tools.runtime.team_dispatch --mission <id> --complete <job-id> \
  --status DONE --summary "..." --messages '[{"to_role":"verify","kind":"lead","body":{...}}]' --json
#   or, on subagent failure:
python3 -m tools.runtime.team_dispatch --mission <id> --fail <job-id> --reason "..."
```

- Waves run in order; members within a wave run in parallel (bounded by the
  mission budget's `max_parallel_tasks`); the engine heartbeats while
  waiting, so a live claim is never judged stale.
- Per-member budget expiry closes the member **BUDGET-EXHAUSTED** — honest,
  never fabricated DONE. A late result after expiry is rejected.
- Every start/finish is an append-only line in
  `state/orchestrator/<mission>/team/runs.jsonl`; checkpoints land in
  `team/state.json`; the queue lives in `team/dispatch/{jobs,results}/`.
- After a crash: rerun with `--resume` — stale claims (heartbeat older than
  15 min) are recovered, finished members never re-run.
- Without `--worker task-tool`, execution falls back to a bound Python
  worker (tests) or BLOCKED evidence per member (no fake results).

## 3. Status

```bash
python3 -m tools.runtime.team --mission <id> --status --json
```

Wave/member states, attempts, totals. Team state is a *record*: the scope
gate (`tools/runtime/scope.py`) and sandbox (`tools/runtime/sandbox.py`)
still hold at every network/spawn choke point for every member.

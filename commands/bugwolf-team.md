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

## 2. Run / resume — live subagent dispatch

### Preferred: native in-process worker (one terminal)

Bind the **native worker** to spawn each `bugwolf:<role>` subagent headlessly
from the engine process itself — no queue, no second terminal:

```bash
python3 -m tools.runtime.team --mission <id> --target <target> \
  --worker native --timeout 900 --run --json
```

Each member becomes one bounded `claude --print --output-format json`
subprocess (prompt on stdin, timeout + output cap enforced), spawned as
its specialist: **`--agent bugwolf:<role>` is pinned by default** from
the dispatch payload's `harness_role` (`pin_agent=False` opts out for
CLIs without subagent-type support). Tier
preferences are **pinned out of the box**: `DEFAULT_MODEL_MAP` maps the
router's preference strings (`none` → no flag, `slm-fast` → `haiku`,
`frontier-reasoning` → `sonnet`; an unmapped primary degrades to the
member's fallback preference) — no operator config needed. Pass
`model_map=` to override per key (merged over the defaults), or
`command_builder=` to fully customize the argv (different flag names,
extra flags — it wins over all default pinning).
No bound CLI in the environment ⇒ members close `FAILED`
honestly — never fabricated results.

### Alternative: task-tool worker (two terminals)

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
- **Finding-driven recomposition (default on):** hunt members may recommend
  unstaffed bug classes via a `recommended_bug_classes` result field or an
  `agent_recommendation` handoff message:

  ```json
  {"status": "DONE",
   "recommended_bug_classes": [{"bug_class": "waf_bypass",
                                 "reason": "WAF 403s on all probes"}]}
  ```

  Recommended classes join the roster as their registry-deterministic
  specialist (budget-capped by `max_agents`, deduped, workflow agents never
  re-added) and the team **re-enters the hunt wave** before verify —
  bounded by `max_recompose_rounds` (default 3; a cap hit is recorded as
  `recompose_capped`, rounds run as `recompose_rounds`). Recon-wave
  findings feed the same hook, so a specialist can join **before** the
  first hunt pass. Every add or skip is recorded exactly once in
  `state["recompositions"]` (and the runs ledger) — decisions are
  idempotent across re-entry rounds and `--resume`. Pass `--no-recompose`
  to pin the planned roster; the preference persists across `--resume`.
- **Recon depth is a dispatched obligation:** recon-lane members receive
  `intel.recon_depth` (D0-D3 technique slice, live ledger coverage, close
  blockers) from `tools/recon/depth_ladder.py`. Recon closes only with an
  empty `recon_close_blockers` list — untried techniques or unclosed
  levels are recorded honestly; waivers are explicit ledger events with a
  reason. D3 (`param-surface`, `js-route-map`, `cloud-buckets`,
  `mobile-endpoints`, `historical-crossref`) is mandatory — it is the
  pass shallow recon always skips.
- **Census evidence auto-recomposes the team:** recorded census hits
  (bucket hostnames, WAF/CDN signatures, secrets in bundles, mobile
  endpoints) are cross-referenced by the ledger's `SIGNAL_RULES` and staff
  the matching specialist automatically — same dedupe, budget cap, and
  idempotent ledger as explicit recommendations, with `recon D-evidence:`
  provenance on every record. Write census detail text that names
  concrete surface; `--recommendations` previews the cross-reference.
- Per-member budget expiry closes the member **BUDGET-EXHAUSTED** — honest,
  never fabricated DONE. A late result after expiry is rejected.
- Every start/finish is an append-only line in
  `state/orchestrator/<mission>/team/runs.jsonl`; checkpoints land in
  `team/state.json`; the queue lives in `team/dispatch/{jobs,results}/`.
- After a crash: rerun with `--resume` — stale claims (heartbeat older than
  15 min) are recovered, finished members never re-run.
- Without `--worker`, execution falls back to a bound Python
  worker (tests) or BLOCKED evidence per member (no fake results).

## 3. Preflight and status

Before running, print an operational readiness report (no execution, no
state writes — safe on a fresh mission id):

```bash
python3 -m tools.runtime.team --mission <id> --target <target> --preflight --json
```

Reports persisted status, worker binding (`none (members will close
BLOCKED honestly)` when unbound), recomposition policy (`source_waves`,
`max_rounds`, `rounds_run`, recorded decisions), roster counts, recon
depth coverage, and the coverage gate.

The `recon_depth` section (in both `--preflight` and `--status`) shows
per-depth covered/total counts with untried + waived techniques, honest
close blockers, and evidence-driven recommendations annotated with
staffing state (`role` + `staffed`) — you see not just "bucket surface
found" but whether the matching specialist is already on the roster. A
mission with no recon activity reports `journal: false`, never
fabricated depth intel. The MCP bridge exposes the same report as
`bugwolf_team {"action": "preflight"}`.

For live wave/member state:

```bash
python3 -m tools.runtime.team --mission <id> --status --json
```

Wave/member states, attempts, totals. Team state is a *record*: the scope
gate (`tools/runtime/scope.py`) and sandbox (`tools/runtime/sandbox.py`)
still hold at every network/spawn choke point for every member.

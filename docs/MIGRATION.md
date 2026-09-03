# BugWolf Migration Guide — orchestrator plan v2 (Phases 0–8)

This guide maps every pre-orchestrator entry point to its orchestrator
equivalent. Nothing was removed: shims and old CLIs keep working; the
orchestrator is the new spine.

## Mission lifecycle (the new spine)

```text
/bugwolf <target> --paths ...        # commands/bugwolf.md
  → harness intake → MissionSpec (tools/runtime/contracts.py)
  → MANDATORY preflight (tools/runtime/preflight.py) — no dispatch before PREFLIGHT_COMPLETE
  → Scheduler plan/execute (tools/runtime/scheduler.py)
  → lanes (mission_runner.py): recon → web_api → domain lanes → verify → report
  → lead protocol (lead_protocol.py): R1 leads, technique matrices, ladder T0–T4
  → modes (modes.py): research / verify / deep-dive / coverage / report
  → report (report.json) with full provenance
```

## Old → new mapping

| Pre-orchestrator entry point | Orchestrator equivalent |
|---|---|
| ad-hoc hunting scripts / engines called directly | `python3 -m tools.runtime.mission_runner --mission-id <id> --target <url> --paths ...` |
| manual "remember what to test" | lead journal (`state/orchestrator/<id>/leads.jsonl`) + technique matrices + escalation ladder |
| run-this-tool-then-that-tool checklists | task graph with preflight gate, dedup, and attack-first priority |
| Cron/loop wrappers around engines | persistent modes (`tools/runtime/modes.py`) — stop/resume replays the JSONL tail |
| OOB callbacks checked by hand | OAST service (`tools/runtime/oast.py`): per-surface canaries, 100% attributed |
| "looks executed in the response" | browser validation (`tools/runtime/browser_driver.py`): console/DOM signature or blocked-browser |
| time-of-check races by sleeping | race engine (`tools/validation/race_engine.py`): last-byte sync barrages |
| Ad-hoc concurrency per engine | scheduler lanes with budget caps + attack-first ordering |
| Duplicate tool invocations across agents | P6 fingerprint dedup at dispatch |
| keyword-based model choice | `configs/models.json` complexity routing (P3) |
| ad-hoc WAF payload lists | ART ordering in `fuzz_bridge` (max-min divergence first) |

## State layout (all JSONL/JSON, restart-safe)

```text
state/
├── preflight/<digest manifest>     # capability memory (PF3)
├── orchestrator/<mission>/
│   ├── graph.json                  # task graph (resume = load)
│   ├── results.jsonl               # every TaskResult (P5)
│   ├── leads.jsonl                 # lead journal (R1–R6)
│   ├── modes.jsonl                 # mode state machines
│   ├── hooks.jsonl                 # hook shim journal
│   └── report.json                 # assembled findings + provenance
├── oast/registry.jsonl|interactions.jsonl
├── benchmark/latest.json
├── perf/dashboard.json
└── release/capability_manifest.json
```

## Commands (plugin package)

`/bugwolf` start · `/bugwolf-plan` dry-run · `/bugwolf-run` execute/resume ·
`/bugwolf-status` · `/bugwolf-review` adversarial verify · `/bugwolf-report` ·
`/bugwolf-stop` freeze · `/bugwolf-resume` open-leads-first.

MCP bridge: `claude mcp add bugwolf -- python3 bridge/bugwolf-mcp.py`.

## Release gates (all must pass)

```bash
python3 -m tools.readiness                       # manifest truth
python3 tools/perf.py --measure                  # §5.3 targets
python3 tools/capability_manifest.py             # documented = implemented
bash scripts/ci_bundle_check.sh                  # bundles + self-eval
python3 -m unittest discover -s tests -p "test_*.py"
```

`capability_manifest.py` is the release blocker: any documented-but-missing
capability fails it. Unmet perf targets print as UNMET, never dropped.

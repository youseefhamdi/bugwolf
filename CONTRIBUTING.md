# Contributing to BugWolf

Thanks for contributing. BugWolf is understanding-driven offensive-security
tooling for **authorized** engagements — contributions that add capability
inside that contract are welcome.

## Ground rules

1. **Authorized use only.** Every feature must operate inside the
   operator-declared boundary (`tools/runtime/scope.py`, deny-by-default).
   A PR that adds target discovery, weakens the scope gate, or bypasses the
   sandbox will be rejected regardless of its other merits.
2. **Honesty is a feature.** A capability that is missing must return
   blocked/budget-exhausted evidence — never a fabricated result. Tests that
   assert honest degradation are as important as tests that assert success.
3. **Fail closed.** New gates default to enforcing; new flags are operator
   *declarations recorded for provenance*, never silent bypasses.

## Agent edits go through the registry, never the files

`agents/bugwolf/*.md` files are **generated**. Edit the source of truth:

1. Change the `AgentSpec` in `tools/core/agent_registry.py` (or the playbook
   in `references/hacking-agents/` the spec points at).
2. Regenerate: `python3 scripts/generate_agents.py`
3. Verify: `python3 scripts/generate_agents.py --check`

Front-matter contract (enforced by `tools/plugin_manifest.py --check-agents`):

- `model:` — native Claude Code field: `sonnet | opus | haiku | inherit`
  (mapped from the spec's tier affinity: deterministic → haiku,
  local_slm → sonnet, frontier → opus).
- `tools:` — real Claude Code tool names, derived per lane. Verify/report
  agents are read-only (no `Bash`); hunt agents get `Bash` + `Task`.
- `x-bugwolf-tier:` — BugWolf router vocabulary (consumed by
  `tools/core/model_router.py`); the legacy `model-tier:` key is forbidden.

## Test gates

```bash
python3 -m unittest discover -s tests -p "test_*.py"   # full suite
python3 tools/plugin_manifest.py --all --json          # packaging gates
python3 scripts/generate_agents.py --check             # agent sync
python3 tools/perf.py --measure                        # perf regression gate
```

CI (`.github/workflows/ci.yml`) runs all of these plus the benchmark quality
gate against the deterministic stub target. A PR that drops suite coverage
below the current count needs a stated reason in the description.

## Versioning & releases

- Bump `VERSION` **and** add a `## vX.Y.Z` heading at the top of
  `CHANGELOG.md` — `tools/plugin_manifest.py --check` fails on drift
  between `VERSION`, `plugin.json`, `marketplace.json`, and the changelog.
- Releases are tag-driven: push `vX.Y.Z` and `.github/workflows/release.yml`
  runs the suite, builds both bundles, emits SHA256SUMS, and publishes the
  GitHub Release.

## What to work on

See `docs/MASTER_PLAN.md` — the Understanding Layer (U1–U9), the raw-socket
send engine, and the harness-level hooks are the roadmap's open phases.
Open an issue before large architectural changes.

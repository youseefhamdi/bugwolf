---
description: 60-second BugWolf smoke test — prove the engine works before hunting
argument-hint: "[--full]"
---

# BugWolf doctor

Value before doctrine: this command proves the installed engine actually
detects bugs, in about a minute, against the deterministic stub target —
no SKILL.md reading required.

1. Runtime diagnostics: `python3 tools/lab_doctor.py` (or `--json`).
   Reports browser (Playwright/Chromium), emulator, chain node (anvil),
   local model, MCP, and cloud runtimes with exact fix commands for
   anything missing.
2. Engine smoke (deterministic, offline):
   `python3 -m unittest tests.test_replay_engine tests.test_browser_playwright -v`
   — the byte-exact send engine and (when Playwright is installed) the
   browser-confirmation lane against the stub target's real sinks
   (desync frontend, executable XSS, price-tamper checkout).
3. Gates: `python3 tools/plugin_manifest.py --all` — packaging, version
   sync, agent front-matter integrity of THIS install.
4. Optional full regression (slower): `python3 -m unittest discover -s
   tests -p "test_*.py"` — the entire suite.
5. Install integrity (offline, fail-closed): `python3 tools/harness_guard.py
   --verify-install --json` — re-hashes the installed tree against the
   release manifest that shipped with it (signature verified too when the
   release was signed).
6. Update check — ONLY when the operator explicitly asks. Never run
   unprompted; nothing in bugwolf phones home at session start:
   `python3 tools/release_signing.py --check-update --json` reads the
   latest tagged release and reports it as a FACT. A release becomes
   actionable only after the operator verifies its SHA256SUMS + minisign
   signature. Act on the result; never auto-apply.
7. Interpret for the operator:
   - all green → the engine detects the seeded classes end-to-end; hunting
     runs on proven machinery,
   - runtime MISSING rows → exact fix commands, and which lanes degrade
     honestly (no browser ≠ broken engine; it means client-side verdicts
     go `blocked-browser` instead of EXECUTION-CONFIRMED),
   - test failures → stop; fix the install before pointing it at any
     target. A broken engine that still fires requests is worse than no
     engine.

Failures here are findings about the harness, not the target — record them
before the mission starts.

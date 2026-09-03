---
description: Start a BugWolf mission (parse target + surfaces into MissionSpec, pre-flight, then run)
argument-hint: "[target] [paths] [--domains recon,web_api,verify,report] [--accounts accounts.json]"
---

# BugWolf mission start

1. Parse the operator input into a durable MissionSpec:
   - target base URL (required, operator-declared)
   - surfaces/paths (`--paths` comma list) — never assumed
   - domains (default: `recon,web_api,verify,report`)
   - optional account matrix JSON (`--accounts`)
2. Run mandatory pre-flight FIRST (no mission work before it completes):
   `python3 -m tools.runtime.preflight --target <target> --offline --json`
3. Run the mission through the scheduler:
   `python3 -m tools.runtime.mission_runner --mission-id bw-$(date +%s) --target <target> --paths <paths> --domains <domains> [--accounts <file>] --json`
4. Report findings, refuted, and open leads with their escalation tiers. Open leads are normal — they re-dispatch first on resume (R6).

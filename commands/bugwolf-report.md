---
description: Assemble the mission report (evidence + provenance) via report mode
argument-hint: "[mission-id]"
---

# BugWolf report

1. Entry predicate: report mode requires ZERO open leads. If any lead is OPEN, list them with `closeability()` and stop — resolve or BUDGET-EXHAUST them first (every technique recorded-tried + research + ladder T4).
2. Run report mode: `python3 -c "from tools.runtime.modes import ModeEngine; ..."` (or inline equivalent) — the engine writes `state/orchestrator/<id>/report.json` with findings, refuted, and provenance.
3. Render the operator report: findings by severity with evidence IDs, refuted with counter-evidence, full technique-matrix provenance per finding, and the coverage summary (which classes got zero coverage and why).
4. Redact session material (`<REDACTED-…>`); severity = demonstrated impact only.

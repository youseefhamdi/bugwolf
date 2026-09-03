---
description: Adversarially review leads (disprove before believing; verify lane)
argument-hint: "[mission-id] [--lead LEAD-ID]"
---

# BugWolf review

1. For the given lead (or every OPEN lead), show: technique log, research refs, escalation history, evidence refs.
2. Re-run the verify lane replay for the lead's class — a claim survives only if the deterministic replay reproduces (G5 discipline: fresh execution, no shared context).
3. For each PWNED candidate, run the disproof checklist: caching? WAF rewrite? contamination? tooling artifact? scope violation? benign explanation?
4. Close REFUTED only with counter-evidence; never overwrite a terminal lead (BUDGET-EXHAUSTED/PWNED are final).
5. Output: per-lead verdict table (PROMOTE / DEMOTE / KILL) with the evidence IDs cited.

---
description: Run the BugWolf mandatory research loop (R1–R7 checkpoints + freshness)
argument-hint: "<target> [--checkpoint pre-hunt|post-recon|pre-report] [--mode modes] [--stack ...]"
---

# BugWolf research

No hunt from a blank slate: the R-loop grounds every stage in current,
cited intelligence. R1–R5 run in sequence at fixed mission points; R6/R7
fire event-driven the moment the hunt hits a wall or a finding is
sub-critical — outside the sequence, exactly when needed.

1. Sequence checkpoints (execute, persist to `research/{target}/{checkpoint}/`):
   - **R1 pre-hunt** (session start, before any probe):
     `python3 tools/research_loop.py --checkpoint pre-hunt --mode <modes> --execute --target <t>`
     → baseline Top-10 / CWE-25 / KEV frame → `research/{t}/baseline.md`.
   - **R2 post-recon** (needs the `--stack` from `tools/tech_fingerprint.py`):
     `python3 tools/research_loop.py --checkpoint post-recon --stack <...> --execute --target <t>`
     → exact-version advisories; context carries forward (stack feeds R2,
     discovered classes feed R4/R6/R7).
   - **R3/R4/R5** at their plan checkpoints (recon depth / technique
     selection / report prep — see the DEEP-RESEARCH LOOP table in SKILL.md).
2. Event-driven checkpoints:
   - **R6 blocker** — a WAF/rate/structure wall: convert the blocker into
     bypass research, not a dead end.
   - **R7 escalation** — a sub-critical finding: force an escalation search
     (chain partner, impact elevation) BEFORE any downgrade. Never downgrade
     without R7 on record.
3. Freshness gate: re-check any research older than the mission window
   (exploit-DB/KEV items move). A stale citation is removed from the brief,
   not softened.
4. Output discipline: every hunt dispatch cites its research line; an
   agent that cannot name its citation hunts from a blank slate — send it
   back through the relevant checkpoint.

Persistence is identical for all seven: `research/{target}/{checkpoint}/`,
so any later session can re-derive why a technique was chosen.

---
description: Open the BugWolf lead ledger (OPEN LEAD state machine, kill guard, chain pool)
argument-hint: "[target] [--state OPEN|MUTATING|PARKED|FINDING|KILLED] [lead-id]"
---

# BugWolf leads

The ledger is the mission's memory. An OPEN LEAD is a persisted research
object that mutates one variable at a time until its impact is provable —
never a dropped journal line. Every refutation needs evidence; a kill
refused is a park, not a delete.

1. Ledger state: `python3 tools/leads.py --list --target <target>` (add
   `--state <state>` to filter). Count per state; OPEN+MUTATING is the live
   workload.
2. For each interesting lead: `python3 tools/leads.py --get --target <t> --lead <id>`
   — show the two halves (trigger / impact verdicts), preconditions with
   status, and the mutation history.
3. Next experiment (deterministic, anti-repeat): `python3 tools/leads.py
   --next-mutation --target <t> --lead <id>` — the ledger picks the first
   missing precondition never tried with a given value. Mutate ONE variable:
   `python3 tools/leads.py --mutate --target <t> --lead <id> --variable V
   --old X --new Y --result advanced --evidence "..."`.
4. Kill discipline (enforced, not advisory): `--kill` REFUSES unless BOTH
   halves are refuted with evidence — the refusal auto-PARKS the lead into
   the chain pool and counts the dismissal attempt. Report refused kills as
   parkings.
5. Chain pool: `python3 tools/leads.py --chain-partners --target <t> [--lead <id>]`
   — parked leads are re-scanned against findings; a parked lead may be the
   missing half of the next A→B breakthrough.

Never summarize a lead as "dead". The only dead lead is KILLED with two
recorded refutations; everything else is alive somewhere in the state
machine.

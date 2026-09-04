---
description: Rank A→B attack chains in BugWolf (deep_chain × differential × impact focus)
argument-hint: "<target> [--findings state/sessions/<t>/findings.jsonl] [--max-hops 5] [--focus impact]"
---

# BugWolf chain

Findings compound. A sub-critical finding is often the missing half of a
critical chain — this command ranks the combinations by impact, not by
individual severity.

1. Graph the edges: `python3 tools/deep_chain.py --findings-file
   state/sessions/<t>/findings.jsonl --classes <c1,c2,...> --max-hops 5 --json`
   — the walk emits A→B paths across the class graph with hop counts.
2. Feed the pool:
   - confirmed findings (`findings.jsonl`),
   - PARKED leads (`python3 tools/leads.py --chain-partners --target <t>` —
     a parked lead is a chain candidate by definition),
   - **exploit-feedback hypotheses**: after a live exploit, the demonstrated
     impact data implies downstream classes — the chain pool records them as
     OPEN leads with the source finding as chain partner.
3. Differential signals (facts from the crawl, `crawl/access_matrix.json`):
   identity A→B differentials (anon 403 / user 403 / admin 200) mark the
   endpoints where a chain is likely to land. Prefer chains whose final hop
   targets a differential path — the access boundary is already observed.
4. Rank by impact focus, not severity strings: dollar value, PII exposure,
   account takeover, privilege boundary crossing. The plan wants ONE ranked
   list — dedupe paths that reach the same terminal impact and keep the
   shortest.
5. For the top chains, create OPEN LEADs with the chain partner attached
   (`--partner <finding-id>`) so the hunt tests the combination, not the
   parts.

A chain prediction is a hypothesis until the first hop is evidenced —
dispatch it like any lead: trigger half first, impact half second.

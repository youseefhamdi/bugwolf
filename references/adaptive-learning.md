# Adaptive Learning After Each Journey

BugWolf improves its future research from completed journeys without
self-modifying executable source. Each completed hunt, recon run, and
potentially-novel analysis extracts bounded technique records into:

```text
state/learning/<target>.jsonl
```

## Lifecycle

```text
observed/researched
      ↓
 candidate (quarantined)
      ↓ explicit evidence review
 approved ──► reused on later journeys
      ↓
 rejected
```

Candidates contain a stable ID, target, technique kind, bug class/defense,
source references, journey label, redacted summary, and observation counts.
They never contain raw credentials, cookies, bearer tokens, JWTs, response
bodies, or unreviewed executable payloads.

The store is append-only and target-isolated. New runs merge duplicate records
instead of creating unlimited copies. `approved` is the only status that can
feed later generated wordlists or research context.

## Review

List candidates:

```bash
python3 tools/adaptive_learning.py --target example.com \
  --list --status candidate --json
```

Approve only after independently confirming the technique and its safe,
authorized applicability:

```bash
python3 tools/adaptive_learning.py --target example.com \
  --review-id TECHNIQUE_ID --decision approve \
  --reviewer operator --evidence "Confirmed on authorized lab fixture; no destructive action"
```

Reject a poisoned, duplicate, irrelevant, or unsafe candidate:

```bash
python3 tools/adaptive_learning.py --target example.com \
  --review-id TECHNIQUE_ID --decision reject \
  --reviewer operator --evidence "Not applicable to this target"
```

## Automatic ingestion

`hunt.py` ingests its result and research manifest at journey completion.
`recon_engine.sh` ingests all persisted checkpoint results after recon.
`zero_day.py` ingests candidate and research metadata after analysis.

The output includes a `learning` block with the candidate IDs and approved
records reused. The research executor uses approved terms only when generating
future target-specific wordlists. Learning remains local and offline; external
search still requires its configured provider and `latest_ready` is never
inferred from the learning store.

## Boundaries

- Learning does not change BugWolf source code, shell commands, authorization
  policy, or execution gates.
- Research titles and snippets are evidence leads, not confirmed findings.
- A learned bypass is not automatically fired; active testing still requires
  scope and explicit confirmation.
- A candidate is not “new” merely because its prose differs; stable normalized
  identity and provenance prevent trivial duplication.
- If the learning store is unavailable, the current journey continues with an
  explicit learning error; no fabricated learning is emitted.

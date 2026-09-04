# Intel Lane Transparency

Phase 6 opsec requires that any third party in the data path is
**documented, bounded, and optional**. This page states exactly what the
intel lane (INTEGRATION_PLAN Phase E, v1.28) crosses, who can see it, and
how to eliminate third parties entirely.

## The lane is default-off

Nothing in `tools/intel/` runs unless explicitly enabled (`--enable-intel`
on the understand CLI, or `intel: true` in the mission spec). The
hermetic test suite and the CI gate never execute a network fetch from
this lane; with the lane disabled, bugwolf's third-party set is unchanged
from v1.23 (OAST callback tunnel only, see `docs/OAST_TRANSPARENCY.md`).

## What the lane fetches

| Channel | Probe/fetch URLs | Feeds |
|---|---|---|
| `github_public` | `https://github.com/<org>`, `https://api.github.com/zen` (probe) | U1 stack lens, U2 endpoints from public issues/READMEs |
| `site_docs` | `<target>/docs` | U1/U2 surface freshness |
| `rss_feed` | `<target>/feed` | U1 product cadence, new surfaces |
| `jobs_page` | `<target>/jobs` | U1 stack signals from job posts |

All fetches are credential-free (v1 gate: a channel that needs login or
cookies is out of scope). Results enter the model as **facts with
provenance** (`channel`, `backend`, `url`, `fetched_at`) and can only
raise a U2 surface rank by a bounded weight — they can never park or
unpark a coverage class, alter the scope gate, or touch the governor.

## Backends and who can see what

| Backend | What crosses | Who can see it | How to eliminate it |
|---|---|---|---|
| `direct` (preferred, every channel) | Your GET of a public target/CDN URL | The target (as any visitor) and your egress IP | Nothing to eliminate — this is bugwolf's own scope-gated replay transport |
| `jina` (fallback-only) | The same public URL, proxied: your request goes to `r.jina.ai/<url>`, Jina's fetcher retrieves the page and returns extracted text | Jina (Reader) sees the URL you fetch and your egress IP; the target sees Jina's fetcher | Set `BUGWOLF_INTEL_DISABLE_JINA=1` or `{"<channel>_backend": "direct"}` per channel — the ordered-backends override pins `direct` and the fallback never runs |

The jina backend exists for one failure mode only: target pages that
serve challenge/boilerplate instead of content to non-browser fetchers.
It is never the preferred backend for any channel, and its results carry
the same provenance fields as any other fact (operators can audit which
backend produced which fact in the model store).

## Data handling

* Intel bodies are truncated to 20 KB in the model store, same as page
  captures.
* No target credentials, mission tokens, or operator identifiers are
  ever sent with intel fetches (credential-free lane).
* Messages rendered by `tools.intel.doctor` are credential-scrubbed at
  the output boundary.
* Intel facts are attributed as `source: "external-intel"` everywhere
  they appear, so external content is always distinguishable from
  target-captured content in briefs and reports.

## Honest failure

A dead channel is a recorded fact (`status: "error"`, reason included),
never a crash and never a silent omission — the same discipline as the
capture/replay loop's skipped-with-reason semantics.

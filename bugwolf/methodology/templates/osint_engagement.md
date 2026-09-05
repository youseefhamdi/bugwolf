# OSINT Engagement

> Open-source intelligence collection for red team pre-engagement or due diligence.

_Template file: `osint_engagement.md`_

## Scoping

- Define the target: organization, executive, brand, domain.
- Define deliverables: report format, depth, anonymization requirements.
- Confirm legal boundaries: do not access private systems, do not exceed public data.
- Confirm opsec: passive only unless explicit authorization for active recon.
- Confirm tooling: Maltego, SpiderFoot, recon-ng, custom scripts.

## Identity OSINT

- Username enumeration: namechk, whatsmyname, sherlock across 500+ platforms.
- Email harvesting: hunter.io, theHarvester, pgp key servers.
- Social media profiling: LinkedIn, Twitter/X, GitHub, Mastodon, Bluesky.
- Image metadata: EXIF from publicly posted photos.
- Conference talks, podcast appearances, public statements.

## Infrastructure OSINT

- Domain registration: WHOIS, historical WHOIS, registrar history.
- ASN mapping: IP ranges, netblocks, BGP routing.
- Certificate transparency: crt.sh, Censys certificate search.
- DNS history: SecurityTrails, DNS Dumpster, ViewDNS.
- Shodan / Censys / InternetDB for exposed services.

## Code & Document OSINT

- GitHub: organization members, public repos, commit metadata, leaked secrets.
- GitLab, Bitbucket, self-hosted git platforms.
- Pastebin, Ghostbin, hastebin: leaked snippets.
- S3 / Azure Blob / GCS public buckets via bucket-stream.
- Job postings: tech stack, internal tooling hints, salary ranges.

## Supply-Chain OSINT

- Vendor list: Crunchbase, procurement data, conference sponsors.
- Managed service providers: identify shared infrastructure.
- Acquisitions and subsidiaries: third-party exposure through M&A.
- Recent breach disclosures: have I been pwned, news monitoring.

## Reporting

- Report organized by kill-chain stage: initial access vectors, exposure summary.
- Each finding labeled with source URL and timestamp.
- Recommendations prioritized by exploitability.
- Opsec note: never include irreplaceable credentials; redact as needed.

## Outputs

- `findings/*.yaml` — registered findings with severity and reproducer.
- `state/engagement/<id>/` — daily notes, surface map, evidence.
- `report/final.md` — final report delivered to the customer.
- `report/citations.md` — auto-generated methodology citations.

## Acceptance Criteria

- All findings reproducible from the documented evidence.
- Severity calibrated to the customer's business context.
- Every finding has at least one fix recommendation.
- Methodology citations attached via CitationEngine.
- Daily standups held; deviations from the runbook documented.

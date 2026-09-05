# Bug Bounty Triage Workflow

> Triage playbook for incoming bug bounty reports at a program operator.

_Template file: `bug_bounty_triage.md`_

## Intake

- Acknowledge within 24 hours; assign report ID and severity tier (S0–S4).
- Capture: title, asset, reproducer, impact, evidence, suggested severity.
- De-duplicate against prior reports by URL, parameter, and bug class fingerprint.
- Check scope: in-scope asset, in-scope bug class, non-duplicate of recent fix.
- Move to researcher queue with SLA timer based on tier.

## Validation

- Reproduce the finding on a clean environment with fresh credentials.
- Verify scope match: asset is on the program scope, no third-party component.
- Capture video + screenshot + raw HTTP exchange. Never trust the reporter's logs alone.
- Determine business impact via asset criticality matrix.
- Confirm fix-on-developer-branch or wait for product team input.

## Prioritization

- Critical (S0): full takeover, mass PII exposure, RCE, payment bypass.
- High (S1): account takeover chains, sensitive data read, persistent XSS.
- Medium (S2): limited PII, limited-impact IDOR, stored XSS in low-traffic areas.
- Low (S3): information disclosure, missing headers, rate-limit gaps.
- Informational (S4): best-practice deviations with no immediate exploit.

## Bounty Decision

- Map severity to bounty range per the public bounty table.
- Apply multipliers for chain complexity, H100-precedent, novelty.
- Bounty reduction criteria: duplicate, out-of-scope, low-quality report, self-inflicted.
- Approval matrix: S0/S1 require security-lead sign-off; S2+ can be auto-approved.
- Bounty payout: HackerOne/Bugcrowd API call, recorded in payment system.

## Communication

- Status updates to reporter every 48 hours until resolved.
- Disclosure coordination if the reporter requests public write-up.
- Public Hall of Fame update at the end of each month.
- Internal post-mortem on each critical finding: root cause, fix, detection gap.

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

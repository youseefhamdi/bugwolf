# Web Application Assessment

> Manual-driven web application security assessment runbook.

_Template file: `web_app_assessment.md`_

## Scoping

- Identify primary entry points: marketing site, app, API, admin portal.
- Document authentication flows: forms, OAuth, SSO, passwordless.
- Document data flows: where does user input enter, where does it land?
- Identify third-party scripts: analytics, ads, marketing tags, support widgets.
- Get deployment architecture: cloud, CDN, WAF, load balancer, rate limiter.

## Recon

- Wayback + gau for historical endpoints.
- Subdomain enum + httpx for live hosts and tech fingerprint.
- JS analysis: extract endpoints, secrets, AWS keys, S3 buckets.
- Discover hidden endpoints via directory brute-force and parameter discovery.
- Map the authentication and authorization matrix per resource.

## Authentication

- Test password complexity, lockout policy, MFA bypass, password reset flows.
- Test JWT: alg confusion, signature stripping, kid injection, jwk header.
- Test OAuth: state parameter, redirect URI, scope escalation, PKCE downgrade.
- Test SAML: signature stripping, XXE in assertion, comment injection.
- Test session: fixation, ID handling, cookie flags, CSRF token entropy.

## Authorization

- Test IDOR on every endpoint with sequential and UUID IDs.
- Test role escalation: admin endpoints accessible to non-admins.
- Test tenant boundary: cross-tenant reads, writes, deletes.
- Test function-level access: hidden admin endpoints via directory brute-force.
- Test API authorization matrix per documented role hierarchy.

## Input Handling

- XSS on every input reflected, stored, or DOM-written.
- SQLi on every parameter sent to a database-backed endpoint.
- Command injection on shell-call parameters (ping, dnslookup, convert).
- SSRF on every URL parameter, including image src and PDF renderer inputs.
- Path traversal on every filename parameter, including zip extraction paths.

## Business Logic

- Replay attack on coupons, invites, password reset tokens.
- Race condition on credit redemption, seat allocation, inventory decrement.
- Price manipulation: client-supplied price, currency, quantity.
- State machine skipping: bypass KYC, MFA, approval, payment steps.
- Privilege escalation: field-level mass-assignment, role parameters.

## Reporting

- Findings registered in `findings/` with reproducer, impact, fix.
- Citation engine attaches methodology pattern references.
- Severity via CVSS 3.1; impact calibrated to the customer's business.
- Final report with prioritized remediation roadmap.

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

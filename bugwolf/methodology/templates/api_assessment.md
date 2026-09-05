# API Security Assessment

> REST and GraphQL API security review runbook.

_Template file: `api_assessment.md`_

## Discovery

- Identify all API endpoints: REST, GraphQL, gRPC, SOAP.
- Download OpenAPI / Swagger spec if publicly available.
- GraphQL introspection query unless explicitly disabled.
- Document authentication scheme per endpoint.
- Map request/response schema for each operation.

## Authentication

- Token validation: JWT, opaque, OAuth, mTLS.
- Token lifetime: short-lived access, revocation list, refresh rotation.
- API key hygiene: where are keys sent, are they scoped, are they logged?
- Service-to-service auth: mTLS, signed requests, scoped IAM.
- Test for credential leakage in error messages, debug endpoints, stack traces.

## Authorization

- Test object-level authorization (IDOR/BOLA) on every GET/PUT/DELETE.
- Test function-level authorization (BFLA) on every admin/management endpoint.
- Test tenant boundary: cross-tenant read/write/delete.
- Test mass-assignment: client-supplied role, is_admin, balance fields.
- Test scope escalation: OAuth scopes broader than the operation requires.

## Input Validation

- Injection on every parameter: SQL, NoSQL, OS command, LDAP, XPath.
- XSS on every string parameter, especially those echoed back in responses.
- Deserialization on binary parameters and JSON-with-type fields.
- SSRF on every URL parameter, especially image, file, and webhook URLs.
- Rate-limit verification on every public endpoint.

## GraphQL-Specific

- Introspection disabled in production.
- Query depth limit and complexity limit enforced.
- Persisted queries only for production traffic.
- Batch/alias attack mitigation: max aliases per request.
- Field-level authorization on every field, not just at the operation level.

## Reporting

- Findings mapped to OWASP API Security Top 10 (2023).
- Severity calibrated to data sensitivity and tenant impact.
- Recommendations prioritized by exploitability and remediation cost.

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

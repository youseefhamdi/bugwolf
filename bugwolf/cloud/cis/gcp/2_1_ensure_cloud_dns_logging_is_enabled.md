# CIS GCP 2.1 — Ensure Cloud DNS logging is enabled

**ID:** 2.1
**Severity:** medium
**Category:** Logging

## Description
Ensure Cloud DNS logging is enabled. Cloud DNS query logs to Cloud Logging.

This control is part of the GCP Foundations Benchmark published by
the Center for Internet Security.  Non-compliance typically maps to
public exposure of internal services, weak identity assurance, or
loss of audit trail during incident response.  Where the control
spans folders or organizations, prefer Org Policy constraints over
per-project checks.

## Audit Procedure
1. Run ``gcloud <service> <describe> --format=json`` and inspect the
   relevant field.
2. For organization-scope controls: ``gcloud organizations get-iam-policy``.
3. Cross-check against Forseti / Security Command Center compliance
   dashboards.

## Remediation
Apply in a dev project first; some controls require resource
recreation (e.g. default network removal).  Where CMEK is required,
ensure the KMS keyring IAM grants cryptoKeyEncrypter to the workload
service account.

## References
- CIS Google Cloud Platform Foundations Benchmark v2.0.0
- https://cloud.google.com/security/

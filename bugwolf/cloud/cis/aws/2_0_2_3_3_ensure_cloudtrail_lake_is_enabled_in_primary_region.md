# CIS AWS Foundations 2.0 — 2.3.3 Ensure CloudTrail Lake is enabled in primary region

**ID:** 2.3.3
**Severity:** medium
**Category:** Logging and Monitoring

## Description
Ensure CloudTrail Lake is enabled in primary region. CloudTrail, CloudWatch, and AWS Config posture in 2.0 favors centralized log aggregation, KMS-encrypted archives, and event-driven remediation over per-account alarms.

This control is part of the AWS Foundations 2.0 lineage, the
successor to the original 2018 v1 benchmark.  Where v1 was an
account-local checklist, v2 emphasises *organization-wide* posture:
the controls can be enforced with SCPs and aggregate dashboards
across hundreds of accounts.  The audit procedure below assumes an
operator with `organizations:Describe*` and `iam:List*` permissions.

## Audit Procedure
1. Run `aws organizations describe-policy --policy-id <SCP>` to
   confirm SCP-level enforcement where applicable.
2. Run `aws --region <region> <service> <describe>` for the resource
   class in scope; filter with `jq` on the relevant field.
3. Cross-check against the Prowler v3.0 `extra7xx` finding list.

Where automation is unavailable, manually enumerate the resource
class and record findings in the bugwolf engagement tracker.  An
auditor must verify each finding manually before remediation; Prowler
findings drift as new services launch.

## Remediation
Apply the remediation in a non-production account first.  Where a
control spans accounts, distribute the change via an automation
pipeline (Control Tower / Customizations for AWS Control Tower /
Account Factory) and watch the CloudWatch alarm for unexpected
behaviour.

For organization-wide controls, prefer SCP-based enforcement to
operator discretion.  An SCP that denies the bad behaviour cannot
be bypassed by a misclick; a console reminder can.

## References
- CIS Benchmark v2.0.0
- https://docs.aws.amazon.com/organizations/
- https://aws.amazon.com/blogs/security/

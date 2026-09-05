# CIS AWS Foundations 1.0 — 5.1 Ensure RDS database instances are not publicly accessible

**ID:** 5.1
**Severity:** critical
**Category:** Database

## Description
Public RDS instances are a direct data-exfiltration primitive.

This control is part of the AWS Foundations Benchmark published by the
Center for Internet Security.  It targets the security posture of
identity, logging, networking, storage, and database primitives in
the AWS account.  Non-compliance typically maps to elevated blast
radius in the event of credential compromise, public exposure of
internal services, or loss of audit trail during incident response.

The audit procedure below is intentionally CLI-first so that it can
be embedded directly into a Prowler / ScoutSuite pipeline.  Where a
control cannot be expressed as a single command, the procedure
spells out the JSON filter that Prowler emits so that operators can
verify the check before relying on it.

## Audit Procedure
1. `aws rds describe-db-instances | jq '.DBInstances[].PubliclyAccessible'`.

Where automated tooling reports the finding, the operator should
always validate the result manually: tools lag behind real AWS API
changes and frequently misreport findings on newly-released
services.  The remediation text below is intentionally generic so
that it remains valid across multiple AWS regions and account
partitions (commercial, GovCloud, China).

## Remediation
Set `PubliclyAccessible=false`; route via private subnet + bastion / SSM.

## Implementation Notes
- This control can usually be enforced via an SCP (Service Control
  Policy) for organization-wide coverage.  SCP-based enforcement
  removes the operator discretion that bypassed the control in the
  first place.
- CloudTrail events relating to this control should be enabled and
  forwarded to a SIEM.  Detective controls should fire on remediation
  attempts as well as violations; an attacker who can disable a
  detective control wants to remove the alarm that fires on their
  intrusion.
- The change should be staged in a development account first.  A
  failed remediation that disables a workload at scale is a
  self-inflicted outage.

## References
- CIS Benchmark v1.5.0
- https://docs.aws.amazon.com/securityhub/
- https://docs.aws.amazon.com/IAM/latest/UserGuide/

# Cloud Security Assessment

> AWS / GCP / Azure misconfiguration and identity review.

_Template file: `cloud_assessment.md`_

## Pre-engagement

- Confirm read-only access to the cloud account(s) via ScoutSuite, Prowler.
- Confirm identity review access: IAM users, roles, policies, federation.
- Document crown-jewel data stores: customer PII, payment data, secrets.
- Identify compliance frameworks in scope: SOC2, PCI-DSS, HIPAA, FedRAMP.
- Confirm incident response contacts and out-of-band communication.

## Identity & Access

- IAM policy review: wildcard actions, wildcard resources, cross-account trust.
- Service control policies: deny-lists, region restrictions, privilege escalation paths.
- Federation: SAML metadata, OIDC trust policies, cross-account assume-role chains.
- Long-lived access keys: scan for keys older than 90 days.
- Privileged identity: who can assume OrganizationAccountAccessRole, BreakGlassRole.

## Data Stores

- S3/Blob/GCS public access: bucket policies, ACLs, Block Public Access.
- Encryption at rest: KMS key rotation, customer-managed keys, key access policy.
- Encryption in transit: TLS 1.2+ required, certificate expiry, mTLS where applicable.
- Database: RDS security groups, public accessibility, parameter groups, IAM auth.
- Backups: cross-region replication, encryption, deletion protection.

## Network

- VPC design: public vs private subnets, NAT gateway, egress filtering.
- Security groups: 0.0.0.0/0 ingress on SSH/RDP/database ports.
- Network ACLs vs security groups, default deny rule coverage.
- VPC flow logs enabled on all subnets, SIEM integration.
- Private endpoints for PaaS services to avoid public egress.

## Detection & Response

- CloudTrail / Cloud Audit Logs enabled in all regions.
- GuardDuty / Security Command Center / Defender enabled.
- Alerts on iam:PassRole, sts:AssumeRole, s3:PutBucketPolicy.
- Incident response runbook tested within the last 12 months.
- Backup and recovery RPO/RTO documented and tested.

## Reporting

- Findings classified by STRIDE or MITRE ATT&CK for cloud.
- Severity mapped to data sensitivity and compliance framework.
- Remediation guidance for every misconfiguration.

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

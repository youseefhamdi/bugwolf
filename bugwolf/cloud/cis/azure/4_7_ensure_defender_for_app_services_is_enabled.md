# CIS Azure Foundations 4.7 — Ensure Defender for App Services is enabled

**ID:** 4.7
**Severity:** medium
**Category:** Logging and Monitoring

## Description
Ensure Defender for App Services is enabled. PAAS threat detection.

This control is part of the Azure Foundations Benchmark published by
the Center for Internet Security.  Non-compliance with this control
typically maps to an elevated blast radius in the event of a tenant
compromise, public exposure of internal services, or loss of audit
trail during incident response.  Where the control spans
subscriptions, prefer management-group-level enforcement with Azure
Policy initiatives over per-resource RBAC.

## Audit Procedure
1. Run the corresponding ``az policy state`` query for the resource
   type; filter by the parameter set in this control.
2. Cross-check against Defender for Cloud's regulatory compliance
   dashboard.
3. Where manual enumeration is needed, iterate the resource graph
   with ``az graph query`` and validate findings.

Where automated tooling reports the finding, validate manually:
Defender for Cloud's compliance scores lag behind new Azure
features and frequently misreport on preview services.

## Remediation
Apply the remediation in a development subscription first.  Azure
Policy assignments at the management group level propagate; test
the impact with ``WhatIf`` mode before applying.

## References
- CIS Microsoft Azure Foundations Benchmark v1.5.0
- https://learn.microsoft.com/azure/defender-for-cloud/

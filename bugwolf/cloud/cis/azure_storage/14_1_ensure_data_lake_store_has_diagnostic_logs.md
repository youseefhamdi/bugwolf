# CIS Azure Storage 14.1 — Ensure Data Lake Store has diagnostic logs

**ID:** 14.1
**Severity:** medium
**Category:** Storage

## Description
Ensure Data Lake Store has diagnostic logs. This control is part of the Azure Storage Benchmark
supplement; the supplement covers storage-specific primitives that
are out of scope for the Foundations benchmark.  Non-compliance
typically maps to public data exposure, key-management weaknesses,
or loss of forensic trail.

## Audit Procedure
1. Run ``az storage account show`` and inspect the relevant field
   (TLS version, public network access, encryption scope).
2. For file shares: ``az storage file share list``.
3. For queue / table: ``az storage queue list`` and ``az storage
   table list``.
4. Cross-check against the Defender for Cloud regulatory compliance
   dashboard.

## Remediation
Apply in a dev subscription first; storage accounts are sticky and
cannot always be migrated in-place.  Where CMK is required, ensure
the key vault access policy grants wrap / unwrap to the storage
account's identity.

## References
- CIS Microsoft Azure Storage Benchmark v1.0.0
- https://learn.microsoft.com/azure/storage/

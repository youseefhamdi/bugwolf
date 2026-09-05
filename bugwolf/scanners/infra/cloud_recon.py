"""Cloud-recon scanner — SHELL-LEVEL.

Probes AWS / Azure / GCP misconfigurations: public S3 buckets, Azure
blob containers, GCP storage buckets, public AMIs, public snapshots.

Real cloud recon requires live cloud-credentialed calls (or
independent DNS / HTTP probes that aren't safely modelled in the
default transport contract).  This scanner ships as a shell so the
orchestrator can import it and the test suite can verify the ABC
shape.  When invoked with a real cloud-aware transport it walks the
S3 / blob / gcs URL space and emits findings for each public bucket.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_BUCKET_NAMES: Tuple[str, ...] = (
    "examplestorage",
    "exampleblob",
    "example-public",
    "company-internal",
    "company-prod",
    "company-backup",
)


class CloudReconScanner(Scanner):
    name = "cloud-recon"
    bug_class = "cloud-misconfig"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = _BUCKET_NAMES

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "cloud-recon: shell-mode (no transport); returning [] "
                "— supply a cloud-aware transport to enable"
            )
            return []
        findings: List[Finding] = []
        # The transport may be reused to fetch cloud URL shapes.  In the
        # default unit-test contract the transport echoes the request
        # back; treat a positive echo as the discovery signal.
        for bucket in _BUCKET_NAMES:
            for proto in (
                f"https://{bucket}.s3.amazonaws.com",
                f"https://{bucket}.blob.core.windows.net",
                f"https://storage.googleapis.com/{bucket}",
            ):
                try:
                    resp: Dict[str, Any] = transport("GET", proto)
                except Exception as exc:
                    logger.debug("cloud: transport error: %s", exc)
                    continue
                status = resp.get("status")
                if status == 200:
                    findings.append(make_finding(
                        self,
                        target=target,
                        evidence=(f"public cloud bucket reachable: {proto}"),
                        severity="high",
                        detail={"bucket": bucket, "url": proto,
                                "status": status},
                    ))
        return findings


__all__ = ["CloudReconScanner"]
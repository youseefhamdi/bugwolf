"""Phase 1.5 LiveFinding — additive dataclass used by the 20 Phase 1.5 scanners.

This is a NEW module. The pre-existing ``Finding`` in ``bugwolf.scanners``
remains untouched; this dataclass captures the Phase 1.5 wire-format that the
20 new scanners emit.

Fields (all keyword-arg, frozen dataclass):
    scanner      scanner name (matches the Scanner.name attribute)
    bug_class    stable slug
    severity     one of: low / medium / high / critical
    endpoint     URL or path
    method       HTTP method
    evidence     short evidence string
    reproducer   short reproducer command / request
    remediation  short remediation hint
    payload_id   stable id of the payload that triggered the finding
    found_at     ISO-8601 timestamp (defaults to utcnow)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


SCHEMA = "bugwolf-scanner-finding-v1"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class LiveFinding:
    scanner: str
    bug_class: str
    severity: str
    endpoint: str
    method: str
    evidence: str
    reproducer: str = ""
    remediation: str = ""
    payload_id: str = ""
    found_at: str = field(default_factory=_utcnow_iso)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "schema": SCHEMA,
            "scanner": self.scanner,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "reproducer": self.reproducer,
            "remediation": self.remediation,
            "payload_id": self.payload_id,
            "found_at": self.found_at,
        }
        if self.extra:
            out["extra"] = dict(self.extra)
        return out


__all__ = ["LiveFinding", "SCHEMA"]

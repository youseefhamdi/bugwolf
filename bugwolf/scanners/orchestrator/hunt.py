"""Hunt orchestrator.

Runs every scanner in a list against a target and aggregates the
findings into a single :class:`CampaignResult`.  Orchestrators in this
package are themselves :class:`Scanner` subclasses so they can sit
alongside their target list inside the registry.

Contract:

    class MyScanner(Scanner):
        ...

    orch = HuntOrchestrator([MyScanner(), OtherScanner()])
    result = orch.scan(target, transport)
    # result.findings -> List[Finding]
    # result.scanners_run -> int
    # result.deduplicated -> int (findings removed by hash)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner


logger = logging.getLogger(__name__)


@dataclass
class CampaignResult:
    """Aggregated result of a hunt over many scanners."""

    target: str
    scanners_run: int = 0
    findings: List[Finding] = field(default_factory=list)
    deduplicated: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scanners_run": self.scanners_run,
            "findings_count": len(self.findings),
            "deduplicated": self.deduplicated,
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }


class HuntOrchestrator(Scanner):
    """Runs every supplied scanner against a single target."""

    name = "hunt-orchestrator"
    bug_class = "campaign-meta"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = ("hunt",)

    def __init__(self, scanners: List[Scanner]) -> None:
        if not isinstance(scanners, list):
            raise TypeError("scanners must be a list[Scanner]")
        for s in scanners:
            if not isinstance(s, Scanner):
                raise TypeError(f"not a Scanner: {s!r}")
        self._scanners = list(scanners)

    @property
    def scanners(self) -> List[Scanner]:
        return list(self._scanners)

    def scan(self, target: str, transport) -> CampaignResult:
        result = CampaignResult(target=target)
        seen: Dict[str, Finding] = {}
        duplicates = 0
        for s in self._scanners:
            result.scanners_run += 1
            try:
                findings = s.scan(target, transport)
            except Exception as exc:  # noqa: BLE001 — orchestrator must
                # continue past single-scanner failures
                logger.warning("hunt: %s raised: %s", s.name, exc)
                result.errors.append(f"{s.name}: {exc}")
                continue
            for f in findings:
                digest = self._digest(f)
                if digest in seen:
                    duplicates += 1
                    continue
                seen[digest] = f
                result.findings.append(f)
        result.deduplicated = duplicates
        return result

    def scan_findings(self, target: str, transport) -> List[Finding]:
        """Convenience wrapper that returns only the findings list."""
        return self.scan(target, transport).findings

    @staticmethod
    def _digest(f: Finding) -> str:
        payload = {
            "scanner": f.scanner,
            "bug_class": f.bug_class,
            "severity": f.severity,
            "target": f.target,
            "evidence": f.evidence,
        }
        b = json.dumps(payload, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8")
        return hashlib.sha256(b).hexdigest()


__all__ = ["HuntOrchestrator", "CampaignResult"]
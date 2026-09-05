# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-sarif-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-sarif-v1"

import json
from typing import Optional

from .types import Severity, finding_from_dict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _normalize(findings):
    out = []
    for f in findings or []:
        if f is None:
            continue
        if isinstance(f, dict):
            try:
                out.append(finding_from_dict(f))
            except Exception:
                continue
        else:
            out.append(f)
    return out


def _build_result(finding):
    sev = _SEVERITY_LEVEL.get(
        finding.severity if isinstance(finding.severity, Severity) else Severity.from_any(finding.severity),
        "none",
    )
    msg_text = finding.title or "N/A"
    if finding.description:
        msg_text = f"{msg_text}\n\n{finding.description}"
    props = {}
    if finding.cwe:
        props["cwe"] = finding.cwe
    if finding.cvss_score is not None:
        props["cvss_score"] = finding.cvss_score
    if finding.evidence:
        props["evidence"] = finding.evidence
    if finding.confidence is not None:
        props["confidence"] = finding.confidence
    if finding.finding_class:
        props["finding_class"] = finding.finding_class
    if finding.gate_result:
        props["gate_result"] = finding.gate_result
    if finding.submission_ids:
        props["submission_ids"] = finding.submission_ids
    if finding.references:
        props["references"] = list(finding.references)
    if finding.reproduction_steps:
        props["reproduction_steps"] = list(finding.reproduction_steps)
    if finding.source:
        props["source"] = finding.source
    result = {
        "ruleId": finding.id or "N/A",
        "level": sev,
        "message": {"text": msg_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.target or "N/A",
                    }
                }
            }
        ],
    }
    if props:
        result["properties"] = props
    return result


def render(findings, *, tool_name="bugwolf", tool_version="0.5.0", run_index=0):
    normalized = _normalize(findings)
    results = [_build_result(f) for f in normalized]
    sarif = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://bugwolf.local",
                        "rules": [],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 0,
                        "exitCodeDescription": "success",
                    }
                ],
                "results": results,
                "properties": {
                    "runIndex": int(run_index),
                    "schema": "bugwolf-reporting-sarif-v1",
                    "resultCount": len(results),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)

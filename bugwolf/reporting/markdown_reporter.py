# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-md-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-md-v1"

import datetime
import os
from collections import Counter
from typing import Optional

from .types import Severity, finding_from_dict


def _esc(value):
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\r", "")


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


def _stats(normalized):
    sev_counts = Counter({s.value: 0 for s in Severity})
    for f in normalized:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
        sev_counts[sev] += 1
    return {"total": len(normalized), "by_severity": dict(sev_counts)}


def _summary_table(stats):
    rows = [
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        rows.append(f"| {sev.upper()} | {stats['by_severity'].get(sev, 0)} |")
    rows.append(f"| **TOTAL** | **{stats['total']}** |")
    return "\n".join(rows)


def _gate_block(gate):
    if not gate:
        return ""
    lines = ["### 7-Question Gate"]
    for k, v in gate.items():
        lines.append(f"- **{_esc(k)}**: {_esc(v)}")
    return "\n".join(lines)


def _submission_block(sub_ids):
    if not sub_ids:
        return ""
    lines = ["### Submissions"]
    for k, v in sub_ids.items():
        lines.append(f"- **{_esc(k)}**: {_esc(v)}")
    return "\n".join(lines)


def _finding_section(f):
    sev_value = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
    lines = [f"## [{sev_value.upper()}] {f.title or 'N/A'}", ""]
    lines.append(f"- **ID**: `{f.id or 'N/A'}`")
    lines.append(f"- **Target**: `{f.target or 'N/A'}`")
    lines.append(f"- **Confidence**: `{round(float(f.confidence or 0.0), 3)}`")
    if f.cvss_score is not None:
        lines.append(f"- **CVSS**: `{f.cvss_score}`")
    if f.cwe:
        lines.append(f"- **CWE**: `{f.cwe}`")
    if f.description:
        lines.append("")
        lines.append(f.description)
    if f.evidence:
        lines.append("")
        lines.append("### Evidence")
        lines.append("")
        lines.append("```text")
        lines.append(f.evidence)
        lines.append("```")
    if f.reproduction_steps:
        lines.append("")
        lines.append("### Reproduction Steps")
        lines.append("")
        for i, step in enumerate(f.reproduction_steps, 1):
            lines.append(f"{i}. {_esc(step)}")
    if f.references:
        lines.append("")
        lines.append("### References")
        lines.append("")
        for r in f.references:
            lines.append(f"- {r}")
    gate_block = _gate_block(f.gate_result)
    if gate_block:
        lines.append("")
        lines.append(gate_block)
    sub_block = _submission_block(f.submission_ids)
    if sub_block:
        lines.append("")
        lines.append(sub_block)
    lines.append("")
    return "\n".join(lines)


def render(findings, *, title="BugWolf Report", metadata=None):
    normalized = _normalize(findings)
    stats = _stats(normalized)
    parts = [f"# {title}", ""]
    if metadata:
        parts.append("## Metadata")
        parts.append("")
        for k, v in metadata.items():
            parts.append(f"- **{_esc(k)}**: {_esc(v)}")
        parts.append("")
    parts.append("## Summary")
    parts.append("")
    parts.append(_summary_table(stats))
    parts.append("")
    if normalized:
        for f in normalized:
            parts.append(_finding_section(f))
    else:
        parts.append("_No findings._")
        parts.append("")
    parts.append("---")
    parts.append("")
    parts.append(f"_Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}_")
    parts.append(f"_Schema: {SCHEMA}_")
    return "\n".join(parts)


def write(findings, path, **kwargs):
    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        data = render(findings, **kwargs)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(data)
        return True
    except Exception:
        return False

# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-h1-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-h1-v1"

from typing import Optional

from .types import finding_from_dict


def _esc(value):
    if value is None:
        return ""
    return str(value)


def _coerce(f):
    if isinstance(f, dict):
        return finding_from_dict(f)
    return f


def _severity_label(sev) -> str:
    if hasattr(sev, "value"):
        return sev.value
    return str(sev).lower()


def render(finding) -> str:
    f = _coerce(finding)
    sev = _severity_label(f.severity)
    cvss = f.cvss_score if f.cvss_score is not None else "N/A"
    lines = []
    lines.append(f"# Title: {f.title or 'N/A'}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f.description or "N/A")
    lines.append("")
    lines.append("## Severity")
    lines.append("")
    lines.append(f"- Severity: **{sev.upper()}**")
    if f.cvss_score is not None:
        lines.append(f"- CVSS Score: **{cvss}**")
    if f.cwe:
        lines.append(f"- CWE: {f.cwe}")
    if f.confidence is not None:
        lines.append(f"- Confidence: {round(float(f.confidence), 3)}")
    lines.append("")
    lines.append("## Asset")
    lines.append("")
    lines.append(f"- Target: `{f.target or 'N/A'}`")
    lines.append("")
    lines.append("## Steps To Reproduce")
    lines.append("")
    if f.reproduction_steps:
        for i, step in enumerate(f.reproduction_steps, 1):
            lines.append(f"{i}. {_esc(step)}")
    else:
        lines.append("1. N/A")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append("```text")
    lines.append(f.evidence or "N/A")
    lines.append("```")
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    impact_text = f.description or "Refer to summary for impact details."
    lines.append(impact_text)
    lines.append("")
    lines.append("## Remediation")
    lines.append("")
    lines.append("Apply input validation, output encoding, and follow the principle of least privilege. "
                 "Refer to OWASP / CWE guidance for this vulnerability class.")
    lines.append("")
    if f.references:
        lines.append("## References")
        lines.append("")
        for r in f.references:
            lines.append(f"- {r}")
        lines.append("")
    if f.gate_result:
        lines.append("## 7-Question Gate Result")
        lines.append("")
        for k, v in f.gate_result.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
    lines.append(f"<!-- BugWolf internal schema: {SCHEMA} -->")
    return "\n".join(lines)


def render_batch(findings) -> str:
    parts = []
    for f in findings or []:
        parts.append(render(f))
        parts.append("\n\n---\n\n")
    return "\n".join(parts).rstrip()

# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-intigriti-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-intigriti-v1"

from typing import Optional

from .types import finding_from_dict


_SEVERITY_SCALE = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}


def _coerce(f):
    if isinstance(f, dict):
        return finding_from_dict(f)
    return f


def _esc(value):
    if value is None:
        return ""
    return str(value)


def _severity_label(sev):
    if hasattr(sev, "value"):
        return sev.value
    return str(sev).lower()


def render(finding) -> str:
    f = _coerce(finding)
    sev = _severity_label(f.severity)
    priority = _SEVERITY_SCALE.get(sev, "P5")
    lines = []
    lines.append("# Vulnerability Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f.description or f.title or "N/A")
    lines.append("")
    lines.append("## Vulnerability")
    lines.append("")
    lines.append(f"- **Title:** {f.title or 'N/A'}")
    lines.append(f"- **Severity:** {sev.upper()} ({priority})")
    if f.cvss_score is not None:
        lines.append(f"- **CVSS:** {f.cvss_score}")
    if f.cwe:
        lines.append(f"- **CWE:** {f.cwe}")
    lines.append("")
    lines.append("## Endpoint")
    lines.append("")
    lines.append(f"- **URL / Asset:** `{f.target or 'N/A'}`")
    lines.append("")
    lines.append("## Reproduction Steps")
    lines.append("")
    if f.reproduction_steps:
        for i, step in enumerate(f.reproduction_steps, 1):
            lines.append(f"{i}. {_esc(step)}")
    else:
        lines.append("1. N/A")
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(f.description or "Refer to summary for impact analysis.")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append("```text")
    lines.append(f.evidence or "N/A")
    lines.append("```")
    lines.append("")
    lines.append("## Mitigation")
    lines.append("")
    lines.append("Apply input validation, output encoding, and access controls. Reference OWASP / CWE guidance.")
    lines.append("")
    if f.references:
        lines.append("## References")
        lines.append("")
        for r in f.references:
            lines.append(f"- {r}")
        lines.append("")
    if f.gate_result:
        lines.append("## 7-Question Gate")
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

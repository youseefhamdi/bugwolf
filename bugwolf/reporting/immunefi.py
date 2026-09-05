# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-immunefi-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-immunefi-v1"

from typing import Optional

from .types import finding_from_dict


_IMPACT_CATEGORIES = [
    "Direct loss of funds",
    "Loss of funds via misuse of privileged role",
    "Theft of yield / fees",
    "Permanent freezing of funds",
    "Temporary freezing of funds",
    "Smart contract unable to operate (e.g., revert on essential operations)",
    "Smart contract operating incorrectly (e.g., incorrect accounting, governance)",
    "Other",
]


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


def _category_for(severity, gate):
    sev = _severity_label(severity)
    if "critical" in sev:
        return _IMPACT_CATEGORIES[0]
    if "high" in sev:
        return _IMPACT_CATEGORIES[1]
    if "medium" in sev:
        return _IMPACT_CATEGORIES[2]
    return _IMPACT_CATEGORIES[-1]


def _cvss_vector(cvss):
    if cvss is None:
        return "N/A"
    try:
        return f"CVSS:3.1/{float(cvss):.1f}"
    except (TypeError, ValueError):
        return "N/A"


def render(finding) -> str:
    f = _coerce(finding)
    sev = _severity_label(f.severity)
    asset = f.target or "N/A"
    impact_cat = _category_for(sev, f.gate_result)
    lines = []
    lines.append("# Immunefi Bug Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f.title or "N/A")
    if f.description:
        lines.append("")
        lines.append(f.description)
    lines.append("")
    lines.append("## Asset")
    lines.append("")
    lines.append(f"- **Smart Contract / Asset:** `{asset}`")
    if f.cwe:
        lines.append(f"- **CWE:** {f.cwe}")
    lines.append("")
    lines.append("## Vulnerability Details")
    lines.append("")
    if f.description:
        lines.append(f.description)
    else:
        lines.append("N/A")
    lines.append("")
    lines.append("## Attack Scenario")
    lines.append("")
    if f.reproduction_steps:
        for i, step in enumerate(f.reproduction_steps, 1):
            lines.append(f"{i}. {_esc(step)}")
    else:
        lines.append("1. N/A")
    lines.append("")
    lines.append("## Impact Category")
    lines.append("")
    lines.append(f"- **{impact_cat}**")
    lines.append("")
    lines.append("## Severity & CVSS")
    lines.append("")
    lines.append(f"- **Severity:** {sev.upper()}")
    if f.cvss_score is not None:
        lines.append(f"- **CVSS Score:** {f.cvss_score}")
    lines.append(f"- **CVSS Vector:** {_cvss_vector(f.cvss_score)}")
    lines.append("")
    lines.append("## Proof of Concept / Evidence")
    lines.append("")
    lines.append("```text")
    lines.append(f.evidence or "N/A")
    lines.append("```")
    lines.append("")
    lines.append("## Mitigation")
    lines.append("")
    lines.append("Apply fixes per smart contract security best practices. "
                 "Consider reentrancy guards, input validation, access controls, "
                 "and full coverage by audit and test suite before deployment.")
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

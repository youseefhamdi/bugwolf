# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-html-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-html-v1"

import datetime
import html as html_lib
import os
import string
from collections import Counter
from typing import Optional

from .types import Severity, finding_from_dict

_SEVERITY_COLORS = {
    "critical": "#7a0019",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#27ae60",
    "info": "#5d6d7e",
}

_PAGE_TEMPLATE = string.Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="generator" content="BugWolf Reporting Layer (Phase 5.B)">
<title>${title}</title>
<style>
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; background: #f4f6f8; color: #1c2833; }
header { background: #1c2833; color: #fff; padding: 24px 32px; }
header h1 { margin: 0 0 4px 0; font-size: 24px; }
header .meta { color: #aab7c4; font-size: 13px; }
main { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
.summary { background: #fff; border: 1px solid #d5dbdb; border-radius: 6px; padding: 16px 20px; margin-bottom: 24px; }
.summary h2 { margin-top: 0; font-size: 18px; }
.summary table { border-collapse: collapse; width: 100%; margin-top: 8px; }
.summary th, .summary td { border-bottom: 1px solid #ecf0f1; padding: 6px 10px; text-align: left; font-size: 14px; }
.summary th { background: #f4f6f8; }
.finding { background: #fff; border: 1px solid #d5dbdb; border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
.finding header { display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; background: #f4f6f8; color: #1c2833; cursor: pointer; }
.finding header h3 { margin: 0; font-size: 16px; }
.sev { display: inline-block; padding: 3px 10px; border-radius: 12px; color: #fff; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
.finding .body { padding: 14px 20px; border-top: 1px solid #ecf0f1; }
.finding dl { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px; font-size: 14px; margin: 0; }
.finding dt { color: #566573; font-weight: 600; }
.finding dd { margin: 0; word-break: break-word; }
.evidence, .steps, .refs, .gate { background: #f8f9fa; padding: 10px 12px; border-radius: 4px; margin-top: 8px; font-size: 13px; }
pre.evidence-block { background: #1c2833; color: #ecf0f1; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
details[open] > summary { list-style: none; }
details > summary::-webkit-details-marker { display: none; }
.empty { background: #fff; border: 1px dashed #d5dbdb; padding: 32px; text-align: center; color: #566573; border-radius: 6px; }
footer { text-align: center; color: #7f8c8d; font-size: 12px; padding: 24px; }
</style>
</head>
<body>
<header>
<h1>${title}</h1>
<div class="meta">Generated ${generated_at} &middot; ${count} finding(s)</div>
</header>
<main>
${summary_section}
${findings_section}
</main>
<footer>${footer_text}</footer>
</body>
</html>
"""
)


def _esc(value):
    if value is None:
        return ""
    return html_lib.escape(str(value))


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
    cls_counts = Counter()
    tgt_counts = Counter()
    for f in normalized:
        sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
        sev_counts[sev] += 1
        cls = getattr(f, "finding_class", "") or "uncategorized"
        cls_counts[cls] += 1
        tgt_counts[f.target or "N/A"] += 1
    return {
        "by_severity": dict(sev_counts),
        "by_class": dict(cls_counts),
        "by_target": dict(tgt_counts),
        "total": len(normalized),
    }


def _summary_section(stats, metadata):
    rows = []
    sev_order = ["critical", "high", "medium", "low", "info"]
    for sev in sev_order:
        n = stats["by_severity"].get(sev, 0)
        color = _SEVERITY_COLORS[sev]
        rows.append(
            f'<tr><td><span class="sev" style="background:{color}">{sev.upper()}</span></td>'
            f'<td>{n}</td></tr>'
        )
    sev_table = (
        "<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    meta_html = ""
    if metadata:
        items = []
        for k, v in metadata.items():
            items.append(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>")
        if items:
            meta_html = "<dl>" + "".join(items) + "</dl>"
    return (
        '<section class="summary"><h2>Summary</h2>'
        f'<p>Total findings: <strong>{stats["total"]}</strong></p>'
        + sev_table
        + meta_html
        + "</section>"
    )


def _gate_rows(gate):
    if not gate:
        return ""
    items = []
    for k, v in gate.items():
        items.append(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>")
    return "<div class=\"gate\"><strong>7-Question Gate</strong><dl>" + "".join(items) + "</dl></div>"


def _submission_rows(sub_ids):
    if not sub_ids:
        return ""
    items = []
    for k, v in sub_ids.items():
        items.append(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>")
    return "<div class=\"refs\"><strong>Submissions</strong><dl>" + "".join(items) + "</dl></div>"


def _finding_section(f):
    sev_value = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
    color = _SEVERITY_COLORS.get(sev_value, "#5d6d7e")
    refs_html = ""
    if f.references:
        items = "".join(f"<li>{_esc(r)}</li>" for r in f.references)
        refs_html = f"<div class=\"refs\"><strong>References</strong><ul>{items}</ul></div>"
    steps_html = ""
    if f.reproduction_steps:
        items = "".join(f"<li>{_esc(s)}</li>" for s in f.reproduction_steps)
        steps_html = f"<div class=\"steps\"><strong>Reproduction</strong><ol>{items}</ol></div>"
    evidence_html = ""
    if f.evidence:
        evidence_html = (
            "<div class=\"evidence\"><strong>Evidence</strong>"
            f"<pre class=\"evidence-block\">{_esc(f.evidence)}</pre></div>"
        )
    cvss = f.cvss_score if f.cvss_score is not None else "N/A"
    cwe = f.cwe or "N/A"
    conf = f.confidence if f.confidence is not None else 0.0
    body = (
        f'<div class="body">'
        f'<dl>'
        f'<dt>ID</dt><dd>{_esc(f.id)}</dd>'
        f'<dt>Target</dt><dd>{_esc(f.target)}</dd>'
        f'<dt>Severity</dt><dd><span class="sev" style="background:{color}">{_esc(sev_value.upper())}</span></dd>'
        f'<dt>Confidence</dt><dd>{_esc(round(float(conf), 3))}</dd>'
        f'<dt>CVSS</dt><dd>{_esc(cvss)}</dd>'
        f'<dt>CWE</dt><dd>{_esc(cwe)}</dd>'
        f'</dl>'
        f'<p>{_esc(f.description or "")}</p>'
        f'{evidence_html}'
        f'{steps_html}'
        f'{refs_html}'
        f'{_gate_rows(f.gate_result)}'
        f'{_submission_rows(f.submission_ids)}'
        f'</div>'
    )
    return (
        '<section class="finding">'
        f'<header><h3>{_esc(f.title or "N/A")}</h3>'
        f'<span class="sev" style="background:{color}">{_esc(sev_value.upper())}</span>'
        f'</header>'
        f'{body}'
        f'</section>'
    )


def render(findings, *, title="BugWolf Report", metadata=None):
    normalized = _normalize(findings)
    stats = _stats(normalized)
    if normalized:
        sections = "".join(_finding_section(f) for f in normalized)
    else:
        sections = '<div class="empty">No findings to display.</div>'
    summary = _summary_section(stats, metadata)
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return _PAGE_TEMPLATE.safe_substitute(
        title=_esc(title),
        generated_at=_esc(generated_at),
        count=stats["total"],
        summary_section=summary,
        findings_section=sections,
        footer_text=f"Schema: {SCHEMA} &middot; BugWolf internal",
    )


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

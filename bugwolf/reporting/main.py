# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-main-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-main-v1"

import os
from typing import Any, List, Optional

from . import json_reporter, sarif_reporter, html_reporter, markdown_reporter
from . import hackerone as h1_mod
from . import bugcrowd as bc_mod
from . import intigriti as intigriti_mod
from . import immunefi as immunefi_mod
from .types import ReportFormat, Finding


def _coerce_list(findings):
    if findings is None:
        return []
    if isinstance(findings, Finding):
        return [findings]
    return list(findings)


def generate_report(findings, fmt: ReportFormat, *, output_path: Optional[str] = None, **kwargs) -> str:
    fmt_value = fmt.value if isinstance(fmt, ReportFormat) else str(fmt)
    norm = _coerce_list(findings)
    text = ""
    if fmt_value == "json":
        text = json_reporter.render(norm, **{k: v for k, v in kwargs.items() if k in ("metadata",)})
    elif fmt_value == "sarif":
        text = sarif_reporter.render(
            norm,
            **{k: v for k, v in kwargs.items() if k in ("tool_name", "tool_version", "run_index")},
        )
    elif fmt_value == "html":
        text = html_reporter.render(
            norm,
            **{k: v for k, v in kwargs.items() if k in ("title", "metadata")},
        )
    elif fmt_value in ("md", "markdown"):
        text = markdown_reporter.render(
            norm,
            **{k: v for k, v in kwargs.items() if k in ("title", "metadata")},
        )
    elif fmt_value == "hackerone":
        if len(norm) != 1:
            text = h1_mod.render_batch(norm)
        else:
            text = h1_mod.render(norm[0])
    elif fmt_value == "bugcrowd":
        if len(norm) != 1:
            text = bc_mod.render_batch(norm)
        else:
            text = bc_mod.render(norm[0])
    elif fmt_value == "intigriti":
        if len(norm) != 1:
            text = intigriti_mod.render_batch(norm)
        else:
            text = intigriti_mod.render(norm[0])
    elif fmt_value == "immunefi":
        if len(norm) != 1:
            text = immunefi_mod.render_batch(norm)
        else:
            text = immunefi_mod.render(norm[0])
    else:
        raise ValueError(f"Unknown report format: {fmt_value}")
    if output_path:
        try:
            out_dir = os.path.dirname(output_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fp:
                fp.write(text)
        except Exception:
            pass
    return text


def batch_export(findings, output_dir: str, *, formats: Optional[List[ReportFormat]] = None) -> dict:
    if formats is None:
        formats = [
            ReportFormat.JSON,
            ReportFormat.SARIF,
            ReportFormat.HTML,
            ReportFormat.MARKDOWN,
        ]
    if not output_dir:
        output_dir = "."
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception:
        pass
    result = {}
    norm = _coerce_list(findings)
    for fmt in formats:
        ext_map = {
            ReportFormat.JSON: "json",
            ReportFormat.SARIF: "sarif.json",
            ReportFormat.HTML: "html",
            ReportFormat.MARKDOWN: "md",
        }
        ext = ext_map.get(fmt, "txt")
        path = os.path.join(output_dir, f"bugwolf-report.{ext}")
        try:
            text = generate_report(norm, fmt, output_path=path)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as fp:
                    fp.write(text)
            result[fmt.value if isinstance(fmt, ReportFormat) else str(fmt)] = path
        except Exception:
            result[fmt.value if isinstance(fmt, ReportFormat) else str(fmt)] = None
    return result

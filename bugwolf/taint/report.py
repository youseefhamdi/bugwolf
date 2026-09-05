"""Taint report — renders :class:`TaintFlow` lists to markdown.

The output is plain Markdown (CommonMark-compatible) suitable for direct
embedding into GitHub-flavored reports.  No external deps; uses ``str``
formatting only.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint report writer (Phase 3.2)
## License: bugwolf-MIT

from __future__ import annotations

from typing import Iterable, List

from bugwolf.taint import TaintFlow
from bugwolf.taint.vulnerability_detector import (
    VulnerabilityDetector,
    VulnerabilityReport,
)


SCHEMA = "bugwolf-taint-v1"


class TaintReport:
    """Markdown report writer for taint flows."""

    def __init__(self, title: str = "Taint Flow Report") -> None:
        self.title = str(title)

    def render_markdown(self, flows: List[TaintFlow]) -> str:
        """Return a Markdown string for ``flows``."""

        lines: List[str] = []
        lines.append(f"# {self.title}")
        lines.append("")
        lines.append(f"_Schema: `{SCHEMA}`_")
        lines.append("")
        lines.append(self._summary_section(flows))
        lines.append(self._vuln_section(flows))
        lines.append(self._flow_table(flows))
        return "\n".join(lines)

    def _summary_section(self, flows: List[TaintFlow]) -> str:
        vulnerable = sum(1 for f in flows if f.is_vulnerable)
        out = ["## Summary", ""]
        out.append(f"- total flows: **{len(flows)}**")
        out.append(f"- vulnerable flows: **{vulnerable}**")
        files = sorted({f.file for f in flows})
        out.append(f"- distinct files: **{len(files)}**")
        out.append("")
        return "\n".join(out)

    def _vuln_section(self, flows: List[TaintFlow]) -> str:
        reports: List[VulnerabilityReport] = VulnerabilityDetector().detect(flows)
        out = ["## Vulnerability Breakdown", ""]
        if not reports:
            out.append("_No vulnerable flows detected._")
            out.append("")
            return "\n".join(out)
        out.append("| Class | Severity | Confidence | Flow Count | Files |")
        out.append("|---|---|---|---|---|")
        for report in reports:
            out.append(
                f"| {report.vuln_class} | {report.severity} | "
                f"{report.confidence:.2f} | {report.flow_count} | "
                f"{len(report.files)} |"
            )
        out.append("")
        return "\n".join(out)

    def _flow_table(self, flows: Iterable[TaintFlow]) -> str:
        out = ["## Flow Details", ""]
        out.append("| File | Line | Source | Sink | Confidence | Vulnerable |")
        out.append("|---|---|---|---|---|---|")
        for flow in flows:
            file_cell = flow.file
            if len(file_cell) > 60:
                file_cell = "…" + file_cell[-59:]
            out.append(
                f"| `{file_cell}` | {flow.line} | "
                f"{flow.source.value} | {flow.sink.value} | "
                f"{flow.confidence:.2f} | "
                f"{'yes' if flow.is_vulnerable else 'no'} |"
            )
        out.append("")
        return "\n".join(out)


__all__ = ["TaintReport", "render_inline"]


def render_inline(flows: List[TaintFlow], title: str = "Taint Flow Report") -> str:
    """Module-level convenience wrapper around :class:`TaintReport`."""

    return TaintReport(title=title).render_markdown(flows)


def render_summary(flows: List[TaintFlow]) -> str:
    """Render just the summary section."""

    return TaintReport()._summary_section(flows)


def render_breakdown(flows: List[TaintFlow]) -> str:
    """Render just the vulnerability breakdown."""

    return TaintReport()._vuln_section(flows)


def render_table(flows: List[TaintFlow]) -> str:
    """Render just the flow details table."""

    return TaintReport()._flow_table(flows)


__all__.extend(["render_summary", "render_breakdown", "render_table"])

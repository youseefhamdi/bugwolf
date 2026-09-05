#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter yaml_workflow.py:1-960 (1.5.o)
## Source: BugWolf runtime/playbooks (in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

YAML workflow DSL + assembleCommand + SARIF import.

BugWolf's YAML workflows describe a sequence of steps; each step is a
tool invocation with typed parameters.  This module is stdlib-only
(no PyYAML): it uses a minimal parser for the subset of YAML we emit,
plus a SARIF 2.1.0 importer that pulls ``results[].message.text`` and
``results[].properties.securitySeverity`` into the bugwolf Finding
shape.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "bugwolf-yaml-workflow/v1"


# ---------------------------------------------------------------------------
# Step + workflow dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WorkflowStep:
    """One workflow step (tool invocation)."""

    name: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    depends_on: Tuple[str, ...] = field(default_factory=tuple)
    on_failure: str = "abort"  # abort | continue | quarantine

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "tool": self.tool,
            "args": dict(self.args),
            "depends_on": list(self.depends_on),
            "on_failure": self.on_failure,
        }


@dataclass(frozen=True)
class Workflow:
    """A complete workflow (ordered list of steps)."""

    name: str
    target: str
    steps: Tuple[WorkflowStep, ...]
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "target": self.target,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
        }


# ---------------------------------------------------------------------------
# Tiny YAML subset parser (the workflow DSL is constrained)
# ---------------------------------------------------------------------------

def _parse_simple_yaml(text: str) -> Any:
    """Parse a constrained YAML subset.

    Supports:
      * ``key: value`` mappings (1 level deep)
      * ``- item`` lists at the top level
      * strings, ints, floats, bools, inline lists ``[a, b, c]``
      * ``#`` comments
      * 2-space indentation for nested mappings

    Raises :class:`ValueError` on unsupported constructs.
    """
    lines = []
    for raw in text.splitlines():
        stripped = raw.split("#", 1)[0]
        if not stripped.strip():
            continue
        lines.append(stripped)
    if not lines:
        return None

    # Decide if top-level is a list or a mapping.
    first = lines[0].lstrip()
    if first.startswith("- "):
        return _parse_top_list(lines)
    return _parse_top_mapping(lines)


def _parse_top_mapping(lines: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if line.startswith(("  ", "\t", "    ")):
            i += 1
            continue
        if ":" not in stripped:
            raise ValueError(f"expected key:value at line {i+1}: {stripped!r}")
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if value == "":
            # Nested content — determine whether it is a list-of-dicts,
            # a flat list, or a flat mapping.
            j = i + 1
            child_lines: List[str] = []
            while j < len(lines):
                child = lines[j]
                if not child.strip() or child.lstrip().startswith("#"):
                    j += 1
                    continue
                if not child.startswith(("  ", "\t", "    ")):
                    break
                child_lines.append(child)
                j += 1
            out[key] = _parse_block(child_lines)
            i = j
        else:
            out[key] = _coerce(value)
            i += 1
    return out


def _parse_block(child_lines: List[str]) -> Any:
    """Parse a list of indented lines as either a list of dicts, a
    flat list, or a flat mapping.
    """
    if not child_lines:
        return {}
    first = child_lines[0].lstrip()
    if first.startswith("- "):
        return _parse_list_of_dicts(child_lines)
    return _parse_inline_mapping(child_lines)


def _parse_list_of_dicts(child_lines: List[str]) -> List[Any]:
    """Parse ``[ "- k: v", "  k2: v2", "- k3: v3", "  k4: v4", ...]``
    into a list of dicts (one per ``-`` marker).
    """
    out: List[Any] = []
    current: Optional[Dict[str, Any]] = None
    for line in child_lines:
        sub = line.lstrip()
        if sub.startswith("- "):
            # Start a new item.
            rest = sub[2:].strip()
            current = {}
            out.append(current)
            if ":" in rest:
                k, _, v = rest.partition(":")
                current[k.strip()] = _coerce(v.strip())
        elif ":" in sub and current is not None:
            k, _, v = sub.partition(":")
            current[k.strip()] = _coerce(v.strip())
        elif sub.startswith("-") and current is not None:
            current = None
    return out


def _parse_inline_mapping(child_lines: List[str]) -> Dict[str, Any]:
    """Parse ``[ "k: v", "k2: v2", ...]`` into a flat dict."""
    out: Dict[str, Any] = {}
    for line in child_lines:
        sub = line.strip()
        if sub.startswith("- "):
            continue
        if ":" in sub:
            k, _, v = sub.partition(":")
            out[k.strip()] = _coerce(v.strip())
    return out


def _parse_top_list(lines: List[str]) -> List[Any]:
    out: List[Any] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("- "):
            item_text = stripped[2:]
            if ":" in item_text:
                key, _, value = item_text.partition(":")
                item: Dict[str, Any] = {key.strip(): _coerce(value.strip())}
                j = i + 1
                while j < len(lines):
                    child = lines[j]
                    if not child.startswith(("  ", "\t", "    ", "      ")):
                        break
                    sub = child.strip()
                    if sub.startswith("- "):
                        break
                    if ":" in sub:
                        k2, _, v2 = sub.partition(":")
                        item[k2.strip()] = _coerce(v2.strip())
                    j += 1
                out.append(item)
                i = j
            else:
                out.append(_coerce(item_text))
                i += 1
        else:
            i += 1
    return out


def _coerce(raw: str) -> Any:
    if raw == "" or raw is None:
        return ""
    s = raw.strip()
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_coerce(part.strip()) for part in inner.split(",")]
    if s.lower() in ("true", "yes", "on"):
        return True
    if s.lower() in ("false", "no", "off"):
        return False
    if s.lower() in ("null", "~"):
        return None
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


# ---------------------------------------------------------------------------
# assembleCommand — translate a workflow step into argv
# ---------------------------------------------------------------------------

def assemble_command(workflow_step: Mapping[str, Any],
                     target: str) -> List[str]:
    """Translate ``workflow_step`` into an argv list for the orchestrator.

    The step is expected to have ``tool`` and ``args`` keys.  The
    function NEVER shell-string-concatenates; it returns an argv list
    safe to pass to :func:`safe_subprocess.spawn_argv`.
    """
    tool = str(workflow_step.get("tool") or "")
    args = workflow_step.get("args") or {}
    if not isinstance(args, Mapping):
        args = {}
    argv: List[str] = [tool, "--target", str(target)]
    for key, val in args.items():
        k = str(key)
        if isinstance(val, bool):
            if val:
                argv.append(f"--{k.replace('_', '-')}")
        elif isinstance(val, (list, tuple)):
            for item in val:
                argv.extend([f"--{k.replace('_', '-')}", str(item)])
        elif isinstance(val, Mapping):
            # Flatten one level: --key.subkey value
            for sk, sv in val.items():
                argv.extend([f"--{k.replace('_', '-')}.{sk}", str(sv)])
        else:
            argv.extend([f"--{k.replace('_', '-')}", str(val)])
    return argv


# ---------------------------------------------------------------------------
# WorkflowDSL — top-level facade
# ---------------------------------------------------------------------------

class WorkflowDSL:
    """The YAML workflow DSL entry point.

    Public API:
      * :meth:`load`            — parse a workflow YAML file
      * :meth:`dump`            — serialise a workflow back to YAML
      * :meth:`compile_step`    — produce argv for a single step
    """

    SCHEMA = SCHEMA

    def load(self, path: Path) -> Workflow:
        """Load and parse a workflow YAML file."""
        text = Path(path).read_text(encoding="utf-8")
        obj = _parse_simple_yaml(text) or {}
        if not isinstance(obj, Mapping):
            raise ValueError("workflow root must be a mapping")
        name = str(obj.get("name") or path.stem)
        target = str(obj.get("target") or "")
        description = str(obj.get("description") or "")
        steps_raw = obj.get("steps") or []
        if not isinstance(steps_raw, list):
            raise ValueError("workflow.steps must be a list")
        steps: List[WorkflowStep] = []
        for row in steps_raw:
            if not isinstance(row, Mapping):
                continue
            steps.append(WorkflowStep(
                name=str(row.get("name") or ""),
                tool=str(row.get("tool") or ""),
                args=dict(row.get("args") or {}),
                depends_on=tuple(row.get("depends_on") or ()),
                on_failure=str(row.get("on_failure") or "abort"),
            ))
        return Workflow(name=name, target=target, description=description,
                        steps=tuple(steps))

    def dump(self, workflow: Workflow) -> str:
        """Serialise ``workflow`` back to the constrained YAML subset."""
        lines: List[str] = []
        lines.append(f"name: {workflow.name}")
        lines.append(f"target: {workflow.target}")
        if workflow.description:
            lines.append(f"description: {workflow.description}")
        lines.append("steps:")
        for step in workflow.steps:
            lines.append(f"  - name: {step.name}")
            lines.append(f"    tool: {step.tool}")
            if step.depends_on:
                lines.append(
                    f"    depends_on: [{', '.join(step.depends_on)}]")
            lines.append(f"    on_failure: {step.on_failure}")
            if step.args:
                lines.append("    args:")
                for k, v in step.args.items():
                    lines.append(f"      {k}: {_yaml_value(v)}")
        return "\n".join(lines) + "\n"

    def compile_step(self, step: WorkflowStep, target: str) -> List[str]:
        return assemble_command(step.to_dict(), target)


def _yaml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_yaml_value(x) for x in v) + "]"
    if isinstance(v, Mapping):
        return "{" + ", ".join(f"{k}: {_yaml_value(val)}"
                               for k, val in v.items()) + "}"
    return str(v)


# ---------------------------------------------------------------------------
# SARIF import
# ---------------------------------------------------------------------------

_SARIF_TO_BUGWOLF_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def import_sarif(sarif_path: Path) -> List[Dict[str, Any]]:
    """Import a SARIF 2.1.0 file and return bugwolf Finding dicts.

    SARIF support is intentionally narrow:
      * reads ``runs[].results[]`` only
      * maps ``level`` -> severity
      * uses ``message.text`` as evidence
      * uses ``locations[].physicalLocation.artifactLocation.uri`` as endpoint
      * uses ``ruleId`` as bug_class (or rule.id)
    """
    text = Path(sarif_path).read_text(encoding="utf-8")
    doc = json.loads(text)
    findings: List[Dict[str, Any]] = []
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return findings
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        for idx, result in enumerate(run.get("results") or []):
            if not isinstance(result, Mapping):
                continue
            level = str(result.get("level") or "warning").lower()
            severity = _SARIF_TO_BUGWOLF_SEVERITY.get(level, "medium")
            msg = (result.get("message") or {}).get("text") or ""
            locs = result.get("locations") or []
            endpoint = ""
            if locs and isinstance(locs[0], Mapping):
                phys = locs[0].get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                endpoint = str(art.get("uri") or "")
            rule_id = str(result.get("ruleId") or result.get("rule") or "unknown")
            findings.append({
                "schema": SCHEMA,
                "id": f"sarif:{rule_id}:{idx}",
                "bug_class": rule_id,
                "severity": severity,
                "endpoint": endpoint,
                "method": "GET",
                "evidence": str(msg)[:1024],
                "reproducer": "",
                "confidence": "tentative",
            })
    return findings


__all__ = [
    "SCHEMA", "WorkflowStep", "Workflow", "WorkflowDSL",
    "assemble_command", "import_sarif",
]
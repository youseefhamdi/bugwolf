#!/usr/bin/env python3
"""BugWolf Agentic Tool-Auth Analyzer — tool-call sites x attacker-influenced args.

Given an agent code/config inventory, maps every tool call to the arguments
that an attacker can influence, producing "tool X with attacker-controlled
argument Y" plans (OWASP ASI02 tool misuse) and identity/privilege-abuse plans
(ASI03) when the tool runs with a privileged identity.

Argument sources are classified:

  * **user_input**   — directly from the user's message        (attacker)
  * **web_content**  — fetched from a URL the user/attacker controls (attacker)
  * **file_content** — read from a file (uploaded or web-downloaded)   (attacker)
  * **tool_result**  — output of another tool (chained influence)      (attacker)
  * **llm_derived**  — synthesized by the model (jailbreakable)         (attacker)
  * **constant/env** — hard-coded or environment                      (trusted)

Input may be a structured inventory or source code (call sites are extracted
with a deterministic regex).  Output lands at
``research/<target>/llm/agentic-tool-auth-plans.json`` (a ``research``
artifact) and emits ``LLM_CANDIDATE`` for high-severity plans.

Offline and deterministic; uncensored; no model is called.

Usage:
  python3 tools/domains/llm/agentic_tool_auth.py --target acme --inventory tools.json
  python3 tools/domains/llm/agentic_tool_auth.py --target acme --path src/ --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current


_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn

SCHEMA = "bugwolf/agentic-tool-auth/v1"

# Attacker-influenced argument sources.
ATTACKER_SOURCES = ("user_input", "web_content", "file_content",
                    "tool_result", "llm_derived")

# Tools whose misuse has high impact when given attacker input.
SENSITIVE_TOOLS = (
    "shell", "exec", "run_command", "bash", "subprocess", "terminal",
    "write_file", "save_file", "upload", "http", "request", "fetch_url",
    "get_url", "browser", "click", "navigate", "send_email", "mail",
    "execute_sql", "query", "run_query", "db_query", "payment", "charge",
    "transfer", "refund", "admin", "delete", "remove", "update_record",
    "create_user", "grant", "revoke", "deploy", "publish", "invoke_lambda",
    "api_call", "call_api",
)


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _tool_sensitive(tool: str) -> bool:
    low = tool.lower()
    return any(marker in low for marker in SENSITIVE_TOOLS)


@dataclass
class ToolCallSite:
    tool: str
    args: Dict[str, str]          # arg name -> source
    identity: str = ""
    description: str = ""
    file: str = ""
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolAuthPlan:
    plan_id: str
    tool: str
    category: str                  # tool_misuse | identity_abuse | chained_influence
    owasp_asi: str                 # ASI02 | ASI03
    attacker_args: List[str]
    identity: str
    severity: str
    rationale: str
    validation_steps: List[str] = field(default_factory=list)
    file: str = ""
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolAuthAnalysis:
    target: str
    generated_at: str
    call_sites: List[ToolCallSite] = field(default_factory=list)
    plans: List[ToolAuthPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "call_site_count": len(self.call_sites),
            "call_sites": [c.to_dict() for c in self.call_sites],
            "plans": [p.to_dict() for p in self.plans],
        }


_CALL_RE = re.compile(
    r"(?P<tool>[a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*(?P<body>[^()]{0,400})\)")


def _scan_call_sites(code: str, *, file: str = "") -> List[ToolCallSite]:
    """Extract call sites from source code (deterministic regex scan)."""
    sites: List[ToolCallSite] = []
    for match in _CALL_RE.finditer(code):
        tool = match.group("tool")
        body = match.group("body")
        line = code[:match.start()].count("\n") + 1
        # Keyword args: name=value
        args: Dict[str, str] = {}
        for kw in re.finditer(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=", body):
            args[kw.group(1)] = "unknown_source"
        if not args and body.strip():
            args["<positional>"] = "unknown_source"
        if tool.startswith("def ") or not args:
            continue
        sites.append(ToolCallSite(
            tool=tool, args=args, file=file, line=line))
    return sites


def analyze(target: str, *, inventory: Optional[List[Dict[str, Any]]] = None,
            code: Optional[str] = None, file_name: str = "") -> ToolAuthAnalysis:
    """Deterministically map attacker-influenced args per tool call."""
    analysis = ToolAuthAnalysis(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    sites: List[ToolCallSite] = []
    if inventory:
        for entry in inventory:
            if not isinstance(entry, dict):
                continue
            raw_args = entry.get("args")
            args: Dict[str, str] = {}
            if isinstance(raw_args, dict):
                for name, source in raw_args.items():
                    args[str(name)] = str(source).lower()
            elif isinstance(raw_args, list):
                for name in raw_args:
                    args[str(name)] = "unknown_source"
            sites.append(ToolCallSite(
                tool=str(entry.get("tool") or ""),
                args=args,
                identity=str(entry.get("identity") or ""),
                description=str(entry.get("description") or ""),
                file=str(entry.get("file") or ""),
                line=int(entry.get("line") or 0),
            ))
    if code:
        sites.extend(_scan_call_sites(code, file=file_name))
    analysis.call_sites = sites

    for site in sites:
        attacker_args = [name for name, source in site.args.items()
                         if source in ATTACKER_SOURCES]
        if not attacker_args:
            continue
        sensitive = _tool_sensitive(site.tool)
        # ASI02 tool misuse.
        if sensitive:
            analysis.plans.append(ToolAuthPlan(
                plan_id=_id("plan", "asi02", site.tool,
                            ",".join(sorted(attacker_args))),
                tool=site.tool,
                category="tool_misuse",
                owasp_asi="ASI02",
                attacker_args=sorted(attacker_args),
                identity=site.identity,
                severity="high" if site.identity else "medium",
                rationale=(
                    f"Tool '{site.tool}' accepts attacker-influenced "
                    f"argument(s): {', '.join(sorted(attacker_args))}. "
                    f"Sensitive tool + untrusted input = arbitrary action "
                    f"with the agent's authority (tool misuse)."),
                validation_steps=[
                    "Trace each attacker-controlled argument to its source "
                    "(user message, fetched page, prior tool result).",
                    "Confirm the tool performs the action with no allowlist "
                    "or sanitization on that argument.",
                    "Draft the minimal prompt/page that would set the "
                    "argument to a hostile value.",
                ],
                file=site.file, line=site.line,
            ))
        else:
            analysis.plans.append(ToolAuthPlan(
                plan_id=_id("plan", "asi02-low", site.tool,
                            ",".join(sorted(attacker_args))),
                tool=site.tool,
                category="tool_misuse",
                owasp_asi="ASI02",
                attacker_args=sorted(attacker_args),
                identity=site.identity,
                severity="low",
                rationale=(
                    f"Tool '{site.tool}' receives attacker-influenced "
                    f"argument(s): {', '.join(sorted(attacker_args))}. Low "
                    f"direct impact but may chain into privileged tools."),
                validation_steps=[
                    "Check whether this tool's output feeds a more "
                    "privileged tool (chained influence).",
                ],
                file=site.file, line=site.line,
            ))
        # ASI03 identity/privilege abuse: the tool runs with an agent
        # identity while accepting attacker input.  Severity is high only
        # for explicitly privileged identities.
        privileged_identity = site.identity.lower() in ("admin", "root",
                                                        "owner", "service")
        if site.identity and (sensitive or privileged_identity):
            analysis.plans.append(ToolAuthPlan(
                plan_id=_id("plan", "asi03", site.tool, site.identity,
                            ",".join(sorted(attacker_args))),
                tool=site.tool,
                category="identity_abuse",
                owasp_asi="ASI03",
                attacker_args=sorted(attacker_args),
                identity=site.identity,
                severity="high" if privileged_identity else "medium",
                rationale=(
                    f"Tool '{site.tool}' runs as '{site.identity}' while "
                    f"accepting attacker-influenced argument(s): "
                    f"{', '.join(sorted(attacker_args))} — the agent's "
                    f"identity amplifies the untrusted input."
                    + (" The identity is privileged, so the amplification is "
                       "direct privilege abuse." if privileged_identity
                       else " The identity is non-privileged; the abuse is "
                              "amplification of whatever authority the "
                              "identity holds.")),
                validation_steps=[
                    "Confirm the identity's actual permissions for the "
                    "tool's action.",
                    "Determine whether the attacker argument can name "
                    "resources outside the intended scope.",
                ],
                file=site.file, line=site.line,
            ))

    # Deduplicate identical plans (stable, deterministic).
    seen: Set[str] = set()
    deduped: List[ToolAuthPlan] = []
    for plan in analysis.plans:
        key = (plan.category, plan.tool, plan.identity,
               ",".join(plan.attacker_args))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(plan)
    analysis.plans = deduped
    return analysis


def write_analysis(analysis: ToolAuthAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/llm/agentic-tool-auth-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(analysis.target)
    out_dir = root / "research" / target_dir / "llm"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "agentic-tool-auth-plans.json"
    out.write_text(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Agentic tool-auth analyzer")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--inventory", default=None,
                        help="path to tool-call inventory JSON")
    parser.add_argument("--path", default=None, help="path to source dir or file")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    inventory = None
    if args.inventory:
        try:
            raw = json.loads(Path(args.inventory).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"error": f"cannot read inventory: {exc}"}))
            return 2
        inventory = raw.get("call_sites") if isinstance(raw, dict) else raw
        if not isinstance(inventory, list):
            inventory = [raw]

    code = None
    file_name = ""
    if args.path:
        path = Path(args.path)
        if path.is_dir():
            chunks: List[str] = []
            for p in sorted(path.rglob("*")):
                if p.suffix.lower() in (".py", ".js", ".ts", ".tsx", ".mjs"):
                    try:
                        chunks.append(p.read_text(errors="replace"))
                    except OSError:
                        continue
            code = "\n".join(chunks)
            file_name = str(path)
        else:
            try:
                code = path.read_text(errors="replace")
                file_name = str(path)
            except OSError as exc:
                print(json.dumps({"error": f"cannot read path: {exc}"}))
                return 2

    if not inventory and not code:
        print(json.dumps({"error": "supply --inventory or --path"}))
        return 2

    analysis = analyze(args.target, inventory=inventory, code=code,
                       file_name=file_name)
    out = write_analysis(analysis, project_root=args.project_root,
                         base_dir=args.base_dir)

    high = [p for p in analysis.plans if p.severity == "high"]
    for plan in high:
        publish_or_warn(args.target, "LLM_CANDIDATE",
                        source="agentic_tool_auth",
                        payload={"tool": plan.tool,
                                 "category": plan.category,
                                 "owasp_asi": plan.owasp_asi,
                                 "attacker_args": plan.attacker_args},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(analysis.plans)} tool-auth plans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

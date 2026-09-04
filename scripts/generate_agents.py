#!/usr/bin/env python3
"""Generate harness-consumable agent definitions from the agent registry.

Single source of truth: tools/core/agent_registry.py.  This script projects
each AgentSpec into ``agents/bugwolf/<role>.md`` with the Claude Code /
Freebuff subagent front-matter:

    ---
    name: bugwolf:<role>
    description: <title> -- <description>
    model: inherit            (sonnet | opus | haiku | inherit -- native Task field)
    tools: <comma-joined Claude Code tool names>   (Task-tool allowlist)
    x-bugwolf-tier: <tier_affinity> (preference: <model_preference>)  -- consumed by
                      tools/core/model_router.py; NOT a Claude Code field
    scope: operator-declared (deny-by-default, runtime/scope.py)
    sandbox: required (runtime/sandbox.py)
    ---

followed by the specialized playbook body loaded (and digest-verified) from
references/hacking-agents/ (or the workflow reference doc for workflow
agents).

Regeneration is deterministic: identical registry state produces byte-
identical files.  CI runs ``--check`` so a registry edit without a
regeneration fails the build.

Usage:
    python3 scripts/generate_agents.py            # (re)generate
    python3 scripts/generate_agents.py --check    # exit 1 if drift
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.agent_registry import AgentRegistry, AgentRegistryError  # noqa: E402

OUT_DIR = ROOT / "agents" / "bugwolf"

# ---------------------------------------------------------------------------
# Claude Code front-matter mapping (master plan Phase 4.1/4.2)
#
# ``model-tier`` is not a Claude Code subagent field (the native field is
# ``model: sonnet|opus|haiku|inherit``), so the tier preference was silently
# ignored on native Task dispatch.  Two fixes:
#   1. emit the real ``model:`` field, mapped from tier affinity;
#   2. move the tier into ``x-bugwolf-tier:`` (non-reserved key) so
#      ``tools/core/model_router.py`` keeps its vocabulary and the CLI-spawn
#      pinning in tools/runtime/team.py keeps working unchanged.
#
# ``tools:`` previously listed BugWolf *module* names ("hunt",
# "runtime.mission_runner"), which Claude Code does not resolve.  The Task
# tool parses ``tools:`` as an allowlist of Claude Code tool names; emit
# real names instead, derived per-lane (4.2).  The BugWolf module list stays
# in the body preamble (``Tool modules:``) so nothing is lost.

# tier affinity -> native model field
TIER_TO_MODEL = {
    "deterministic": "haiku",
    "local_slm": "sonnet",
    "frontier": "opus",
}

# Claude Code tool names by team lane.  Read-only lanes (verify/report) get
# no Bash -- lane discipline is enforced mechanically, not by prompt.
LANE_TOOLS = {
    "recon": ("Read", "Grep", "Glob", "WebFetch", "WebSearch", "Task"),
    "hunt": ("Read", "Grep", "Glob", "WebFetch", "WebSearch", "Bash", "Task"),
    "verify": ("Read", "Grep", "Glob", "WebFetch", "Task"),
    "report": ("Read", "Grep", "Glob", "Write"),
}

# Tool list for lanes that never dispatch subagents.
LANE_TOOLS_NO_TASK = {lane: tuple(t for t in tools if t != "Task")
                      for lane, tools in LANE_TOOLS.items()}

PROMPT_PREAMBLE = """You are {title}, a specialized BugWolf subagent dispatched as
`{harness_role}` inside a multi-agent security team.

Non-negotiable operating rules (apply to every dispatch):

1. **Scope** -- you operate ONLY inside the operator-declared scope
   (tools/runtime/scope.py, deny-by-default). A `scope-blocked:` sentinel is
   a hard stop, never a puzzle.
2. **Sandbox** -- every spawn goes through tools/runtime/sandbox.py. No
   direct subprocesses.
3. **Evidence** -- an "insight" without a lead ref is a contract violation
   (R1). Terminal states are PWNED / REFUTED / BUDGET-EXHAUSTED -- nothing
   else closes a lead.
4. **Honesty** -- never fabricate a result. If a capability is missing,
   return blocked evidence and move on.
5. **Handoff** -- return structured messages (`to_role`, `kind`, `body`)
   instead of prose handoffs; the team engine routes them.
"""


def render(registry: AgentRegistry, role: str) -> str:
    spec = registry.get(role)
    model = TIER_TO_MODEL.get(spec.tier_affinity, "inherit")
    # Merge lane allowlists across the agent's lanes; workflow agents
    # (recon/verify/report lanes) never dispatch subagents, so drop Task.
    lanes = spec.lanes or ()
    if spec.entry == "workflow":
        tool_names = LANE_TOOLS_NO_TASK.get(lanes[0], ()) if lanes else ()
    else:
        merged: list[str] = []
        for lane in lanes:
            for tool_name in LANE_TOOLS.get(lane, ()):
                if tool_name not in merged:
                    merged.append(tool_name)
        tool_names = tuple(merged)
    front = (
        "---\n"
        f"name: {spec.harness_role}\n"
        f"description: {spec.title} -- {spec.description}\n"
        f"model: {model}\n"
        f"tools: {', '.join(tool_names)}\n"
        f"x-bugwolf-tier: {spec.tier_affinity}"
        f" (preference via tools/core/model_router.py)\n"
        "scope: operator-declared (deny-by-default, tools/runtime/scope.py)\n"
        "sandbox: required (tools/runtime/sandbox.py)\n"
        f"playbook-digest: {registry.prompt_digest(role)}\n"
        "---\n\n"
    )
    body = registry.load_prompt(role)
    module_line = (
        f"Tool modules (BugWolf internals driven via Bash -- "
        f"always through tools/runtime/sandbox.py): {', '.join(spec.tools)}\n\n"
    )
    return front + PROMPT_PREAMBLE.format(
        title=spec.title, harness_role=spec.harness_role) + module_line + body + "\n"


def main() -> int:
    check = "--check" in sys.argv
    registry = AgentRegistry()
    drift: list[str] = []
    written = 0
    for role in registry.all_roles():
        path = OUT_DIR / f"{role}.md"
        content = render(registry, role)
        if check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                drift.append(str(path.relative_to(ROOT)))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written += 1
    if check:
        if drift:
            print("agent definitions drifted from the registry:")
            for d in drift:
                print(f"  {d}")
            print("run: python3 scripts/generate_agents.py")
            return 1
        print(f"OK {len(registry.all_roles())} agent definitions in sync")
        return 0
    print(f"wrote {written} agent definitions to {OUT_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AgentRegistryError as exc:
        print(f"registry error: {exc}", file=sys.stderr)
        raise SystemExit(2)

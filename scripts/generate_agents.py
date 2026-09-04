#!/usr/bin/env python3
"""Generate harness-consumable agent definitions from the agent registry.

Single source of truth: tools/core/agent_registry.py.  This script projects
each AgentSpec into ``agents/bugwolf/<role>.md`` with the Claude Code /
Freebuff subagent front-matter:

    ---
    name: bugwolf:<role>
    description: <title> -- <description>
    model-tier: <tier_affinity> (preference: <model_preference>)
    tools: <comma-joined tool modules>
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
    front = (
        "---\n"
        f"name: {spec.harness_role}\n"
        f"description: {spec.title} -- {spec.description}\n"
        f"model-tier: {spec.tier_affinity}\n"
        f"tools: {', '.join(spec.tools)}\n"
        "scope: operator-declared (deny-by-default, tools/runtime/scope.py)\n"
        "sandbox: required (tools/runtime/sandbox.py)\n"
        f"playbook-digest: {registry.prompt_digest(role)}\n"
        "---\n\n"
    )
    body = registry.load_prompt(role)
    return front + PROMPT_PREAMBLE.format(
        title=spec.title, harness_role=spec.harness_role) + "\n" + body + "\n"


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

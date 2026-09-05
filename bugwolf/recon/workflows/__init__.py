"""Recon workflow YAML library.

Each ``*.yaml`` file in this directory conforms to::

    schema: bugwolf-recon-workflow-v1
    name: <slug>
    description: <text>
    phases:
      - order: 1
        name: <phase_name>
        tools: [tool1, tool2]
        budget:
          max_requests: 50
          max_seconds: 600
        scope_verb: passive

Loaded by :func:`bugwolf.recon.orchestrator.discover_workflows` and
:func:`bugwolf.recon.orchestrator.load_workflow`.  No third-party deps.
"""

from __future__ import annotations

__all__: list[str] = []
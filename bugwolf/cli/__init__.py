# bugwolf/cli — unified CLI
# SCHEMA: bugwolf-cli-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher) — all capabilities behind existing fail-closed gates

from __future__ import annotations

SCHEMA = "bugwolf-cli-v1"
__version__ = "0.5.0"
__all__ = ["main", "build_parser", "SUBCOMMANDS"]

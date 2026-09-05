# bugwolf/cli/dispatch — handler registry
# SCHEMA: bugwolf-cli-dispatch-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import importlib
from typing import Callable, Dict

SCHEMA = "bugwolf-cli-dispatch-v1"


def _load(name: str):
    return importlib.import_module(f"bugwolf.cli.commands.{name}")


SUBCOMMANDS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "discover": _load("discover").run,
    "scan": _load("scan").run,
    "fuzz": _load("fuzz").run,
    "taint": _load("taint").run,
    "chain": _load("chain").run,
    "audit": _load("audit").run,
    "redteam": _load("redteam").run,
    "llm-redteam": _load("llm_redteam").run,
    "osint": _load("osint").run,
    "recon": _load("recon").run,
    "report": _load("report").run,
    "govern": _load("govern").run,
    "semantic": _load("semantic").run,
    "regression": _load("regression").run,
    "methodology": _load("methodology").run,
    "benchmark": _load("benchmark").run,
    "distributed": _load("distributed").run,
    "version": _load("version").run,
}


def dispatch(args: argparse.Namespace) -> int:
    """Route ``args`` to the registered handler and return its exit code."""
    handler = SUBCOMMANDS[args.subcommand]
    return handler(args)

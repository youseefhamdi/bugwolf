# bugwolf/cli/commands/version — version reporting
# SCHEMA: bugwolf-cli-version-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

SCHEMA = "bugwolf-cli-version-v1"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add subcommand-specific args (none)."""
    return


def run(args: argparse.Namespace) -> int:
    """Print the bugwolf CLI version. STUB-SAFE."""
    try:
        version = "0.5.0"
        try:
            import bugwolf as _bw
            version = getattr(_bw, "__version__", None) or version
        except Exception:  # noqa: BLE001
            pass
        payload: Dict[str, Any] = {"ok": True, "version": version,
                                   "schema": SCHEMA}
        if getattr(args, "json", False):
            print(json.dumps(payload, sort_keys=True))
        elif not getattr(args, "quiet", False):
            print(f"bugwolf {version}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

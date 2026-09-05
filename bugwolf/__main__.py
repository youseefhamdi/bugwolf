# bugwolf/__main__ — `python -m bugwolf` entry point
# SCHEMA: bugwolf-cli-entrypoint-v1
# ## Source: original work for Phase 5.1
# ## License: BugWolf internal
# ## Capability tier: C0 (CLI dispatcher)

from __future__ import annotations

import sys

from bugwolf.cli.main import main

SCHEMA = "bugwolf-cli-entrypoint-v1"


if __name__ == "__main__":
    sys.exit(main())

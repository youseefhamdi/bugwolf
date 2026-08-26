#!/usr/bin/env python3
"""Runtime path helpers shared by bundled BugWolf tools.

The source tree and an installed skill have different locations.  Runtime
artifacts belong to the project in which the tool is invoked, not beside the
skill code.  ``BUGWOLF_PROJECT_ROOT`` and an explicit argument take priority;
the current working directory is the safe default used by the documented CLI.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

CODE_ROOT = Path(__file__).resolve().parent.parent


def target_slug(value: str | Path, *, max_length: int = 200) -> str:
    """Return one safe, deterministic filesystem component for a target.

    Target identifiers may be URLs, host:port pairs, or operator labels, but
    they must never be interpreted as path syntax when used for runtime state.
    """
    raw = str(value or "").strip()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    slug = slug.strip(".")[:max_length]
    return slug or "default"


def workspace_root(explicit: Optional[str | Path] = None) -> Path:
    """Return the project workspace for runtime artifacts."""
    value = explicit or os.environ.get("BUGWOLF_PROJECT_ROOT") or os.getcwd()
    return Path(value).expanduser().resolve()


def runtime_path(*parts: str, root: Optional[str | Path] = None) -> Path:
    """Build a path under the invoking workspace."""
    return workspace_root(root).joinpath(*parts)

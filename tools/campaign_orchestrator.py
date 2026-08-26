#!/usr/bin/env python3
"""Compatibility shim: tools.campaign_orchestrator -> tools.core.campaign_orchestrator.

The APT Commander was moved into the modular ``tools/core/`` layout.  This
shim aliases the canonical module so the documented CLI and every existing
import work unchanged.
"""
import sys
from pathlib import Path

_CODE_ROOT = Path(__file__).resolve().parent.parent
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))

from tools.core import campaign_orchestrator as _impl  # noqa: E402

sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())

#!/usr/bin/env python3
"""Compatibility shim: tools.stage_controller -> tools.core.stage_controller.

The APT Commander was moved into the modular ``tools/core/`` layout.  This
shim aliases the canonical module so the documented CLI (``python3
tools/stage_controller.py``) and every existing ``from tools.stage_controller
import ...`` (including underscore-prefixed helpers) work unchanged.
"""
import sys
from pathlib import Path

_CODE_ROOT = Path(__file__).resolve().parent.parent
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))

from tools.core import stage_controller as _impl  # noqa: E402

sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())

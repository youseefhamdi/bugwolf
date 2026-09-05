"""Dynamic taint sub-package — runtime instrumentation primitives.

All classes in this sub-package are **stub-safe**: when a runtime hook
isn't available (e.g. we are running outside a process we can ptrace or
LD_PRELOAD), the public methods return the constant ``"unavailable"``
or ``[]`` rather than raising.

Schema: ``bugwolf-taint-v1``
"""

## Source: dynamic taint package (Phase 3.2 — stub-safe)
## License: bugwolf-MIT

from __future__ import annotations

from bugwolf.taint.dynamic.instrument import DynamicTaintInstrument  # noqa: F401
from bugwolf.taint.dynamic.probe import DynamicTaintProbe  # noqa: F401
from bugwolf.taint.dynamic.shadow_memory import ShadowMemory  # noqa: F401


SCHEMA = "bugwolf-taint-v1"


UNAVAILABLE = "unavailable"


__all__ = ["DynamicTaintInstrument", "DynamicTaintProbe", "ShadowMemory", "UNAVAILABLE"]

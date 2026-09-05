"""Engines sub-package — language-specific taint engines.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint engines registry (Phase 3.2)
## License: bugwolf-MIT

from __future__ import annotations


SCHEMA = "bugwolf-taint-v1"


from bugwolf.taint.engines.python import PythonTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.javascript import JavaScriptTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.typescript import TypeScriptTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.go import GoTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.rust import RustTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.solidity import SolidityTaintEngine  # noqa: E402,F401
from bugwolf.taint.engines.java import JavaTaintEngine  # noqa: E402,F401


__all__ = [
    "PythonTaintEngine",
    "JavaScriptTaintEngine",
    "TypeScriptTaintEngine",
    "GoTaintEngine",
    "RustTaintEngine",
    "SolidityTaintEngine",
    "JavaTaintEngine",
]

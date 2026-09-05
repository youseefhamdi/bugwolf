"""BugWolf Phase 2.3 — Mobile security package.

Additive module providing APK / iOS red-team methodology, Frida
script snippets, and Objection / apktool wrappers.

The Frida ``.js`` scripts are documentation + code; they are not
executed by bugwolf directly.  They are loaded at runtime by the
Frida CLI (``frida -U -l bypass_ssl.js ...``).
"""

from __future__ import annotations

SCHEMA = "bugwolf-mobile-v1"

__all__ = ["SCHEMA"]
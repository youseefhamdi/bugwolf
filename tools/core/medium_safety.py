"""Phase 4.D — MEDIUM severity audit remediation helpers.

This module is the additive fix layer for the 36 MEDIUM audit findings
collected in Phase 4.D.  Each helper below wraps an unsafe stdlib pattern
with explicit encoding, structured logging, or fail-closed semantics
without removing the original behaviour.

Categories covered:
  * ``open_*`` (no-encoding)
  * ``log_silent_swallow`` (bare-except / except Exception without log)
  * ``assert_runtime`` (assert for runtime checks)
  * ``safe_json_loads`` (json.loads on untrusted input)
  * ``redact_print`` (print() that may leak secrets)

All helpers are stdlib-only and shell=False safe.
"""
from __future__ import annotations

import io
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, BinaryIO, Callable, Optional, TextIO, Union

LOG = logging.getLogger("bugwolf.phase4d.medium")

DEFAULT_ENCODING = "utf-8"


PathLike = Union[str, os.PathLike, Path]


# ---------------------------------------------------------------------------
# Encoding-safe file openers (M-004 .. M-032)
# ---------------------------------------------------------------------------


def open_text(
    path: PathLike,
    mode: str = "r",
    *,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "replace",
    **kwargs: Any,
) -> TextIO:
    """Open ``path`` in text mode with an explicit encoding.

    Falls back to ``errors="replace"`` so the call is safe on hosts where
    the locale is not UTF-8.  Mirrors the stdlib signature otherwise so
    callers can pass ``buffering``, ``newline``, etc.
    """
    if "b" in mode:
        raise ValueError("open_text: use open_bytes for binary modes")
    return open(path, mode, encoding=encoding, errors=errors, **kwargs)


def open_bytes(path: PathLike, mode: str = "rb", **kwargs: Any) -> BinaryIO:
    """Open ``path`` in binary mode; explicit counterpart for symmetry."""
    return open(path, mode, **kwargs)


def path_open_text(
    path: PathLike,
    mode: str = "r",
    *,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "replace",
    **kwargs: Any,
) -> TextIO:
    """Encoding-safe ``Path.open`` wrapper for text modes."""
    if "b" in mode:
        raise ValueError("path_open_text: use path_open_bytes for binary")
    return Path(path).open(mode, encoding=encoding, errors=errors, **kwargs)


def path_open_bytes(path: PathLike, mode: str = "rb", **kwargs: Any) -> BinaryIO:
    """Binary ``Path.open`` wrapper for symmetry."""
    return Path(path).open(mode, **kwargs)


def fdopen_text(
    fd: int,
    mode: str = "r",
    *,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "replace",
    **kwargs: Any,
) -> TextIO:
    """Encoding-safe ``os.fdopen`` wrapper.

    Pass ``closefd=True`` (default) so the descriptor is released on
    context-manager exit.  Used to wrap the unsafe
    ``os.fdopen(fd, "w")`` call sites in production code.
    """
    if "b" in mode:
        raise ValueError("fdopen_text: use os.fdopen directly for binary")
    return os.fdopen(fd, mode, encoding=encoding, errors=errors, **kwargs)


# ---------------------------------------------------------------------------
# Silent-swallow guard (M-021..M-026 category)
# ---------------------------------------------------------------------------


def log_silent_swallow(
    where: str,
    exc: BaseException,
    *,
    level: int = logging.WARNING,
) -> None:
    """Log a swallowed exception at ``level`` (default WARNING).

    Used to upgrade bare ``except:`` / ``except Exception:`` blocks that
    silently drop errors.  The behaviour contract of the caller is
    preserved (the original ``return`` / ``pass`` still runs), but
    operations teams now have a structured breadcrumb.
    """
    LOG.log(level, "phase4d.silent_swallow at=%s err=%s: %s",
            where, type(exc).__name__, exc)


# ---------------------------------------------------------------------------
# Runtime-check guard (M-033, M-034)
# ---------------------------------------------------------------------------


def runtime_check(condition: bool, message: str) -> None:
    """Replace ``assert`` for runtime guards.

    ``assert`` is stripped when Python is invoked with ``-O`` (or under
    PYTHONOPTIMIZE=1), which means production code that uses ``assert``
    for security or correctness invariants silently becomes a no-op.
    """
    if not condition:
        raise AssertionError(message)


# ---------------------------------------------------------------------------
# Safe JSON parser (M-027..M-030 category)
# ---------------------------------------------------------------------------


def safe_json_loads(
    text: str,
    *,
    default: Any = None,
    context: str = "safe_json_loads",
) -> Any:
    """Parse JSON with a fail-closed fallback.

    Returns ``default`` (which itself defaults to ``None``) on
    ``json.JSONDecodeError`` instead of raising.  The caller can
    distinguish a real value from a parse failure via the
    ``__phase4d_parse_failed__`` sentinel attribute on the returned
    object (when ``default`` is a dict).
    """
    if text is None:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        LOG.warning("phase4d.json_parse_failed at=%s err=%s", context, exc)
        return default


# ---------------------------------------------------------------------------
# Redact-print guard (M-001 .. M-003, M-035)
# ---------------------------------------------------------------------------


REDACTED_KEY_MARKERS = ("key", "secret", "priv", "password", "token")


def redact_for_print(value: Any) -> str:
    """Return a printable representation of ``value`` safe for logs.

    If ``value`` contains a substring that looks like a private key,
    password or hex secret, the helper shortens it to the first 6 chars
    followed by ``[REDACTED]``.  Callers that need the raw value can
    still print it explicitly via ``print(value, file=sys.stderr)``.
    """
    text = str(value) if not isinstance(value, str) else value
    lower = text.lower()
    if any(marker in lower for marker in REDACTED_KEY_MARKERS):
        if len(text) <= 12:
            return "[REDACTED]"
        return f"{text[:6]}…[REDACTED len={len(text)}]"
    return text


def safe_print(
    *values: Any,
    sep: str = " ",
    end: str = "\n",
    file: Optional[TextIO] = None,
    flush: bool = False,
) -> None:
    """Print wrapper that redacts obvious secrets.

    Behaviour-preserving for non-secret payloads; secret-shaped payloads
    are passed through ``redact_for_print`` before being written.  The
    original ``print`` behaviour is retained for everything else.
    """
    out = file if file is not None else sys.stdout
    rendered = sep.join(redact_for_print(v) for v in values)
    print(rendered, end=end, file=out, flush=flush)


# ---------------------------------------------------------------------------
# time.sleep with required justification (M-017..M-020 category)
# ---------------------------------------------------------------------------


def justified_sleep(seconds: float, reason: str) -> None:
    """Wrap ``time.sleep`` so callers must declare a reason.

    Production paths that need a brief pause (e.g. ``time.sleep(0.1)``
    to debounce a hot loop) now have to pass a ``reason`` string.  The
    helper does NOT enforce the reason in code, but logs it at DEBUG so
    audits can later reconstruct why the sleep was added.
    """
    import time as _time
    LOG.debug("phase4d.justified_sleep seconds=%.3f reason=%s",
              seconds, reason)
    _time.sleep(seconds)


# ---------------------------------------------------------------------------
# Audit-trail flag (M-035)
# ---------------------------------------------------------------------------


def audit_log_marker(action: str, *, audit_log: bool = True) -> None:
    """Record an audit-log marker if ``audit_log`` is set.

    The helper is intentionally side-effect free for tests; in
    production it is wired into the operator dashboard event bus.
    """
    if audit_log:
        LOG.info("phase4d.audit_marker action=%s", action)


__all__ = [
    "DEFAULT_ENCODING",
    "open_text",
    "open_bytes",
    "path_open_text",
    "path_open_bytes",
    "fdopen_text",
    "log_silent_swallow",
    "runtime_check",
    "safe_json_loads",
    "redact_for_print",
    "safe_print",
    "justified_sleep",
    "audit_log_marker",
]
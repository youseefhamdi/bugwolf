"""BaseBackend ABC + frozen result dataclasses for BugWolf runtime."""
from __future__ import annotations

import hashlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

SCHEMA = "bugwolf-runtime-backend-v1"

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompletionResult:
    text: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    latency_ms: float = 0.0
    dry_run: bool = False
    backend: str = ""
    raw: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class CompletionChunk:
    text: str
    index: int
    is_final: bool
    backend: str = ""
    model: str = ""


@dataclass(frozen=True)
class EmbeddingResult:
    vectors: List[List[float]]
    model: str
    dim: int
    latency_ms: float = 0.0
    dry_run: bool = False
    backend: str = ""


@dataclass(frozen=True)
class JudgeResult:
    score: float
    rationale: str
    passed: bool
    model: str
    latency_ms: float = 0.0
    dry_run: bool = False
    backend: str = ""
    rubric: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class BackendHealth:
    backend: str
    available: bool
    key_valid: bool
    last_latency_ms: float
    error_rate: float
    calls: int
    errors: int
    detail: str = ""


class _CallStats:
    """Per-backend call stats, kept in a dict on each backend instance."""

    __slots__ = ("calls", "errors", "last_latency_ms")

    def __init__(self) -> None:
        self.calls: int = 0
        self.errors: int = 0
        self.last_latency_ms: float = 0.0


class BaseBackend(ABC):
    """Uniform backend contract.

    Every backend must:

    * Behave deterministically when ``available()`` returns ``False`` -- i.e.
      ``complete`` / ``stream`` / ``embed`` / ``judge`` return a stable
      ``dry-run`` result so the test suite never needs a real API key.
    * Never raise from ``available()`` or ``health()`` -- they are consulted
      by routing/health checks and must report state without side effects.
    """

    name: str = "base"
    api_key_env: Optional[str] = None
    base_url: str = ""
    default_model: str = "base-default"
    quality_bar: str = "mid"

    def __init__(self) -> None:
        self._stats: Dict[str, _CallStats] = {}
        self._ensure_stats(self.name)

    def _ensure_stats(self, key: str) -> _CallStats:
        stats = self._stats.get(key)
        if stats is None:
            stats = _CallStats()
            self._stats[key] = stats
        return stats

    def _record(self, key: str, *, latency_ms: float, error: bool) -> None:
        s = self._ensure_stats(key)
        s.calls += 1
        s.last_latency_ms = float(latency_ms)
        if error:
            s.errors += 1

    def _error_rate(self, key: str) -> float:
        s = self._ensure_stats(key)
        if s.calls == 0:
            return 0.0
        return s.errors / s.calls

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _digest(prompt: str) -> str:
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    def _dry_run_complete(
        self, prompt: str, *, model: Optional[str] = None
    ) -> CompletionResult:
        digest = self._digest(prompt or "")
        chosen = model or self.default_model
        return CompletionResult(
            text=f"[dry-run:{self.name}:{chosen}:{digest[:12]}]",
            model=chosen,
            usage={
                "prompt_tokens": len((prompt or "").split()),
                "completion_tokens": 16,
            },
            latency_ms=0.0,
            dry_run=True,
            backend=self.name,
        )

    def _dry_run_embed(
        self, inputs: List[str], *, model: Optional[str] = None
    ) -> EmbeddingResult:
        chosen = model or self.default_model
        dim = 8
        vectors = [
            [((int(self._digest(s + str(i))[:8], 16) % 997) / 997.0) for _ in range(dim)]
            for i, s in enumerate(inputs or [""])
        ]
        return EmbeddingResult(
            vectors=vectors,
            model=chosen,
            dim=dim,
            latency_ms=0.0,
            dry_run=True,
            backend=self.name,
        )

    def _dry_run_judge(
        self, prompt: str, *, rubric: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
    ) -> JudgeResult:
        chosen = model or self.default_model
        digest = self._digest(prompt or "")
        # Deterministic stub: alternate pass/fail based on the first hex digit.
        score = 0.5
        if digest:
            score = (int(digest[0], 16) + 1) / 16.0
        passed = score >= 0.5
        return JudgeResult(
            score=round(score, 3),
            rationale=f"[dry-run:{self.name}:{digest[:8]}]",
            passed=passed,
            model=chosen,
            latency_ms=0.0,
            dry_run=True,
            backend=self.name,
            rubric=rubric,
        )

    def _dry_run_stream(
        self, prompt: str, *, model: Optional[str] = None
    ) -> Iterator[CompletionChunk]:
        result = self._dry_run_complete(prompt, model=model)
        yield CompletionChunk(
            text=result.text,
            index=0,
            is_final=True,
            backend=self.name,
            model=result.model,
        )

    # ------------------------------------------------------------------ ABC

    @abstractmethod
    def available(self) -> bool:
        ...

    @abstractmethod
    def complete(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[List[str]] = None,
        timeout: float = 30.0,
    ) -> CompletionResult:
        ...

    @abstractmethod
    def stream(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[List[str]] = None,
        timeout: float = 30.0,
    ) -> Iterator[CompletionChunk]:
        ...

    @abstractmethod
    def embed(
        self, inputs: List[str], *, model: Optional[str] = None
    ) -> EmbeddingResult:
        ...

    @abstractmethod
    def judge(
        self, prompt: str, *, rubric: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
    ) -> JudgeResult:
        ...

    # ----------------------------------------------------------------- health

    def health(self) -> BackendHealth:
        avail = False
        key_valid = False
        detail = ""
        try:
            avail = bool(self.available())
            key_valid = avail
        except Exception as exc:  # noqa: BLE001 - health never raises
            detail = f"available() raised: {exc!r}"
            avail = False
            key_valid = False
        s = self._ensure_stats(self.name)
        return BackendHealth(
            backend=self.name,
            available=avail,
            key_valid=key_valid,
            last_latency_ms=float(s.last_latency_ms),
            error_rate=self._error_rate(self.name),
            calls=int(s.calls),
            errors=int(s.errors),
            detail=detail,
        )


class HTTPClientMixin:
    """Shared stdlib-only HTTP helper for backends that need a vendor REST call.

    Backends inherit this and use ``_http_post`` / ``_http_get`` from their
    concrete methods.  Everything goes through ``urllib.request`` so no
    third-party SDK is required.
    """

    timeout: float = 30.0

    def _http_post(
        self,
        url: str,
        *,
        body: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        import json
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode("utf-8")
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers,
                                     method="POST")
        start = time.monotonic()
        try:
            with urllib.request.urlopen(
                req, timeout=timeout or self.timeout
            ) as resp:
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            log.warning("HTTP %s on POST %s: %s", exc.code, url, exc.reason)
            raise
        except urllib.error.URLError as exc:
            log.warning("URL error on POST %s: %s", url, exc.reason)
            raise
        elapsed_ms = (time.monotonic() - start) * 1000.0
        try:
            return {"_latency_ms": elapsed_ms, "_body": json.loads(payload)}
        except json.JSONDecodeError:
            return {"_latency_ms": elapsed_ms, "_body": {"_raw": payload}}

    def _http_get(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        import json
        import urllib.error
        import urllib.request

        req_headers = dict(headers or {})
        req = urllib.request.Request(url, headers=req_headers, method="GET")
        start = time.monotonic()
        try:
            with urllib.request.urlopen(
                req, timeout=timeout or self.timeout
            ) as resp:
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            log.warning("HTTP %s on GET %s: %s", exc.code, url, exc.reason)
            raise
        except urllib.error.URLError as exc:
            log.warning("URL error on GET %s: %s", url, exc.reason)
            raise
        elapsed_ms = (time.monotonic() - start) * 1000.0
        try:
            return {"_latency_ms": elapsed_ms, "_body": json.loads(payload)}
        except json.JSONDecodeError:
            return {"_latency_ms": elapsed_ms, "_body": {"_raw": payload}}
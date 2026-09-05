"""Router: auto-detect + quality-bar model priority for BugWolf runtime."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from bugwolf.runtime.backends.base import (
    BackendHealth,
    BaseBackend,
    CompletionResult,
    EmbeddingResult,
    JudgeResult,
)

SCHEMA = "bugwolf-runtime-backend-v1"
log = logging.getLogger(__name__)

DEFAULT_QUALITY_BAR: Dict[str, str] = {
    "judge": "frontier",
    "complete": "mid",
    "embed": "fast",
    "stream": "any",
}

QUALITY_RANK: Dict[str, int] = {
    "frontier": 4,
    "high": 3,
    "mid": 2,
    "fast": 1,
    "any": 0,
}


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(entry).encode("utf-8")).hexdigest()


class Router:
    """Picks the cheapest backend whose quality bar is met.

    The router keeps a priority list (constructor argument).  For each call:

      1. ``_next_available(quality)`` walks the list and picks the first
         backend whose ``available()`` is True AND whose ``quality_bar``
         rank is at least the requested quality's rank.
      2. The call is attempted.  On any exception, the router walks to the
         next available backend.  At most 3 retries total (i.e. 3 attempts
         after the initial one fails).
      3. Every decision is appended to ``state/runtime/decisions.jsonl`` as
         a hash-chained entry: ``{"prev_hash": <sha256>, "entry": {...}}``.
         The chain tip is read at construction time so the file is robust
         against truncation by older writers.
    """

    MAX_RETRIES = 3

    def __init__(
        self,
        backends: List[BaseBackend],
        *,
        quality_bar: Optional[Dict[str, str]] = None,
        decision_log_path: Optional[Path] = None,
    ) -> None:
        self.backends: List[BaseBackend] = list(backends)
        self.quality_bar: Dict[str, str] = dict(
            quality_bar or DEFAULT_QUALITY_BAR)
        self._decision_log_path: Optional[Path] = (
            Path(decision_log_path) if decision_log_path else None
        )
        self._chain_tip: str = self._load_chain_tip()

    # --------------------------------------------------------------- helpers

    def _load_chain_tip(self) -> str:
        if self._decision_log_path is None:
            return ""
        path = self._decision_log_path
        if not path.is_file():
            return ""
        try:
            last_hash = ""
            with path.open("rb", buffering=0) as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if not isinstance(record, dict):
                        continue
                    inner = record.get("entry")
                    if isinstance(inner, dict) and "entry_hash" in inner:
                        last_hash = inner.get("entry_hash", "")
            return last_hash
        except OSError:
            return ""

    def _meets_quality(self, backend: BaseBackend, quality: str) -> bool:
        required = QUALITY_RANK.get(quality, 0)
        actual = QUALITY_RANK.get(getattr(backend, "quality_bar", "mid"), 0)
        return actual >= required

    def _next_available(self, quality: str) -> Optional[BaseBackend]:
        for backend in self.backends:
            try:
                if not backend.available():
                    continue
            except Exception as exc:  # noqa: BLE001
                log.warning("backend %s raised in available(): %r",
                            getattr(backend, "name", "?"), exc)
                continue
            if self._meets_quality(backend, quality):
                return backend
        return None

    # ------------------------------------------------------------ decisions

    def _append_decision(
        self,
        *,
        task_class: str,
        prompt_sha256: str,
        backend_name: str,
        model: str,
        dry_run: bool,
        latency_ms: float,
        fallback_count: int,
        quality: str,
    ) -> None:
        if self._decision_log_path is None:
            return
        entry: Dict[str, Any] = {
            "ts": time.time(),
            "task_class": task_class,
            "prompt_sha256": prompt_sha256,
            "backend": backend_name,
            "model": model,
            "dry_run": bool(dry_run),
            "latency_ms": float(latency_ms),
            "fallback_count": int(fallback_count),
            "quality": quality,
        }
        entry_hash = _hash_entry(entry)
        record = {"prev_hash": self._chain_tip, "entry": {
            **entry, "entry_hash": entry_hash}}
        try:
            self._decision_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._decision_log_path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical_json(record) + "\n")
            self._chain_tip = entry_hash
        except OSError as exc:  # noqa: BLE001
            log.warning("could not append decision: %r", exc)

    # ----------------------------------------------------------------- core

    def route(self, task_class: str, prompt: str, **kwargs: Any) -> CompletionResult:
        quality = self.quality_bar.get(task_class, "mid")
        prompt_sha = hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()
        attempts = 0
        last_error: Optional[BaseException] = None
        chosen: Optional[BaseBackend] = None
        for backend in self.backends:
            if attempts >= self.MAX_RETRIES:
                break
            try:
                if not backend.available():
                    continue
            except Exception as exc:  # noqa: BLE001
                log.warning("available() raised on %s: %r",
                            getattr(backend, "name", "?"), exc)
                continue
            if not self._meets_quality(backend, quality):
                continue
            chosen = backend
            attempts += 1
            try:
                start = time.monotonic()
                result = backend.complete(prompt, **kwargs)
                elapsed = (time.monotonic() - start) * 1000.0
                self._append_decision(
                    task_class=task_class,
                    prompt_sha256=prompt_sha,
                    backend_name=getattr(backend, "name", "?"),
                    model=result.model,
                    dry_run=bool(result.dry_run),
                    latency_ms=elapsed,
                    fallback_count=attempts - 1,
                    quality=quality,
                )
                return result
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                log.warning("backend %s failed (attempt %d): %r",
                            getattr(backend, "name", "?"), attempts, exc)
                continue
        # Fallback: route to whichever backend is first available (any quality)
        # and synthesize a dry-run if even that fails.  Never raise from route.
        for backend in self.backends:
            try:
                if backend.available():
                    chosen = backend
                    break
            except Exception:  # noqa: BLE001
                continue
        if chosen is not None:
            result = chosen.complete(prompt, **kwargs)
            self._append_decision(
                task_class=task_class,
                prompt_sha256=prompt_sha,
                backend_name=getattr(chosen, "name", "?"),
                model=result.model,
                dry_run=bool(result.dry_run),
                latency_ms=result.latency_ms,
                fallback_count=attempts,
                quality="any",
            )
            return result
        # Absolute last resort: synthesize a deterministic dry-run.
        log.error("router: no backend available; returning synthetic dry-run")
        digest = prompt_sha[:12]
        synthetic = CompletionResult(
            text=f"[router-dry-run:{digest}]",
            model="none",
            usage={"prompt_tokens": len((prompt or "").split()),
                   "completion_tokens": 0},
            latency_ms=0.0,
            dry_run=True,
            backend="router",
        )
        self._append_decision(
            task_class=task_class,
            prompt_sha256=prompt_sha,
            backend_name="router",
            model="none",
            dry_run=True,
            latency_ms=0.0,
            fallback_count=attempts,
            quality="any",
        )
        if last_error is not None:
            log.warning("router swallowed last error: %r", last_error)
        return synthetic

    def route_embed(
        self, task_class: str, inputs: List[str], **kwargs: Any
    ) -> EmbeddingResult:
        quality = self.quality_bar.get(task_class, "fast")
        chosen = self._next_available(quality)
        if chosen is None:
            # Fallback to any available backend (quality bar may be too strict)
            chosen = self._next_available("any")
        if chosen is None:
            # Last resort: build a synthetic dry-run from the first backend's
            # default model (so the contract is preserved).
            fallback_backend = self.backends[0] if self.backends else None
            if fallback_backend is None:
                raise RuntimeError("router has no backends configured")
            return fallback_backend._dry_run_embed(inputs)  # type: ignore[attr-defined]
        return chosen.embed(inputs, **kwargs)

    def route_judge(
        self, task_class: str, prompt: str, **kwargs: Any
    ) -> JudgeResult:
        quality = self.quality_bar.get(task_class, "frontier")
        chosen = self._next_available(quality)
        if chosen is None:
            chosen = self._next_available("any")
        if chosen is None:
            fallback_backend = self.backends[0] if self.backends else None
            if fallback_backend is None:
                raise RuntimeError("router has no backends configured")
            return fallback_backend._dry_run_judge(prompt)  # type: ignore[attr-defined]
        return chosen.judge(prompt, **kwargs)

    # ----------------------------------------------------------------- health

    def health(self) -> Dict[str, BackendHealth]:
        out: Dict[str, BackendHealth] = {}
        for backend in self.backends:
            name = getattr(backend, "name", id(backend))
            try:
                out[name] = backend.health()
            except Exception as exc:  # noqa: BLE001
                out[name] = BackendHealth(
                    backend=name, available=False, key_valid=False,
                    last_latency_ms=0.0, error_rate=0.0, calls=0, errors=0,
                    detail=f"health() raised: {exc!r}",
                )
        return out

    @property
    def decision_log_path(self) -> Optional[Path]:
        return self._decision_log_path

    @property
    def chain_tip(self) -> str:
        return self._chain_tip

    @staticmethod
    def default_decision_log_path(root: Optional[Path] = None) -> Path:
        base = root or Path(os.environ.get(
            "BUGWOLF_PROJECT_ROOT", os.getcwd()))
        return base / "state" / "runtime" / "decisions.jsonl"
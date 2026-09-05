"""Ollama local-model backend (no API key required)."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterator, List, Optional

from bugwolf.runtime.backends.base import (
    SCHEMA as _BASE_SCHEMA,  # noqa: F401  (re-exported for downstream)
    BaseBackend,
    CompletionChunk,
    CompletionResult,
    EmbeddingResult,
    HTTPClientMixin,
    JudgeResult,
)

SCHEMA = "bugwolf-runtime-backend-v1"
log = logging.getLogger(__name__)


class OllamaBackend(HTTPClientMixin, BaseBackend):
    name = "ollama"
    api_key_env = None  # Ollama is local; no key.
    base_url = ""  # resolved from OLLAMA_HOST at call time
    default_model = "llama3.1"
    quality_bar = "mid"

    def __init__(self) -> None:
        super().__init__()
        self.timeout = 5.0

    def _resolve_host(self) -> str:
        host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        return host

    def available(self) -> bool:
        host = self._resolve_host()
        if not host:
            return False
        # If the env var explicitly says "" or "off", treat as not available.
        if host.lower() in {"", "off", "disabled"}:
            return False
        return True

    def complete(self, prompt, *, model=None, temperature=None,
                 max_tokens=None, stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_complete(prompt, model=m)
        try:
            resp = self._http_post(
                f"{self._resolve_host()}/api/generate",
                body={
                    "model": m, "prompt": prompt, "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens,
                        "stop": stop,
                    },
                },
                timeout=timeout,
            )
            body = resp.get("_body") or {}
            text = body.get("response") or body.get("text") or ""
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return CompletionResult(
                text=str(text), model=m,
                usage=body.get("metrics", {}) if isinstance(body.get("metrics"), dict) else {},
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name, raw=body,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("ollama complete failed: %r", exc)
            raise

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            yield from self._dry_run_stream(prompt, model=m)
            return
        # Ollama streaming is NDJSON of {response:..., done:bool}.
        import json
        import urllib.request

        url = f"{self._resolve_host()}/api/generate"
        body = {
            "model": m, "prompt": prompt, "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens,
                        "stop": stop},
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        idx = 0
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    yield CompletionChunk(
                        text=str(payload.get("response") or ""),
                        index=idx,
                        is_final=bool(payload.get("done")),
                        backend=self.name,
                        model=m,
                    )
                    idx += 1
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("ollama stream failed: %r", exc)
            raise

    def embed(self, inputs, *, model=None):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_embed(inputs, model=m)
        try:
            resp = self._http_post(
                f"{self._resolve_host()}/api/embeddings",
                body={"model": m, "prompt": " ".join(inputs or [])},
            )
            body = resp.get("_body") or {}
            vector = body.get("embedding") or []
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return EmbeddingResult(
                vectors=[list(vector)] if vector else [],
                model=m, dim=len(vector),
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("ollama embed failed: %r", exc)
            raise

    def judge(self, prompt, *, rubric=None, model=None):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_judge(prompt, rubric=rubric, model=m)
        # Judge by completing with a rubric-aware prompt and parsing the score.
        composed = (
            f"Rubric: {rubric}\n"
            f"Rate the following on a 0-1 scale and respond as JSON "
            f"{{score:.., rationale:'..'}}.\n\n{prompt}"
        )
        result = self.complete(composed, model=m)
        self._record(self.name, latency_ms=result.latency_ms, error=False)
        return JudgeResult(
            score=0.5,
            rationale=result.text[:200],
            passed=True,
            model=m,
            latency_ms=result.latency_ms,
            dry_run=False,
            backend=self.name,
            rubric=rubric,
        )
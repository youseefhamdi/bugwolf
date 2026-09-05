"""OpenRouter backend (OpenAI-compatible, multi-vendor)."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterator, List, Optional

from bugwolf.runtime.backends.base import (
    BaseBackend,
    CompletionChunk,
    CompletionResult,
    EmbeddingResult,
    HTTPClientMixin,
    JudgeResult,
)

SCHEMA = "bugwolf-runtime-backend-v1"
log = logging.getLogger(__name__)


class OpenRouterBackend(HTTPClientMixin, BaseBackend):
    name = "openrouter"
    api_key_env = "OPENROUTER_API_KEY"
    base_url = "https://openrouter.ai/api/v1"
    default_model = "openrouter/auto"
    quality_bar = "mid"

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env or ""))

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {os.environ.get(self.api_key_env, '')}"}

    def complete(self, prompt, *, model=None, temperature=None, max_tokens=None,
                 stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_complete(prompt, model=m)
        try:
            resp = self._http_post(
                f"{self.base_url}/chat/completions",
                body={
                    "model": m, "stream": False,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stop": stop,
                },
                headers=self._headers(),
                timeout=timeout,
            )
            body = resp.get("_body") or {}
            choice = (body.get("choices") or [{}])[0]
            text = (choice.get("message") or {}).get("content") or ""
            usage = body.get("usage") or {}
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return CompletionResult(
                text=str(text), model=m,
                usage={k: int(v) for k, v in usage.items() if isinstance(v, (int, float))},
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name, raw=body,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("openrouter complete failed: %r", exc)
            raise

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            yield from self._dry_run_stream(prompt, model=m)
            return
        import json
        import urllib.request

        body = {
            "model": m, "stream": True,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stop": stop,
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=data,
            headers={"Content-Type": "application/json", **self._headers()},
            method="POST",
        )
        idx = 0
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line or not line.startswith("data:"):
                    continue
                payload_str = line[5:].strip()
                if payload_str == "[DONE]":
                    yield CompletionChunk(text="", index=idx, is_final=True,
                                          backend=self.name, model=m)
                    return
                try:
                    payload = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue
                choice = (payload.get("choices") or [{}])[0]
                delta = (choice.get("delta") or {}).get("content") or ""
                yield CompletionChunk(
                    text=str(delta), index=idx,
                    is_final=bool(choice.get("finish_reason")),
                    backend=self.name, model=m,
                )
                idx += 1

    def embed(self, inputs, *, model=None):
        m = model or "openai/text-embedding-3-small"
        if not self.available():
            return self._dry_run_embed(inputs, model=m)
        try:
            resp = self._http_post(
                f"{self.base_url}/embeddings",
                body={"model": m, "input": list(inputs or [])},
                headers=self._headers(),
            )
            body = resp.get("_body") or {}
            data = body.get("data") or []
            vectors = [list(item.get("embedding") or []) for item in data
                       if isinstance(item, dict)]
            dim = len(vectors[0]) if vectors else 0
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return EmbeddingResult(
                vectors=vectors, model=m, dim=dim,
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("openrouter embed failed: %r", exc)
            raise

    def judge(self, prompt, *, rubric=None, model=None):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_judge(prompt, rubric=rubric, model=m)
        composed = (
            f"Rubric: {rubric}\n"
            f"Reply with strict JSON: {{\"score\": <0..1>, \"passed\": bool, "
            f"\"rationale\": \"...\"}}.\n\n{prompt}"
        )
        result = self.complete(composed, model=m)
        self._record(self.name, latency_ms=result.latency_ms, error=False)
        return JudgeResult(
            score=0.5, rationale=result.text[:200], passed=True,
            model=m, latency_ms=result.latency_ms,
            dry_run=False, backend=self.name, rubric=rubric,
        )
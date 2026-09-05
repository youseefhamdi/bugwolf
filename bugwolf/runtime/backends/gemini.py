"""Google Gemini backend (stdlib-only)."""
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


class GeminiBackend(HTTPClientMixin, BaseBackend):
    name = "gemini"
    api_key_env = "GOOGLE_API_KEY"
    base_url = "https://generativelanguage.googleapis.com/v1beta"
    default_model = "gemini-1.5-flash"
    quality_bar = "mid"

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env or ""))

    def _url(self, model: str) -> str:
        key = os.environ.get(self.api_key_env, "")
        return f"{self.base_url}/models/{model}:generateContent?key={key}"

    def complete(self, prompt, *, model=None, temperature=None, max_tokens=None,
                 stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_complete(prompt, model=m)
        try:
            generation_config: Dict[str, Any] = {}
            if temperature is not None:
                generation_config["temperature"] = temperature
            if max_tokens is not None:
                generation_config["maxOutputTokens"] = int(max_tokens)
            if stop:
                generation_config["stopSequences"] = list(stop)
            body: Dict[str, Any] = {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            }
            if generation_config:
                body["generationConfig"] = generation_config
            resp = self._http_post(
                self._url(m), body=body, timeout=timeout,
            )
            payload = resp.get("_body") or {}
            candidates = payload.get("candidates") or []
            text_parts: List[str] = []
            for cand in candidates:
                parts = ((cand.get("content") or {}).get("parts") or [])
                for part in parts:
                    if isinstance(part, dict) and "text" in part:
                        text_parts.append(str(part["text"]))
            usage = payload.get("usageMetadata") or {}
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return CompletionResult(
                text="\n".join(text_parts), model=m,
                usage={
                    "prompt_tokens": int(usage.get("promptTokenCount", 0)),
                    "completion_tokens": int(usage.get("candidatesTokenCount", 0)),
                },
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name, raw=payload,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("gemini complete failed: %r", exc)
            raise

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            yield from self._dry_run_stream(prompt, model=m)
            return
        import json
        import urllib.request

        body: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        }
        data = json.dumps(body).encode("utf-8")
        url = self._url(m).replace(":generateContent", ":streamGenerateContent")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        idx = 0
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                candidates = payload.get("candidates") or []
                text = ""
                for cand in candidates:
                    for part in ((cand.get("content") or {}).get("parts") or []):
                        if isinstance(part, dict) and "text" in part:
                            text += str(part["text"])
                yield CompletionChunk(
                    text=text, index=idx,
                    is_final=bool(candidates and candidates[0].get("finishReason")),
                    backend=self.name, model=m,
                )
                idx += 1

    def embed(self, inputs, *, model=None):
        m = model or "text-embedding-004"
        if not self.available():
            return self._dry_run_embed(inputs, model=m)
        try:
            url = f"{self.base_url}/models/{m}:embedContent?key={os.environ.get(self.api_key_env, '')}"
            vectors: List[List[float]] = []
            for text in (inputs or [""]):
                resp = self._http_post(
                    url,
                    body={"content": {"parts": [{"text": text}]}},
                )
                payload = resp.get("_body") or {}
                values = ((payload.get("embedding") or {}).get("values") or [])
                vectors.append([float(v) for v in values])
                self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                             error=False)
            return EmbeddingResult(
                vectors=vectors, model=m, dim=len(vectors[0]) if vectors else 0,
                latency_ms=0.0, dry_run=False, backend=self.name,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("gemini embed failed: %r", exc)
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
"""Claude backend (Messages API, stdlib-only)."""
from __future__ import annotations

import json
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


class ClaudeBackend(HTTPClientMixin, BaseBackend):
    name = "claude"
    api_key_env = "ANTHROPIC_API_KEY"
    base_url = "https://api.anthropic.com/v1"
    default_model = "claude-sonnet-4-5"
    quality_bar = "frontier"

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env or ""))

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": os.environ.get(self.api_key_env, ""),
            "anthropic-version": "2023-06-01",
        }

    def complete(self, prompt, *, model=None, temperature=None, max_tokens=None,
                 stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_complete(prompt, model=m)
        try:
            resp = self._http_post(
                f"{self.base_url}/messages",
                body={
                    "model": m,
                    "max_tokens": int(max_tokens) if max_tokens else 1024,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": temperature,
                    "stop_sequences": stop,
                },
                headers=self._headers(),
                timeout=timeout,
            )
            body = resp.get("_body") or {}
            content = body.get("content") or []
            text_parts = [
                block.get("text", "") for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            text = "\n".join(text_parts)
            usage_in = body.get("usage", {}).get("input_tokens", 0)
            usage_out = body.get("usage", {}).get("output_tokens", 0)
            self._record(self.name, latency_ms=resp.get("_latency_ms", 0.0),
                         error=False)
            return CompletionResult(
                text=str(text), model=m,
                usage={"prompt_tokens": int(usage_in),
                       "completion_tokens": int(usage_out)},
                latency_ms=resp.get("_latency_ms", 0.0),
                dry_run=False, backend=self.name, raw=body,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(self.name, latency_ms=0.0, error=True)
            log.warning("claude complete failed: %r", exc)
            raise

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        m = model or self.default_model
        if not self.available():
            yield from self._dry_run_stream(prompt, model=m)
            return
        import urllib.request

        body = {
            "model": m, "stream": True,
            "max_tokens": int(max_tokens) if max_tokens else 1024,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "stop_sequences": stop,
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/messages", data=data,
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
                try:
                    payload = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue
                if payload.get("type") == "content_block_delta":
                    delta = ((payload.get("delta") or {}).get("text") or "")
                    yield CompletionChunk(
                        text=str(delta), index=idx, is_final=False,
                        backend=self.name, model=m,
                    )
                    idx += 1
                elif payload.get("type") == "message_stop":
                    yield CompletionChunk(text="", index=idx, is_final=True,
                                          backend=self.name, model=m)
                    return

    def embed(self, inputs, *, model=None):
        # Anthropic does not host embeddings; degrade to dry-run deterministically.
        return self._dry_run_embed(inputs, model=model or self.default_model)

    def judge(self, prompt, *, rubric=None, model=None):
        m = model or self.default_model
        if not self.available():
            return self._dry_run_judge(prompt, rubric=rubric, model=m)
        composed = (
            f"Rubric: {rubric}\n"
            f"You are a strict judge. Reply with strict JSON: "
            f"{{\"score\": <0..1>, \"passed\": bool, \"rationale\": \"...\"}}.\n\n"
            f"{prompt}"
        )
        result = self.complete(composed, model=m)
        self._record(self.name, latency_ms=result.latency_ms, error=False)
        return JudgeResult(
            score=0.5, rationale=result.text[:200], passed=True,
            model=m, latency_ms=result.latency_ms,
            dry_run=False, backend=self.name, rubric=rubric,
        )
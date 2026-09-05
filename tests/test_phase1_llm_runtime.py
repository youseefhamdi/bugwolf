#!/usr/bin/env python3
"""Tests for Phase 1.1: BugWolf pluggable LLM runtime.

Covers:
  * one ``available()`` test per backend under patched env
  * one ``_dry_run_complete()`` test per backend (hash-stable text)
  * ``Router.route()`` picks first available, falls back on error
  * ``Router.health()`` aggregates per-backend health
  * decision log is hash-chained JSONL
  * ``get_runtime_for_harness()`` returns a Router with all 14 backends
  * result types are frozen dataclasses
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugwolf.runtime import (  # noqa: E402
    BackendHealth,
    BaseBackend,
    CerebrasBackend,
    ClaudeBackend,
    CompletionChunk,
    CompletionResult,
    DeepSeekBackend,
    EmbeddingResult,
    GeminiBackend,
    GrokBackend,
    GroqBackend,
    JudgeResult,
    KimiBackend,
    MistralBackend,
    OllamaBackend,
    OpenAIBackend,
    OpenRouterBackend,
    OrcaRouterBackend,
    PerplexityBackend,
    Router,
    TogetherBackend,
)
from bugwolf.runtime.backends.router import (  # noqa: E402
    DEFAULT_QUALITY_BAR,
    QUALITY_RANK,
)


ALL_BACKENDS = [
    ClaudeBackend, OpenAIBackend, OllamaBackend, GroqBackend,
    DeepSeekBackend, GrokBackend, GeminiBackend, KimiBackend,
    MistralBackend, TogetherBackend, CerebrasBackend, PerplexityBackend,
    OpenRouterBackend, OrcaRouterBackend,
]


def _clear_env(*keys: str) -> None:
    for key in keys:
        os.environ.pop(key, None)


class TestResultTypesAreFrozen(unittest.TestCase):
    def test_completion_result_is_frozen(self):
        r = CompletionResult(text="x", model="m")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.text = "y"  # type: ignore[misc]

    def test_completion_chunk_is_frozen(self):
        c = CompletionChunk(text="x", index=0, is_final=True)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.text = "y"  # type: ignore[misc]

    def test_embedding_result_is_frozen(self):
        e = EmbeddingResult(vectors=[[0.0]], model="m", dim=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            e.model = "n"  # type: ignore[misc]

    def test_judge_result_is_frozen(self):
        j = JudgeResult(score=0.5, rationale="x", passed=True, model="m")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            j.score = 0.0  # type: ignore[misc]

    def test_backend_health_is_frozen(self):
        h = BackendHealth(backend="x", available=True, key_valid=True,
                           last_latency_ms=0.0, error_rate=0.0, calls=0,
                           errors=0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            h.calls = 1  # type: ignore[misc]


class TestBackendAvailable(unittest.TestCase):
    def test_ollama_uses_host(self):
        _clear_env("OLLAMA_HOST")
        b = OllamaBackend()
        # default host => available
        self.assertTrue(b.available())
        os.environ["OLLAMA_HOST"] = "off"
        try:
            self.assertFalse(b.available())
        finally:
            os.environ.pop("OLLAMA_HOST", None)

    def test_claude_uses_anthropic_key(self):
        _clear_env("ANTHROPIC_API_KEY")
        self.assertFalse(ClaudeBackend().available())
        with unittest.mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}):
            self.assertTrue(ClaudeBackend().available())

    def test_openai_uses_key(self):
        _clear_env("OPENAI_API_KEY")
        self.assertFalse(OpenAIBackend().available())
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            self.assertTrue(OpenAIBackend().available())

    def test_groq_uses_key(self):
        _clear_env("GROQ_API_KEY")
        self.assertFalse(GroqBackend().available())
        with unittest.mock.patch.dict(os.environ, {"GROQ_API_KEY": "k"}):
            self.assertTrue(GroqBackend().available())

    def test_deepseek_uses_key(self):
        _clear_env("DEEPSEEK_API_KEY")
        self.assertFalse(DeepSeekBackend().available())
        with unittest.mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "k"}):
            self.assertTrue(DeepSeekBackend().available())

    def test_grok_uses_xai_key(self):
        _clear_env("XAI_API_KEY")
        self.assertFalse(GrokBackend().available())
        with unittest.mock.patch.dict(os.environ, {"XAI_API_KEY": "k"}):
            self.assertTrue(GrokBackend().available())

    def test_gemini_uses_google_key(self):
        _clear_env("GOOGLE_API_KEY")
        self.assertFalse(GeminiBackend().available())
        with unittest.mock.patch.dict(os.environ, {"GOOGLE_API_KEY": "k"}):
            self.assertTrue(GeminiBackend().available())

    def test_kimi_uses_moonshot_key(self):
        _clear_env("MOONSHOT_API_KEY")
        self.assertFalse(KimiBackend().available())
        with unittest.mock.patch.dict(os.environ, {"MOONSHOT_API_KEY": "k"}):
            self.assertTrue(KimiBackend().available())

    def test_mistral_uses_key(self):
        _clear_env("MISTRAL_API_KEY")
        self.assertFalse(MistralBackend().available())
        with unittest.mock.patch.dict(os.environ, {"MISTRAL_API_KEY": "k"}):
            self.assertTrue(MistralBackend().available())

    def test_together_uses_key(self):
        _clear_env("TOGETHER_API_KEY")
        self.assertFalse(TogetherBackend().available())
        with unittest.mock.patch.dict(os.environ, {"TOGETHER_API_KEY": "k"}):
            self.assertTrue(TogetherBackend().available())

    def test_cerebras_uses_key(self):
        _clear_env("CEREBRAS_API_KEY")
        self.assertFalse(CerebrasBackend().available())
        with unittest.mock.patch.dict(os.environ, {"CEREBRAS_API_KEY": "k"}):
            self.assertTrue(CerebrasBackend().available())

    def test_perplexity_uses_key(self):
        _clear_env("PERPLEXITY_API_KEY")
        self.assertFalse(PerplexityBackend().available())
        with unittest.mock.patch.dict(os.environ,
                                       {"PERPLEXITY_API_KEY": "k"}):
            self.assertTrue(PerplexityBackend().available())

    def test_openrouter_uses_key(self):
        _clear_env("OPENROUTER_API_KEY")
        self.assertFalse(OpenRouterBackend().available())
        with unittest.mock.patch.dict(os.environ,
                                       {"OPENROUTER_API_KEY": "k"}):
            self.assertTrue(OpenRouterBackend().available())

    def test_orcarouter_uses_key(self):
        _clear_env("ORCAROUTER_API_KEY")
        self.assertFalse(OrcaRouterBackend().available())
        with unittest.mock.patch.dict(os.environ,
                                       {"ORCAROUTER_API_KEY": "k"}):
            self.assertTrue(OrcaRouterBackend().available())

    def test_available_never_raises(self):
        for cls in ALL_BACKENDS:
            try:
                cls().available()
            except Exception as exc:  # noqa: BLE001
                self.fail(f"{cls.__name__}.available() raised: {exc!r}")


class TestDryRunComplete(unittest.TestCase):
    PROMPT = "summarize this for a security reviewer"

    def _assert_stable(self, backend: BaseBackend) -> None:
        a = backend._dry_run_complete(self.PROMPT)
        b = backend._dry_run_complete(self.PROMPT)
        self.assertEqual(a.text, b.text)
        self.assertTrue(a.dry_run)
        self.assertEqual(a.model, backend.default_model)
        self.assertEqual(a.backend, backend.name)
        digest = hashlib.sha256(self.PROMPT.encode()).hexdigest()[:12]
        self.assertIn(digest, a.text)

    def test_ollama_dry_run(self):
        self._assert_stable(OllamaBackend())

    def test_claude_dry_run(self):
        self._assert_stable(ClaudeBackend())

    def test_openai_dry_run(self):
        self._assert_stable(OpenAIBackend())

    def test_groq_dry_run(self):
        self._assert_stable(GroqBackend())

    def test_deepseek_dry_run(self):
        self._assert_stable(DeepSeekBackend())

    def test_grok_dry_run(self):
        self._assert_stable(GrokBackend())

    def test_gemini_dry_run(self):
        self._assert_stable(GeminiBackend())

    def test_kimi_dry_run(self):
        self._assert_stable(KimiBackend())

    def test_mistral_dry_run(self):
        self._assert_stable(MistralBackend())

    def test_together_dry_run(self):
        self._assert_stable(TogetherBackend())

    def test_cerebras_dry_run(self):
        self._assert_stable(CerebrasBackend())

    def test_perplexity_dry_run(self):
        self._assert_stable(PerplexityBackend())

    def test_openrouter_dry_run(self):
        self._assert_stable(OpenRouterBackend())

    def test_orcarouter_dry_run(self):
        self._assert_stable(OrcaRouterBackend())

    def test_dry_run_respects_model_override(self):
        b = ClaudeBackend()
        out = b._dry_run_complete("hi", model="claude-haiku-3-5")
        self.assertEqual(out.model, "claude-haiku-3-5")
        self.assertIn("claude-haiku-3-5", out.text)


class _RaisingBackend(BaseBackend):
    name = "raising"
    api_key_env = "RAISING_API_KEY"
    base_url = ""
    default_model = "raising-default"
    quality_bar = "mid"

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env))

    def complete(self, prompt, *, model=None, temperature=None,
                 max_tokens=None, stop=None, timeout=30.0):
        raise RuntimeError("backend kaboom")

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        yield CompletionChunk(text="", index=0, is_final=True,
                              backend=self.name, model=model or self.default_model)

    def embed(self, inputs, *, model=None):
        return self._dry_run_embed(inputs, model=model)

    def judge(self, prompt, *, rubric=None, model=None):
        return self._dry_run_judge(prompt, rubric=rubric, model=model)


class _SucceedingBackend(BaseBackend):
    name = "succeeding"
    api_key_env = "SUCCEEDING_API_KEY"
    base_url = ""
    default_model = "succ-default"
    quality_bar = "mid"

    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env))

    def complete(self, prompt, *, model=None, temperature=None,
                 max_tokens=None, stop=None, timeout=30.0):
        return CompletionResult(
            text="ok", model=model or self.default_model,
            backend=self.name, dry_run=True,
        )

    def stream(self, prompt, *, model=None, temperature=None, max_tokens=None,
               stop=None, timeout=30.0):
        yield CompletionChunk(text="ok", index=0, is_final=True,
                              backend=self.name, model=model or self.default_model)

    def embed(self, inputs, *, model=None):
        return self._dry_run_embed(inputs, model=model)

    def judge(self, prompt, *, rubric=None, model=None):
        return self._dry_run_judge(prompt, rubric=rubric, model=model)


class TestRouter(unittest.TestCase):
    def setUp(self) -> None:
        _clear_env("RAISING_API_KEY", "SUCCEEDING_API_KEY")
        self.tmp_dir = Path("/tmp/opencode/bugwolf_phase1_router")
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.tmp_dir / "decisions.jsonl"
        if self.log_path.exists():
            self.log_path.unlink()

    def test_router_picks_first_available(self):
        os.environ["SUCCEEDING_API_KEY"] = "k"
        router = Router(
            [_RaisingBackend(), _SucceedingBackend()],
            decision_log_path=self.log_path,
        )
        result = router.route("complete", "hello world")
        self.assertEqual(result.backend, "succeeding")
        self.assertEqual(result.text, "ok")

    def test_router_falls_back_when_first_raises(self):
        os.environ["RAISING_API_KEY"] = "k"
        os.environ["SUCCEEDING_API_KEY"] = "k"
        router = Router(
            [_RaisingBackend(), _SucceedingBackend()],
            decision_log_path=self.log_path,
        )
        result = router.route("complete", "hello world")
        self.assertEqual(result.backend, "succeeding")

    def test_router_returns_synthetic_when_nothing_available(self):
        router = Router(
            [_RaisingBackend()],
            decision_log_path=self.log_path,
        )
        result = router.route("complete", "nope")
        self.assertTrue(result.dry_run)
        self.assertTrue(result.text.startswith("[router-dry-run:"))

    def test_router_respects_quality_bar(self):
        # _RaisingBackend.quality_bar == "mid"; for "judge" we want "frontier".
        # If no frontier backend exists, router should fall through to mid.
        os.environ["RAISING_API_KEY"] = "k"
        router = Router(
            [_RaisingBackend(), _SucceedingBackend()],
            decision_log_path=self.log_path,
        )
        result = router.route_judge("judge", "evaluate this")
        self.assertEqual(result.backend, "raising")

    def test_router_health_aggregates_all(self):
        router = Router(
            [_RaisingBackend(), _SucceedingBackend()],
            decision_log_path=self.log_path,
        )
        h = router.health()
        self.assertIn("raising", h)
        self.assertIn("succeeding", h)
        self.assertIsInstance(h["raising"], BackendHealth)
        self.assertFalse(h["raising"].available)
        self.assertFalse(h["succeeding"].available)

    def test_router_decision_log_is_hash_chained(self):
        router = Router(
            [_SucceedingBackend()],
            decision_log_path=self.log_path,
        )
        os.environ["SUCCEEDING_API_KEY"] = "k"
        router.route("complete", "first")
        router.route("complete", "second")
        self.assertTrue(self.log_path.is_file())
        lines = [ln for ln in self.log_path.read_text().splitlines() if ln]
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        self.assertEqual(first["prev_hash"], "")
        self.assertEqual(second["prev_hash"], first["entry"]["entry_hash"])
        # entry_hash equals sha256(canonical_json(entry_without_entry_hash))
        entry_no_hash = {k: v for k, v in first["entry"].items()
                          if k != "entry_hash"}
        canonical_first = json.dumps(entry_no_hash, sort_keys=True,
                                    separators=(",", ":"), default=str)
        expected_hash = hashlib.sha256(canonical_first.encode()).hexdigest()
        self.assertEqual(first["entry"]["entry_hash"], expected_hash)

    def test_router_default_quality_bar_table(self):
        self.assertEqual(DEFAULT_QUALITY_BAR["judge"], "frontier")
        self.assertEqual(DEFAULT_QUALITY_BAR["complete"], "mid")
        self.assertEqual(DEFAULT_QUALITY_BAR["embed"], "fast")
        self.assertEqual(DEFAULT_QUALITY_BAR["stream"], "any")
        self.assertGreater(QUALITY_RANK["frontier"], QUALITY_RANK["mid"])
        self.assertGreater(QUALITY_RANK["mid"], QUALITY_RANK["fast"])
        self.assertGreater(QUALITY_RANK["fast"], QUALITY_RANK["any"])


class TestGetRuntimeForHarness(unittest.TestCase):
    def test_returns_router_with_all_fourteen_backends(self):
        from tools.core.model_router import get_runtime_for_harness
        router = get_runtime_for_harness()
        self.assertIsInstance(router, Router)
        names = [b.name for b in router.backends]
        for expected in [
            "claude", "openai", "ollama", "groq", "deepseek", "grok",
            "gemini", "kimi", "mistral", "together", "cerebras",
            "perplexity", "openrouter", "orcarouter",
        ]:
            self.assertIn(expected, names)
        self.assertEqual(len(names), 14)


# Late import so unittest.mock is available without being at module top.
import unittest.mock  # noqa: E402


if __name__ == "__main__":
    unittest.main()
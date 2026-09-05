"""BugWolf pluggable LLM runtime.

Phase 1.1: adds an additive backend abstraction layer that can actually
invoke models.  Existing ``tools.core.model_router`` (advisory tier
classification) is preserved unchanged.
"""
from __future__ import annotations

from typing import Iterable, List, Optional

from bugwolf.runtime.backends import SCHEMA
from bugwolf.runtime.backends.base import (
    BackendHealth,
    BaseBackend,
    CompletionChunk,
    CompletionResult,
    EmbeddingResult,
    HTTPClientMixin,
    JudgeResult,
)
from bugwolf.runtime.backends.cerebras import CerebrasBackend
from bugwolf.runtime.backends.claude import ClaudeBackend
from bugwolf.runtime.backends.deepseek import DeepSeekBackend
from bugwolf.runtime.backends.gemini import GeminiBackend
from bugwolf.runtime.backends.grok import GrokBackend
from bugwolf.runtime.backends.groq import GroqBackend
from bugwolf.runtime.backends.kimi import KimiBackend
from bugwolf.runtime.backends.mistral import MistralBackend
from bugwolf.runtime.backends.ollama import OllamaBackend
from bugwolf.runtime.backends.openai import OpenAIBackend
from bugwolf.runtime.backends.openrouter import OpenRouterBackend
from bugwolf.runtime.backends.orcarouter import OrcaRouterBackend
from bugwolf.runtime.backends.perplexity import PerplexityBackend
from bugwolf.runtime.backends.router import (
    DEFAULT_QUALITY_BAR,
    QUALITY_RANK,
    Router,
)
from bugwolf.runtime.backends.together import TogetherBackend

__all__ = [
    "SCHEMA",
    "Router",
    "BaseBackend",
    "BackendHealth",
    "CompletionChunk",
    "CompletionResult",
    "EmbeddingResult",
    "HTTPClientMixin",
    "JudgeResult",
    "CerebrasBackend",
    "ClaudeBackend",
    "DeepSeekBackend",
    "GeminiBackend",
    "GrokBackend",
    "GroqBackend",
    "KimiBackend",
    "MistralBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "OpenRouterBackend",
    "OrcaRouterBackend",
    "PerplexityBackend",
    "TogetherBackend",
    "register_backend",
    "default_backends",
]


_REGISTRY: List[BaseBackend] = []


def register_backend(backend: BaseBackend) -> None:
    """Add ``backend`` to the global registry (idempotent on name)."""
    name = getattr(backend, "name", None)
    if not name:
        raise ValueError("backend must define a non-empty name")
    for existing in _REGISTRY:
        if getattr(existing, "name", None) == name:
            return
    _REGISTRY.append(backend)


def default_backends() -> List[BaseBackend]:
    """Return one of every shipped backend (14 total)."""
    return [
        ClaudeBackend(),
        OpenAIBackend(),
        OllamaBackend(),
        GroqBackend(),
        DeepSeekBackend(),
        GrokBackend(),
        GeminiBackend(),
        KimiBackend(),
        MistralBackend(),
        TogetherBackend(),
        CerebrasBackend(),
        PerplexityBackend(),
        OpenRouterBackend(),
        OrcaRouterBackend(),
    ]


# Seed the registry with the default set so callers can introspect it.
for _backend in default_backends():
    register_backend(_backend)
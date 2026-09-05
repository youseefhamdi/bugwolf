"""BugWolf pluggable LLM runtime backends."""
from __future__ import annotations

from bugwolf.runtime.backends.base import (
    SCHEMA,
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
from bugwolf.runtime.backends.together import TogetherBackend

__all__ = [
    "SCHEMA",
    "BackendHealth",
    "BaseBackend",
    "CerebrasBackend",
    "ClaudeBackend",
    "CompletionChunk",
    "CompletionResult",
    "DeepSeekBackend",
    "EmbeddingResult",
    "GeminiBackend",
    "GrokBackend",
    "GroqBackend",
    "HTTPClientMixin",
    "JudgeResult",
    "KimiBackend",
    "MistralBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "OpenRouterBackend",
    "OrcaRouterBackend",
    "PerplexityBackend",
    "TogetherBackend",
]
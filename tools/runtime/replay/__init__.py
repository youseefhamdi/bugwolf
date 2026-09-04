"""Replay engine: byte-exact sends, governed (master plan Phase 1).

Modules:
    message   -- byte-exact HTTP/1.1 Request/Response (framing observed, never resolved)
    encode    -- composable value-encoding pipelines
    apply     -- the mutation-op vocabulary over parsed messages
    governor  -- CircuitBreaker / AIMD limiter / token bucket / global budget
    backend_socket -- raw-socket sender under scope gate + governor
    observe   -- facts-only response observation (never verdicts)
    batch     -- compare (A/B credential+mutation) and sweep (one mutation x N) modes
    engine    -- facade: replay_request / replay_raw wired to the CLI + MCP bridge
"""

from tools.runtime.replay.engine import replay_request, replay_raw  # noqa: F401

SCHEMA = "bugwolf-replay/v1"

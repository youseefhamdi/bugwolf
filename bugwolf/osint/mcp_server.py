"""JSON-RPC 2.0 server (stdio) for the OSINT surface.

The MCP server exposes two methods:

  * ``osint.search(query: str, top_k: int = 10) -> Dict[str, Any]``
  * ``osint.scrape_channel(channel: str, target: str) -> Dict[str, Any]``

Stub-safe: when the server has not been started, calls return
``{"error": "MCP server not started"}`` rather than crashing.

Designed to run as a subprocess via ``python -m bugwolf.osint.mcp_server``.
The protocol is line-delimited JSON-RPC 2.0 over stdin/stdout.

No third-party deps.
"""

from __future__ import annotations

import dataclasses
import json
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

from .channels import (
    BilibiliChannel,
    ExaSearchChannel,
    GithubChannel,
    RedditChannel,
    RssChannel,
    TwitterChannel,
    WebChannel,
    YoutubeChannel,
)


SCHEMA = "bugwolf-osint-mcp-v1"
JSONRPC_VERSION = "2.0"

_STARTED = False
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Channel registry
# ---------------------------------------------------------------------------


def _channel_registry() -> Dict[str, Any]:
    return {
        "reddit": RedditChannel,
        "twitter": TwitterChannel,
        "github": GithubChannel,
        "youtube": YoutubeChannel,
        "bilibili": BilibiliChannel,
        "rss": RssChannel,
        "web": WebChannel,
        "exa_search": ExaSearchChannel,
    }


def _make_channel(name: str) -> Any:
    registry = _channel_registry()
    cls = registry.get(name.lower())
    if cls is None:
        return None
    return cls()


# ---------------------------------------------------------------------------
# RPC handlers
# ---------------------------------------------------------------------------


def _osint_search(params: Dict[str, Any]) -> Dict[str, Any]:
    query = str(params.get("query") or "")
    top_k = int(params.get("top_k") or 10)
    registry = _channel_registry()
    out: List[Dict[str, Any]] = []
    for name in sorted(registry.keys()):
        channel = registry[name]()
        try:
            findings = channel.scrape(query, budget=top_k)
        except Exception as exc:  # noqa: BLE001
            out.append({"channel": name, "error": repr(exc)})
            continue
        out.append({
            "channel": name,
            "count": len(findings),
            "items": [dataclasses.asdict(f) for f in findings],
        })
    return {
        "schema": SCHEMA,
        "query": query,
        "top_k": top_k,
        "channels": out,
    }


def _osint_scrape_channel(params: Dict[str, Any]) -> Dict[str, Any]:
    channel_name = str(params.get("channel") or "")
    target = str(params.get("target") or "")
    budget = int(params.get("budget") or 50)
    channel = _make_channel(channel_name)
    if channel is None:
        return {"error": f"unknown channel {channel_name!r}",
                "schema": SCHEMA}
    findings = channel.scrape(target, budget=budget)
    return {
        "schema": SCHEMA,
        "channel": channel_name,
        "target": target,
        "count": len(findings),
        "items": [dataclasses.asdict(f) for f in findings],
    }


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "osint.search": _osint_search,
    "osint.scrape_channel": _osint_scrape_channel,
}


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------


def _make_response(req: Dict[str, Any],
                   result: Optional[Dict[str, Any]] = None,
                   error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": req.get("id"),
        "result": result,
        "error": error,
    }


def _handle_line(line: str) -> Optional[Dict[str, Any]]:
    """Process one line of JSON-RPC.  Returns the response (or None)."""
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        return _make_response(
            {"id": None},
            error={"code": -32700, "message": "parse error"},
        )
    if not isinstance(req, dict):
        return _make_response(
            {"id": None},
            error={"code": -32600, "message": "invalid request"},
        )
    if req.get("jsonrpc") != JSONRPC_VERSION:
        return _make_response(
            req,
            error={"code": -32600, "message": "jsonrpc must be 2.0"},
        )
    method = str(req.get("method") or "")
    params = req.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    handler = HANDLERS.get(method)
    if handler is None:
        return _make_response(
            req,
            error={"code": -32601, "message": f"unknown method {method!r}"},
        )
    try:
        result = handler(params)
    except Exception as exc:  # noqa: BLE001
        return _make_response(
            req,
            error={"code": -32603, "message": repr(exc)},
        )
    return _make_response(req, result=result)


def serve_stdio(*, input_stream: Optional[Any] = None,
                output_stream: Optional[Any] = None,
                oneshot: bool = False) -> int:
    """Run the JSON-RPC server on stdio (or test streams).

    Parameters
    ----------
    input_stream:
        File-like object to read JSON-RPC lines from (default: stdin).
    output_stream:
        File-like object to write JSON-RPC responses to (default: stdout).
    oneshot:
        If True, return after the first message instead of looping.
    """
    global _STARTED
    in_ = input_stream if input_stream is not None else sys.stdin
    out_ = output_stream if output_stream is not None else sys.stdout
    with _LOCK:
        _STARTED = True
    for line in in_:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        line = line.strip()
        if not line:
            continue
        resp = _handle_line(line)
        if resp is None:
            continue
        out_.write(json.dumps(resp, ensure_ascii=False) + "\n")
        out_.flush()
        if oneshot:
            break
    return 0


def is_started() -> bool:
    with _LOCK:
        return bool(_STARTED)


def not_started_response() -> Dict[str, Any]:
    """Returned by the MCP client when the server is not running."""
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": None,
        "result": None,
        "error": {"code": -32000,
                  "message": "MCP server not started",
                  "data": {"schema": SCHEMA}},
    }


def main(argv: Optional[List[str]] = None) -> int:  # noqa: ARG001
    """Entry point — ``python -m bugwolf.osint.mcp_server``."""
    return serve_stdio()


__all__ = [
    "SCHEMA",
    "JSONRPC_VERSION",
    "serve_stdio",
    "is_started",
    "not_started_response",
    "HANDLERS",
    "main",
]
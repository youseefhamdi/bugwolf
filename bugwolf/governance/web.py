"""FastAPI control plane (Phase 1.4 — Governance Core).

Minimal HTTP control plane exposing:

  * ``GET  /healthz``              → liveness probe
  * ``GET  /state/{mission_id}``   → mission state JSON
  * ``POST /approvals``            → create a new approval
  * ``GET  /decisions/recent?n=20`` → last N routing decisions

Routes require the ``X-Outrider-Control-Token`` header (read from the
``OUTRIDER_CONTROL_TOKEN`` env var).  Missing or wrong header → 401
(fail-closed).  Every response carries a
``Content-Security-Policy: default-src 'self'`` header.

If FastAPI is not installed, :class:`_StubFastAPI` provides just enough
shape for callers that import ``app`` at module level (e.g. tests using
``mock.patch``).

No external deps; stdlib only.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import os
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"

CSP_HEADER = "default-src 'self'"

DEFAULT_ROUTING_DECISIONS = 20


# ---------------------------------------------------------------------------
# FastAPI / stub fallback
# ---------------------------------------------------------------------------

try:  # pragma: no cover — exercised via tests with mock.patch
    fastapi_module = importlib.import_module("fastapi")
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover — fallback path
    fastapi_module = None
    _FASTAPI_AVAILABLE = False


def _has_fastapi() -> bool:
    return _FASTAPI_AVAILABLE and fastapi_module is not None


# ---------------------------------------------------------------------------
# Stub FastAPI — minimal shape used by tests and offline harnesses.
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, payload: Any, status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None) -> None:
        self.payload = payload
        self.status_code = int(status_code)
        self.headers = dict(headers or {})

    def to_payload(self) -> Any:
        return self.payload


class _StubRoute:
    def __init__(self, path: str, method: str, handler: Callable[..., Any]) -> None:
        self.path = path
        self.method = method.upper()
        self.handler = handler


class _StubFastAPI:
    def __init__(self, schema: str = _SCHEMA) -> None:
        self._schema = schema
        self._routes: List[_StubRoute] = []
        self._middleware: List[Callable[..., Any]] = []

    # -- route registration (mirror FastAPI's surface enough for tests) ---

    def add_api_route(self, path: str, handler: Callable[..., Any],
                      methods: Optional[List[str]] = None) -> None:
        for method in (methods or ["GET"]):
            self._routes.append(_StubRoute(path, method, handler))

    def get(self, path: str) -> "callable":
        def _register(handler: Callable[..., Any]) -> Callable[..., Any]:
            self.add_api_route(path, handler, methods=["GET"])
            return handler
        return _register

    def post(self, path: str) -> "callable":
        def _register(handler: Callable[..., Any]) -> Callable[..., Any]:
            self.add_api_route(path, handler, methods=["POST"])
            return handler
        return _register

    def middleware(self, _kind: str) -> "callable":
        def _register(fn: Callable[..., Any]) -> Callable[..., Any]:
            self._middleware.append(fn)
            return fn
        return _register

    # -- invocation helpers used by tests --------------------------------

    @property
    def routes(self) -> List[_StubRoute]:
        return list(self._routes)

    def handle(self, method: str, path: str,
               headers: Optional[Dict[str, str]] = None,
               json_body: Any = None) -> _StubResponse:
        """Invoke the matching route (first match wins)."""
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        method = method.upper()
        for route in self._routes:
            if route.method != method:
                continue
            params = _match_path(route.path, path)
            if params is None:
                continue
            return self._invoke(route, headers=headers, json_body=json_body,
                                path_params=params)
        return _StubResponse({"error": "not found", "schema": self._schema},
                             status_code=404,
                             headers={"Content-Security-Policy": CSP_HEADER})

    def _invoke(self, route: _StubRoute, *, headers: Dict[str, str],
                json_body: Any, path_params: Optional[Dict[str, str]] = None) -> _StubResponse:
        from . import web as _web  # avoid cycles
        request = _web._StubRequest(headers=headers, json_body=json_body,
                                     path=route.path, method=route.method)
        if path_params:
            request.path_params = dict(path_params)
        else:
            request.path_params = {}
        try:
            response = route.handler(request)
        except _web._HTTPError as exc:
            return _StubResponse(
                {"error": exc.reason, "schema": self._schema},
                status_code=exc.status_code,
                headers={"Content-Security-Policy": CSP_HEADER,
                         **exc.headers},
            )
        if not isinstance(response, _StubResponse):
            response = _StubResponse(response)
        response.headers.setdefault("Content-Security-Policy", CSP_HEADER)
        return response


class _StubRequest:
    def __init__(self, *, headers: Dict[str, str], json_body: Any,
                 path: str, method: str) -> None:
        self.headers = headers
        self._json = json_body
        self.path = path
        self.method = method
        self.query_params: Dict[str, str] = {}
        self.path_params: Dict[str, str] = {}

    def json(self) -> Any:
        return self._json


def _match_path(template: str, path: str) -> Optional[Dict[str, str]]:
    """Match a FastAPI-style ``{param}`` template; return extracted params."""
    t_parts = [p for p in template.split("/") if p != ""]
    p_parts = [p for p in path.split("/") if p != ""]
    if len(t_parts) != len(p_parts):
        return None
    params: Dict[str, str] = {}
    for t, p in zip(t_parts, p_parts):
        if t.startswith("{") and t.endswith("}"):
            params[t[1:-1]] = p
        elif t != p:
            return None
    return params


class _HTTPError(Exception):
    def __init__(self, status_code: int, reason: str,
                 headers: Optional[Dict[str, str]] = None) -> None:
        self.status_code = int(status_code)
        self.reason = str(reason)
        self.headers = dict(headers or {})
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Token + decision registry
# ---------------------------------------------------------------------------


class _DecisionRegistry:
    """Bounded deque of recent routing decisions."""

    def __init__(self, *, max_size: int = 1000) -> None:
        self._items: Deque[Dict[str, Any]] = deque(maxlen=int(max_size))

    def push(self, decision: Mapping[str, Any]) -> None:
        self._items.append(dict(decision))

    def recent(self, n: int) -> List[Dict[str, Any]]:
        if n <= 0:
            return []
        items = list(self._items)[-int(n):]
        items.reverse()
        return items


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _expected_token() -> Optional[str]:
    return os.environ.get("OUTRIDER_CONTROL_TOKEN") or None


def _constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _token_ok(headers: Mapping[str, str]) -> bool:
    expected = _expected_token()
    if expected is None:
        return False
    supplied = headers.get("x-outrider-control-token")
    if not supplied:
        return False
    return _constant_time_equals(supplied, expected)


def _build_decisions() -> _DecisionRegistry:
    return _DecisionRegistry()


def _make_app(using_fastapi: bool = False) -> Any:
    """Construct the control-plane app (real FastAPI or stub)."""
    if using_fastapi and fastapi_module is not None:
        return fastapi_module.FastAPI()

    app = _StubFastAPI()
    decisions = _build_decisions()
    app._decisions = decisions  # type: ignore[attr-defined]

    def _wrap(handler: Callable[..., Any]) -> Callable[..., Any]:
        def inner(request: Any, *args: Any, **kwargs: Any) -> Any:
            headers = getattr(request, "headers", {}) or {}
            if not _token_ok(headers):
                raise _HTTPError(
                    401,
                    reason="missing or invalid X-Outrider-Control-Token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return handler(request, *args, **kwargs)
        inner.__wrapped__ = handler  # type: ignore[attr-defined]
        return inner

    @app.get("/healthz")
    def healthz(request: Any) -> Any:
        return _stub_json(_wrap(_healthz_handler)(request))

    @app.get("/state/{mission_id}")
    def state_for(request: Any, mission_id: str = "") -> Any:
        params = getattr(request, "path_params", {}) or {}
        mid = params.get("mission_id") or mission_id
        return _stub_json(_wrap(lambda req: _state_handler(req, mid))(request))

    @app.post("/approvals")
    def create_approval(request: Any) -> Any:
        return _stub_json(_wrap(_approvals_handler)(request))

    @app.get("/decisions/recent")
    def decisions_recent(request: Any) -> Any:
        return _stub_json(_wrap(_decisions_recent_handler)(request))

    app._handle_token = _token_ok  # type: ignore[attr-defined]
    return app


# Use FastAPI when installed, otherwise the stub.  We keep both behind the
# ``app`` symbol so external callers can ``from bugwolf.governance.web
# import app`` without conditional imports.
if _FASTAPI_AVAILABLE:
    app = _make_app(using_fastapi=True)

    @app.get("/healthz")  # type: ignore[no-redef]
    def healthz() -> Dict[str, Any]:  # pragma: no cover - real FastAPI path
        return _healthz_handler(None)

    @app.get("/state/{mission_id}")  # type: no redef
    def state_for(mission_id: str) -> Dict[str, Any]:  # pragma: no cover
        return _state_handler(None, mission_id)

    @app.post("/approvals")  # type: no redef
    async def create_approval(request: Any) -> Dict[str, Any]:  # pragma: no cover
        body = await request.json() if hasattr(request, "json") else {}
        return _approvals_handler_body(body)

    @app.get("/decisions/recent")  # type: no redef
    def decisions_recent(n: int = DEFAULT_ROUTING_DECISIONS) -> Dict[str, Any]:
        return _decisions_recent_handler_body(n)

    @app.middleware("http")  # type: no redef
    async def _token_middleware(request: Any, call_next: Any) -> Any:  # pragma: no cover
        headers = {k.lower(): v for k, v in request.headers.items()}
        if not _token_ok(headers):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"error": "missing or invalid "
                                   "X-Outrider-Control-Token",
                         "schema": SCHEMA},
                headers={"WWW-Authenticate": "Bearer",
                         "Content-Security-Policy": CSP_HEADER},
            )
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP_HEADER)
        return response
else:
    app = _make_app(using_fastapi=False)


# ---------------------------------------------------------------------------
# Shared handlers (used by both stub and real FastAPI)
# ---------------------------------------------------------------------------


def _healthz_handler(_request: Any) -> Dict[str, Any]:
    return {"status": "ok", "version": SCHEMA}


def _state_handler(_request: Any, mission_id: str) -> Dict[str, Any]:
    from .state import MissionStateMachine, SCHEMA as STATE_SCHEMA
    try:
        machine = MissionStateMachine(target="unknown-target",
                                       mission_id=mission_id)
    except Exception:  # noqa: BLE001
        machine = None  # type: ignore[assignment]
    if machine is None:
        return {
            "schema": SCHEMA,
            "mission_id": mission_id,
            "state": "UNKNOWN",
            "target": "",
        }
    return {
        "schema": SCHEMA,
        "mission_id": mission_id,
        "state": machine.state.value,
        "target": machine.target,
        "state_schema": STATE_SCHEMA,
    }


def _approvals_handler_body(body: Mapping[str, Any]) -> Dict[str, Any]:
    from .approval import Approval
    target = str(body.get("target") or "")
    action = str(body.get("action") or "")
    if not target or not action:
        raise _HTTPError(400, reason="target and action are required")
    method = str(body.get("method") or "")
    endpoint = str(body.get("endpoint") or "")
    scope_file_sha256 = str(body.get("scope_file_sha256") or "")
    ttl = body.get("ttl_seconds")
    ttl_int = int(ttl) if ttl is not None else None
    store = Approval()
    pending = store.request(
        target=target,
        action=action,
        method=method,
        endpoint=endpoint,
        scope_file_sha256=scope_file_sha256,
        ttl_seconds=ttl_int,
    )
    granted = store.grant(pending.approval_id, target=target)
    return {
        "schema": SCHEMA,
        "approval_id": granted.approval_id,
        "status": granted.status,
        "expires_at": granted.expires_at,
    }


def _approvals_handler(request: Any) -> Dict[str, Any]:
    try:
        body = request.json() or {}
    except Exception:  # noqa: BLE001
        body = {}
    if not isinstance(body, dict):
        body = {}
    return _approvals_handler_body(body)


def _decisions_recent_handler_body(n: int) -> Dict[str, Any]:
    decisions = getattr(app, "_decisions", None)
    if decisions is None:
        return {"schema": SCHEMA, "decisions": []}
    return {"schema": SCHEMA, "decisions": decisions.recent(int(n))}


def _decisions_recent_handler(request: Any) -> Dict[str, Any]:
    n = DEFAULT_ROUTING_DECISIONS
    qp = getattr(request, "query_params", {}) or {}
    if "n" in qp:
        try:
            n = int(qp["n"])
        except (TypeError, ValueError):
            n = DEFAULT_ROUTING_DECISIONS
    return _decisions_recent_handler_body(n)


def _stub_json(payload: Any) -> Any:
    if not isinstance(payload, _StubResponse):
        return _StubResponse(payload)
    return payload


def record_decision(decision: Mapping[str, Any]) -> None:
    """Push a routing decision onto the in-memory ring buffer."""
    decisions = getattr(app, "_decisions", None)
    if decisions is None:
        decisions = _build_decisions()
        try:
            app._decisions = decisions  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return
    decisions.push(decision)


def fingerprint(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical form of ``payload`` (helper for tests)."""
    return hashlib.sha256(
        json.dumps(dict(payload), sort_keys=True,
                   separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


__all__ = [
    "SCHEMA",
    "CSP_HEADER",
    "app",
    "record_decision",
    "fingerprint",
]
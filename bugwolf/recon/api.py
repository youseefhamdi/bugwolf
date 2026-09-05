"""FastAPI control plane for the recon subsystem (port :8811).

Phase 2.5 additive module.  Does NOT modify any pre-existing module.

Routes:

  * ``GET  /healthz``                          → liveness probe
  * ``POST /targets``                          → create a target record
  * ``GET  /targets/{target}/workflows``       → list workflows
  * ``POST /targets/{target}/run``             → kick off a workflow run
  * ``GET  /runs/{run_id}``                    → run status
  * ``GET  /runs/{run_id}/results``            → results JSON
  * ``POST /runs/{run_id}/cancel``             → cancel a run

Auth: requires the ``X-Outrider-Control-Token`` header (read from the
``OUTRIDER_CONTROL_TOKEN`` env var).  Missing → 401 fail-closed.  Every
response carries ``Content-Security-Policy: default-src 'self'``.

If FastAPI is not installed, ``_StubFastAPI`` provides just enough
shape for callers that import ``app`` at module level (e.g. tests
using ``mock.patch``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import importlib
import json
import os
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from . import SCHEMA as _SCHEMA
from .orchestrator import (
    DEFAULT_STATE_DIR,
    DEFAULT_WORKFLOW_DIR,
    ReconOrchestrator,
    discover_workflows,
    load_workflow,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


CSP_HEADER = "default-src 'self'"
AUTH_HEADER = "X-Outrider-Control-Token"
TOKEN_ENV_VAR = "OUTRIDER_CONTROL_TOKEN"

# Module starts a fresh clock so /healthz can report uptime.
_MODULE_START = time.monotonic()

# In-memory run registry — keyed by run_id (uuid4 string).
_RUN_LOCK = threading.Lock()
_RUN_REGISTRY: Dict[str, "ReconRun"] = {}

_TARGET_LOCK = threading.Lock()
_TARGETS: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# FastAPI / stub fallback (mirrors governance/web.py)
# ---------------------------------------------------------------------------


try:  # pragma: no cover — exercised via tests with mock.patch
    fastapi_module = importlib.import_module("fastapi")
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover — fallback path
    fastapi_module = None
    _FASTAPI_AVAILABLE = False


def _has_fastapi() -> bool:
    return _FASTAPI_AVAILABLE and fastapi_module is not None


class _StubResponse:
    def __init__(self, payload: Any, status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None) -> None:
        self.payload = payload
        self.status_code = int(status_code)
        self.headers = dict(headers or {})

    def to_payload(self) -> Any:
        return self.payload


class _StubRoute:
    def __init__(self, path: str, method: str,
                 handler: Callable[..., Any]) -> None:
        self.path = path
        self.method = method.upper()
        self.handler = handler


class _StubFastAPI:
    def __init__(self, schema: str = _SCHEMA) -> None:
        self._schema = schema
        self._routes: List[_StubRoute] = []
        self._middleware: List[Callable[..., Any]] = []

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

    @property
    def routes(self) -> List[_StubRoute]:
        return list(self._routes)

    def handle(self, method: str, path: str,
               headers: Optional[Dict[str, str]] = None,
               json_body: Any = None) -> _StubResponse:
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        method = method.upper()
        for route in self._routes:
            if route.method != method:
                continue
            params = _match_path(route.path, path)
            if params is None:
                continue
            return self._invoke(route, headers=headers,
                                json_body=json_body, path_params=params)
        return _StubResponse(
            {"error": "not found", "schema": self._schema},
            status_code=404,
            headers={"Content-Security-Policy": CSP_HEADER},
        )

    def _invoke(self, route: _StubRoute, *, headers: Dict[str, str],
                json_body: Any,
                path_params: Optional[Dict[str, str]] = None) -> _StubResponse:
        request = _StubRequest(headers=headers, json_body=json_body,
                                path=route.path, method=route.method)
        request.path_params = dict(path_params or {})
        request.query_params = {}
        try:
            response = route.handler(request)
        except _HTTPError as exc:
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
# Token + run helpers
# ---------------------------------------------------------------------------


def _expected_token() -> Optional[str]:
    return os.environ.get(TOKEN_ENV_VAR) or None


def _constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _token_ok(headers: Dict[str, str]) -> bool:
    expected = _expected_token()
    if expected is None:
        return False
    supplied = headers.get("x-outrider-control-token") \
        or headers.get(AUTH_HEADER) or ""
    if not supplied:
        return False
    return _constant_time_equals(supplied, expected)


def _unauthorized() -> _HTTPError:
    return _HTTPError(
        401,
        reason=f"missing or invalid {AUTH_HEADER}",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Run model
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ReconRun:
    """A single workflow run, tracked in-memory and journal-backed."""
    run_id: str
    target: str
    workflows: List[str]
    status: str = "PENDING"      # PENDING / RUNNING / COMPLETED / FAILED / CANCELLED
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    orchestrator: Optional[ReconOrchestrator] = None
    cancel_event: Optional[threading.Event] = None


def _new_run(target: str, workflows: List[str]) -> ReconRun:
    rid = str(uuid.uuid4())
    run = ReconRun(
        run_id=rid, target=target, workflows=list(workflows),
        cancel_event=threading.Event(),
    )
    with _RUN_LOCK:
        _RUN_REGISTRY[rid] = run
    return run


def _get_run(run_id: str) -> Optional[ReconRun]:
    with _RUN_LOCK:
        return _RUN_REGISTRY.get(run_id)


def _uptime_seconds() -> float:
    return time.monotonic() - _MODULE_START


# ---------------------------------------------------------------------------
# Shared handlers
# ---------------------------------------------------------------------------


def _healthz_handler(_request: Any) -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": _SCHEMA,
        "uptime_seconds": _uptime_seconds(),
        "fastapi": _has_fastapi(),
    }


def _create_target_handler(request: Any) -> Dict[str, Any]:
    body = _safe_json(request) or {}
    target = str(body.get("target") or "").strip()
    if not target:
        raise _HTTPError(400, reason="target is required")
    scope = str(body.get("scope") or "")
    workflows = body.get("workflows") or ["full_recon"]
    if isinstance(workflows, str):
        workflows = [workflows]
    with _TARGET_LOCK:
        _TARGETS[target] = {
            "target": target,
            "scope": scope,
            "workflows": workflows,
            "created_at": _now_iso(),
        }
    return {
        "schema": _SCHEMA,
        "target": target,
        "scope": scope,
        "workflows": workflows,
    }


def _list_workflows_handler(request: Any) -> Dict[str, Any]:
    target = request.path_params.get("target", "")
    base = DEFAULT_WORKFLOW_DIR
    found = discover_workflows(base)
    workflows: List[Dict[str, Any]] = []
    for name, path in sorted(found.items()):
        try:
            parsed = load_workflow(path)
        except Exception as exc:  # noqa: BLE001
            workflows.append({
                "name": name, "valid": False, "error": str(exc),
            })
            continue
        workflows.append({
            "name": name,
            "schema": parsed.get("schema"),
            "phases": len(parsed.get("phases") or []),
            "valid": True,
        })
    return {
        "schema": _SCHEMA,
        "target": target,
        "workflows": workflows,
        "count": len(workflows),
    }


def _kickoff_run_handler(request: Any) -> Dict[str, Any]:
    target = request.path_params.get("target", "")
    body = _safe_json(request) or {}
    workflows = body.get("workflows")
    if not workflows:
        with _TARGET_LOCK:
            rec = _TARGETS.get(target, {})
        workflows = rec.get("workflows") or ["full_recon"]
    if isinstance(workflows, str):
        workflows = [workflows]
    max_concurrent = int(body.get("max_concurrent") or 4)

    run = _new_run(target=target, workflows=list(workflows))
    run.status = "RUNNING"
    run.started_at = _now_iso()
    orch = ReconOrchestrator(
        target=target,
        scope_file=str(body.get("scope") or ""),
        max_concurrent=max_concurrent,
    )
    run.orchestrator = orch
    try:
        orch.plan(workflows)
        report = orch.run(timeout=body.get("timeout"))
        run.status = "COMPLETED"
        run.finished_at = _now_iso()
        return {
            "schema": _SCHEMA,
            "run_id": run.run_id,
            "target": target,
            "workflows": workflows,
            "status": run.status,
            "report": dataclasses.asdict(report),
        }
    except Exception as exc:  # noqa: BLE001
        run.status = "FAILED"
        run.error = repr(exc)
        run.finished_at = _now_iso()
        raise _HTTPError(500, reason=f"recon run failed: {exc!r}")


def _run_status_handler(request: Any) -> Dict[str, Any]:
    run_id = request.path_params.get("run_id", "")
    run = _get_run(run_id)
    if run is None:
        raise _HTTPError(404, reason=f"unknown run_id {run_id!r}")
    out = {
        "schema": _SCHEMA,
        "run_id": run_id,
        "target": run.target,
        "workflows": run.workflows,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "error": run.error,
    }
    if run.orchestrator is not None:
        out["status_map"] = run.orchestrator.status()
    return out


def _run_results_handler(request: Any) -> Dict[str, Any]:
    run_id = request.path_params.get("run_id", "")
    run = _get_run(run_id)
    if run is None:
        raise _HTTPError(404, reason=f"unknown run_id {run_id!r}")
    if run.orchestrator is None:
        return {
            "schema": _SCHEMA,
            "run_id": run_id,
            "status": run.status,
            "jobs": [],
            "findings": [],
            "journal": [],
        }
    return {
        "schema": _SCHEMA,
        "run_id": run_id,
        "status": run.status,
        "jobs": [dataclasses.asdict(j) for j in run.orchestrator.jobs],
        "findings": [dataclasses.asdict(f) for f in []],
    }


def _run_cancel_handler(request: Any) -> Dict[str, Any]:
    run_id = request.path_params.get("run_id", "")
    run = _get_run(run_id)
    if run is None:
        raise _HTTPError(404, reason=f"unknown run_id {run_id!r}")
    if run.orchestrator is not None:
        for job in run.orchestrator.jobs:
            run.orchestrator.cancel(job.job_id)
    if run.cancel_event is not None:
        run.cancel_event.set()
    run.status = "CANCELLED"
    return {
        "schema": _SCHEMA,
        "run_id": run_id,
        "status": run.status,
        "cancelled": True,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _safe_json(request: Any) -> Optional[Dict[str, Any]]:
    if request is None:
        return None
    try:
        body = request.json()
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(body, dict):
        return None
    return body


def _stub_json(payload: Any) -> Any:
    if not isinstance(payload, _StubResponse):
        return _StubResponse(payload)
    return payload


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _make_app(using_fastapi: bool = False) -> Any:
    if using_fastapi and fastapi_module is not None:
        return fastapi_module.FastAPI()

    app = _StubFastAPI()

    def _wrap(handler: Callable[..., Any]) -> Callable[..., Any]:
        def inner(request: Any, *args: Any, **kwargs: Any) -> Any:
            headers = getattr(request, "headers", {}) or {}
            if not _token_ok(dict(headers)):
                raise _unauthorized()
            return handler(request, *args, **kwargs)
        inner.__wrapped__ = handler  # type: ignore[attr-defined]
        return inner

    @app.get("/healthz")
    def healthz(request: Any) -> Any:
        # /healthz is allowed without token — useful for liveness probes.
        return _stub_json(_healthz_handler(request))

    @app.post("/targets")
    def create_target(request: Any) -> Any:
        return _stub_json(_wrap(_create_target_handler)(request))

    @app.get("/targets/{target}/workflows")
    def list_workflows(request: Any) -> Any:
        return _stub_json(_wrap(_list_workflows_handler)(request))

    @app.post("/targets/{target}/run")
    def kickoff_run(request: Any) -> Any:
        return _stub_json(_wrap(_kickoff_run_handler)(request))

    @app.get("/runs/{run_id}")
    def run_status(request: Any) -> Any:
        return _stub_json(_wrap(_run_status_handler)(request))

    @app.get("/runs/{run_id}/results")
    def run_results(request: Any) -> Any:
        return _stub_json(_wrap(_run_results_handler)(request))

    @app.post("/runs/{run_id}/cancel")
    def run_cancel(request: Any) -> Any:
        return _stub_json(_wrap(_run_cancel_handler)(request))

    app._handle_token = _token_ok  # type: ignore[attr-defined]
    return app


# Build the app at import time — both stub and real FastAPI variants.
if _FASTAPI_AVAILABLE:
    app = _make_app(using_fastapi=True)

    @app.get("/healthz")  # type: ignore[no-redef]
    def healthz() -> Dict[str, Any]:  # pragma: no cover - real FastAPI path
        return _healthz_handler(None)

    @app.post("/targets")  # type: no redef
    async def create_target(request: Any) -> Dict[str, Any]:  # pragma: no cover
        body = await request.json() if hasattr(request, "json") else {}
        return _create_target_handler_body(body)

    @app.get("/targets/{target}/workflows")  # type: no redef
    def list_workflows(target: str) -> Dict[str, Any]:  # pragma: no cover
        return _list_workflows_handler_body(target)

    @app.post("/targets/{target}/run")  # type: no redef
    async def kickoff_run(target: str, request: Any) -> Dict[str, Any]:  # pragma: no cover
        body = await request.json() if hasattr(request, "json") else {}
        return _kickoff_run_handler_body(target, body)

    @app.get("/runs/{run_id}")  # type: no redef
    def run_status(run_id: str) -> Dict[str, Any]:  # pragma: no cover
        return _run_status_handler_body(run_id)

    @app.get("/runs/{run_id}/results")  # type: no redef
    def run_results(run_id: str) -> Dict[str, Any]:  # pragma: no cover
        return _run_results_handler_body(run_id)

    @app.post("/runs/{run_id}/cancel")  # type: no redef
    async def run_cancel(run_id: str, request: Any) -> Dict[str, Any]:  # pragma: no cover
        body = await request.json() if hasattr(request, "json") else {}
        return _run_cancel_handler_body(run_id, body)

    @app.middleware("http")  # type: no redef
    async def _token_middleware(request: Any, call_next: Any) -> Any:  # pragma: no cover
        headers = {k.lower(): v for k, v in request.headers.items()}
        if not _token_ok(headers):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"error": f"missing or invalid {AUTH_HEADER}",
                         "schema": _SCHEMA},
                headers={"WWW-Authenticate": "Bearer",
                         "Content-Security-Policy": CSP_HEADER},
            )
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP_HEADER)
        return response
else:
    app = _make_app(using_fastapi=False)


# Body-only variants for the real FastAPI handlers (the body has already
# been parsed by the request.json() coroutine).
def _create_target_handler_body(body: Dict[str, Any]) -> Dict[str, Any]:
    return _create_target_handler(_StubRequest(
        headers={}, json_body=body, path="/targets", method="POST",
    ))


def _list_workflows_handler_body(target: str) -> Dict[str, Any]:
    req = _StubRequest(
        headers={}, json_body={},
        path=f"/targets/{target}/workflows", method="GET",
    )
    req.path_params = {"target": target}
    return _list_workflows_handler(req)


def _kickoff_run_handler_body(target: str, body: Dict[str, Any]) -> Dict[str, Any]:
    req = _StubRequest(
        headers={}, json_body=body,
        path=f"/targets/{target}/run", method="POST",
    )
    req.path_params = {"target": target}
    return _kickoff_run_handler(req)


def _run_status_handler_body(run_id: str) -> Dict[str, Any]:
    req = _StubRequest(
        headers={}, json_body={},
        path=f"/runs/{run_id}", method="GET",
    )
    req.path_params = {"run_id": run_id}
    return _run_status_handler(req)


def _run_results_handler_body(run_id: str) -> Dict[str, Any]:
    req = _StubRequest(
        headers={}, json_body={},
        path=f"/runs/{run_id}/results", method="GET",
    )
    req.path_params = {"run_id": run_id}
    return _run_results_handler(req)


def _run_cancel_handler_body(run_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    req = _StubRequest(
        headers={}, json_body=body,
        path=f"/runs/{run_id}/cancel", method="POST",
    )
    req.path_params = {"run_id": run_id}
    return _run_cancel_handler(req)


def fingerprint(payload: Dict[str, Any]) -> str:
    """SHA-256 over the canonical form of ``payload`` (helper for tests)."""
    return hashlib.sha256(
        json.dumps(dict(payload), sort_keys=True,
                   separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


__all__ = [
    "SCHEMA",
    "CSP_HEADER",
    "AUTH_HEADER",
    "TOKEN_ENV_VAR",
    "app",
    "ReconRun",
    "_FASTAPI_AVAILABLE",
    "fingerprint",
]
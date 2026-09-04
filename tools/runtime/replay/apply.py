#!/usr/bin/env python3
"""Mutation operations over byte-exact messages (Phase 1.2).

The documented mutation vocabulary from the master plan (15 ops;
set-path-param consolidates the positional and named variants).  Every op
mutates the parsed structure (never a string template), so prior byte-level
fidelity is preserved everywhere the op does not touch.  Payloads travel as
request DATA through this engine — replacing the curl-in-bash
confirm/weaponize path and its quoting/encoding hazards.

Ops:
    set-query / add-query / remove-query     query string surgery
    set-header / add-header / remove-header  header lines (position-preserving)
    set-body                                 replace the body wholesale
    set-method / set-target                  request line edits
    body-merge / body-set-field / body-remove-field   JSON body dot-path edits
    set-cookie / remove-cookie               cookie header convenience ops
    set-path-param                           positional path segment rewrite
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from tools.runtime.replay.message import Request
from tools.runtime.replay.encode import apply_pipeline

SCHEMA = "bugwolf-replay-apply/v1"

OPS = (
    "set-query", "add-query", "remove-query",
    "set-header", "add-header", "remove-header",
    "set-body", "set-method", "set-target",
    "body-merge", "body-set-field", "body-remove-field",
    "set-cookie", "remove-cookie", "set-path-param",
)


class ApplyError(ValueError):
    """A mutation could not be applied to the request."""


@dataclass
class Mutation:
    """One mutation op with its arguments (mirrors the tool surface schema)."""

    op: str
    name: Optional[str] = None          # param/header/cookie name or dot-path
    value: Optional[str] = None
    encode: Optional[List[str]] = None  # codec pipeline applied to value
    position: Optional[int] = None      # 0-based path segment for set-path-param
                                       # (counts the leading empty segment)

    def validated(self) -> "Mutation":
        if self.op not in OPS:
            raise ApplyError(f"unknown op {self.op!r} (known: {OPS})")
        if self.op in ("set-query", "add-query", "remove-query", "set-header",
                       "add-header", "body-set-field", "body-remove-field",
                       "set-cookie", "remove-cookie") \
                and not self.name:
            raise ApplyError(f"op {self.op!r} requires 'name'")
        if self.op == "set-path-param" \
                and self.position is None and not self.name:
            raise ApplyError(f"op {self.op!r} requires 'name' or 'position'")
        return self


def _encoded_value(mutation: Mutation) -> str:
    if mutation.value is None:
        return ""
    if not mutation.encode:
        return mutation.value
    return apply_pipeline(mutation.value, list(mutation.encode))


def _split_target(target: str) -> tuple:
    # requests carry an origin-form target: /path?query#frag
    frag = ""
    if "#" in target:
        target, _, frag = target.partition("#")
    if "?" in target:
        path, _, query = target.partition("?")
    else:
        path, query = target, ""
    return path, query, frag


def _join_target(path: str, query: str, frag: str) -> str:
    target = path + ("?" + query if query else "")
    return target + ("#" + frag if frag else "")


def _query_pairs(query: str) -> List[tuple]:
    pairs: List[tuple] = []
    for part in query.split("&"):
        if not part:
            continue
        key, _, val = part.partition("=")
        pairs.append((key, val))
    return pairs


def _render_query(pairs: List[tuple]) -> str:
    return "&".join(f"{key}={val}" if val != "" or True else key
                    for key, val in pairs)


# -- query ops ----------------------------------------------------------------

def _op_set_query(request: Request, mutation: Mutation) -> None:
    path, query, frag = _split_target(request.target)
    pairs = _query_pairs(query)
    new_key, new_val = mutation.name, _encoded_value(mutation)
    for idx, (key, _) in enumerate(pairs):
        if key == new_key:
            pairs[idx] = (key, new_val)
            break
    else:
        pairs.append((new_key, new_val))
    request.target = _join_target(path, _render_query(pairs), frag)


def _op_add_query(request: Request, mutation: Mutation) -> None:
    """Append a duplicate parameter (parameter-pollution probes)."""
    path, query, frag = _split_target(request.target)
    pairs = _query_pairs(query)
    pairs.append((mutation.name, _encoded_value(mutation)))
    request.target = _join_target(path, _render_query(pairs), frag)


def _op_remove_query(request: Request, mutation: Mutation) -> None:
    path, query, frag = _split_target(request.target)
    pairs = [(k, v) for k, v in _query_pairs(query) if k != mutation.name]
    request.target = _join_target(path, _render_query(pairs), frag)


# -- header ops ---------------------------------------------------------------

def _op_set_header(request: Request, mutation: Mutation) -> None:
    request.set_header(mutation.name, _encoded_value(mutation))


def _op_add_header(request: Request, mutation: Mutation) -> None:
    request.add_header(mutation.name, _encoded_value(mutation))


def _op_remove_header(request: Request, mutation: Mutation) -> None:
    request.remove_header(mutation.name)


# -- body ops -----------------------------------------------------------------

def _parse_json_body(request: Request) -> Dict[str, Any]:
    try:
        parsed = json.loads(request.body.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ApplyError("body is not a JSON object")
        return parsed
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApplyError("body is not valid JSON (use set-body instead)")


def _store_json_body(request: Request, payload: Dict[str, Any]) -> None:
    request.body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if request.get("content-type") is None:
        request.set_header("Content-Type", "application/json")
    # FRAMING REPAIR: the body just changed length; a stale Content-Length
    # makes the target wait for bytes that never arrive (hang → our own
    # timeout fact, and on keep-alive servers a request-smuggling-shaped
    # accident WE introduced).  Deliberate CL mismatches remain possible via
    # add-header; auto-repair applies only to ops that edit the body.
    if request.get("content-length") is not None:
        request.set_header("Content-Length", str(len(request.body)))


def _dot_get(payload: Dict[str, Any], path: str) -> Any:
    node: Any = payload
    for segment in path.split("."):
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        else:
            return None
    return node


def _dot_set(payload: Dict[str, Any], path: str, value: Any) -> None:
    segments = path.split(".")
    node = payload
    for segment in segments[:-1]:
        child = node.get(segment)
        if not isinstance(child, dict):
            child = {}
            node[segment] = child
        node = child
    node[segments[-1]] = value


def _dot_remove(payload: Dict[str, Any], path: str) -> bool:
    segments = path.split(".")
    node = payload
    for segment in segments[:-1]:
        child = node.get(segment) if isinstance(node, dict) else None
        if not isinstance(child, dict):
            return False
        node = child
    return node.pop(segments[-1], None) is not None


def _op_body_merge(request: Request, mutation: Mutation) -> None:
    """JSON-merge a value into the body (value must be JSON text or scalar)."""
    payload = _parse_json_body(request)
    raw = _encoded_value(mutation)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    if not isinstance(value, dict):
        raise ApplyError("body-merge value must be a JSON object")
    payload.update(value)
    _store_json_body(request, payload)


def _op_body_set_field(request: Request, mutation: Mutation) -> None:
    payload = _parse_json_body(request)
    # Set the value EXACTLY as given (after its encode pipeline): a mutator
    # that silently JSON-coerces "1" to 1 changes the attack — type confusion
    # probes are body-merge's job, not this op's.
    _dot_set(payload, mutation.name, _encoded_value(mutation))
    _store_json_body(request, payload)


def _op_body_remove_field(request: Request, mutation: Mutation) -> None:
    payload = _parse_json_body(request)
    if not _dot_remove(payload, mutation.name):
        raise ApplyError(f"body path not found: {mutation.name!r}")
    _store_json_body(request, payload)


# -- request-line ops ----------------------------------------------------------

def _op_set_body(request: Request, mutation: Mutation) -> None:
    request.body = _encoded_value(mutation).encode("latin-1")
    if request.get("content-length") is not None:
        request.set_header("Content-Length", str(len(request.body)))


def _op_set_method(request: Request, mutation: Mutation) -> None:
    request.method = mutation.value.upper() if mutation.value else "GET"


def _op_set_target(request: Request, mutation: Mutation) -> None:
    request.target = _encoded_value(mutation)


def _op_set_path_param(request: Request, mutation: Mutation) -> None:
    """Rewrite the 0-based path segment (position counts the leading empty
    segment: in /rest/products/1/reviews the id '1' is position 3)."""
    path, query, frag = _split_target(request.target)
    position = int(mutation.position if mutation.position is not None
                   else (mutation.name if str(mutation.name or "").isdigit() else 0))
    segments = path.split("/")
    if position < 0 or position >= len(segments):
        raise ApplyError(
            f"path position {position} out of range (path has "
            f"{len(segments)} segments: {segments!r})")
    segments[position] = _encoded_value(mutation)
    request.target = _join_target("/".join(segments), query, frag)


# -- cookie ops -----------------------------------------------------------------

def _op_set_cookie(request: Request, mutation: Mutation) -> None:
    current = request.get("cookie") or ""
    key = mutation.name
    value = _encoded_value(mutation)
    pairs = [pair for pair in current.split("; ")
             if pair and not pair.startswith(f"{key}=")]
    pairs.append(f"{key}={value}")
    request.set_header("Cookie", "; ".join(pairs))


def _op_remove_cookie(request: Request, mutation: Mutation) -> None:
    current = request.get("cookie") or ""
    pairs = [pair for pair in current.split("; ")
             if pair and not pair.startswith(f"{mutation.name}=")]
    if pairs:
        request.set_header("Cookie", "; ".join(pairs))
    else:
        request.remove_header("Cookie")


_DISPATCH = {
    "set-query": _op_set_query,
    "add-query": _op_add_query,
    "remove-query": _op_remove_query,
    "set-header": _op_set_header,
    "add-header": _op_add_header,
    "remove-header": _op_remove_header,
    "set-body": _op_set_body,
    "set-method": _op_set_method,
    "set-target": _op_set_target,
    "body-merge": _op_body_merge,
    "body-set-field": _op_body_set_field,
    "body-remove-field": _op_body_remove_field,
    "set-cookie": _op_set_cookie,
    "remove-cookie": _op_remove_cookie,
    "set-path-param": _op_set_path_param,
}


def apply_mutations(request: Request,
                    mutations: List[Dict[str, Any]]) -> Request:
    """Apply mutations in order to a *fresh copy* of ``request``.

    The original request object is never mutated (compare sides depend on
    that).  Each mutation dict mirrors the tool-surface schema; values pass
    through their optional encode pipeline first.
    """
    clone = Request.from_bytes(request.to_bytes())
    clone._raw = None
    for spec in mutations or []:
        mutation = Mutation(
            op=str(spec.get("op") or ""),
            name=(str(spec["name"]) if spec.get("name") is not None else None),
            value=(str(spec["value"]) if spec.get("value") is not None else None),
            encode=([str(c) for c in spec["encode"]] if spec.get("encode") else None),
            position=(int(spec["position"]) if spec.get("position") is not None else None),
        ).validated()
        if mutation.op == "set-path-param" and mutation.position is None \
                and str(mutation.name or "").isdigit():
            mutation.position = int(mutation.name)  # name may carry the position
        try:
            _DISPATCH[mutation.op](clone, mutation)
        except ApplyError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface op failures precisely
            raise ApplyError(f"op {mutation.op!r} failed: {exc}") from exc
    return clone

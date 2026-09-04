#!/usr/bin/env python3
"""Compare and sweep batch modes (Phase 1.7).

compare  -- send the baseline and one-or-more mutated variants of the SAME
            captured request; each variant may carry its own mutations and
            (per-side) auth stance.  Output is the deterministic Delta per
            side.  This is the automation behind IDOR/authz diffs: same
            request, different credential or object id, measurable delta.

sweep    -- one mutation template applied across N parameter positions
            (query params, JSON body fields, path segments) — the sibling
            hunt: does the same injection land anywhere else?

Deterministic tier: sends happen through the governed backend only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from tools.runtime.replay.message import Request
from tools.runtime.replay.apply import apply_mutations
from tools.runtime.replay.backend_socket import SendResult, send_raw
from tools.runtime.replay.observe import diff

SCHEMA = "bugwolf-replay-batch/v1"


@dataclass
class CompareSide:
    """One side of a compare: which mutations (and which host) to use."""

    label: str
    mutations: List[Dict[str, Any]] = field(default_factory=list)
    host: Optional[str] = None          # defaults to the request's Host


@dataclass
class CompareReport:
    baseline: Dict[str, Any]
    sides: List[Dict[str, Any]]

    @property
    def differing(self) -> List[str]:
        return [side["label"] for side in self.sides
                if side["delta"]["differs"]]

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "mode": "compare",
            "baseline": self.baseline,
            "sides": self.sides,
            "differing": self.differing,
        }


def compare(request: Request, sides: List[CompareSide], *, host: Optional[str] = None,
            markers: Optional[List[str]] = None,
            send: Optional[Any] = None, **send_kwargs) -> CompareReport:
    """Baseline send + one send per side, then deterministic diffs.

    ``send`` is injectable for tests (defaults to the governed raw backend).
    """
    sender = send or send_raw
    target_host = host or request.host
    if not target_host:
        raise ValueError("request has no Host header and no host given")

    baseline_result: SendResult = sender(target_host, request.to_bytes(),
                                         **send_kwargs)
    report_sides: List[Dict[str, Any]] = []
    for side in sides:
        variant = apply_mutations(request, side.mutations)
        side_host = side.host or target_host
        side_result: SendResult = sender(side_host, variant.to_bytes(),
                                         **send_kwargs)
        report_sides.append({
            "label": side.label,
            "request_bytes": variant.to_bytes().decode("latin-1"),
            "delta": diff(baseline_result, side_result,
                          markers=markers).to_dict(),
        })
    baseline_obs = {
        "status": baseline_result.status,
        "body_bytes": len(baseline_result.body),
        "error": baseline_result.error,
    }
    return CompareReport(baseline=baseline_obs, sides=report_sides)


def sweep_positions(request: Request, *, op: str, value: str,
                    encode: Optional[List[str]] = None,
                    host: Optional[str] = None,
                    markers: Optional[List[str]] = None,
                    send: Optional[Any] = None,
                    **send_kwargs) -> List[Dict[str, Any]]:
    """Fire one mutation template across every position it can land on:

      * every existing query parameter name (set-query),
      * every top-level JSON body field (body-set-field),
      * every path segment position >= 1 (set-path-param).

    Returns per-position deltas against one shared baseline.  The unit of
    hunting is the intersection, not the endpoint — this is how "the bug on
    one endpoint chains into the identical pattern on every sibling".
    """
    sender = send or send_raw
    target_host = host or request.host
    if not target_host:
        raise ValueError("request has no Host header and no host given")

    baseline: SendResult = sender(target_host, request.to_bytes(), **send_kwargs)
    plans: List[Dict[str, Any]] = []

    path, _sep, query = request.target.partition("#")[0].partition("?")
    for key, _val in (pair.partition("=")[::2]
                      for pair in query.split("&") if pair):
        plans.append({"position": f"query:{key}",
                      "mutation": {"op": "set-query", "name": key,
                                   "value": value, "encode": encode}})
    try:
        import json
        body = json.loads(request.body.decode("utf-8"))
        if isinstance(body, dict):
            for key in body:
                plans.append({"position": f"body:{key}",
                              "mutation": {"op": "body-set-field", "name": key,
                                           "value": value, "encode": encode}})
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    for position in range(1, len(path.split("/"))):
        plans.append({"position": f"path:{position}",
                      "mutation": {"op": "set-path-param", "position": position,
                                   "value": value, "encode": encode}})

    results: List[Dict[str, Any]] = []
    for plan in plans:
        variant = apply_mutations(request, [plan["mutation"]])
        side_result: SendResult = sender(target_host, variant.to_bytes(),
                                         **send_kwargs)
        results.append({
            "position": plan["position"],
            "delta": diff(baseline, side_result, markers=markers).to_dict(),
        })
    return results

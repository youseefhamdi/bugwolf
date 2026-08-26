#!/usr/bin/env python3
"""Live sibling-differential runner for BugWolf's discovery core.

Replays the *same* request against paired surfaces (API v1/v2, web/mobile,
REST/GraphQL siblings) and scores live behavioral divergence. This is the
executor for the ``sibling_differential`` mutations the mutator emits, and the
live counterpart of the static ``differential.py`` detector.

Divergence scoring reuses the oracle's :func:`tools.observation.compute_metrics`
(status, body similarity, headers, timing, redirects, size) so the runner and
the observation layer share one definition of "a material delta".

The runner never performs HTTP itself: a ``transport`` callable (e.g. hunt.py's
``curl_fetch_observation`` wrapped by the execution controller) executes each
request and returns an :class:`tools.observation.HttpObservation`.

Usage:
  python3 tools/differential_runner.py --target T --urls-file recon/T/urls.txt --base-url https://target --scope-file scope.json --max-pairs 20 --json
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from tools.observation import HttpObservation, compute_metrics
    from tools.surface_model import (
        SurfaceModel, Operation, ParamLocation, load_surface,
    )
except ImportError:  # direct script execution
    from observation import HttpObservation, compute_metrics
    from surface_model import SurfaceModel, Operation, ParamLocation, load_surface

SCHEMA_VERSION = "bugwolf-differential-runner-v1"

# Divergence thresholds shared with the oracle's semantics.
_BODY_SIMILARITY_THRESHOLD = 0.98
_TIMING_RATIO_THRESHOLD = 3.0
_TIMING_ABS_THRESHOLD = 0.5


@dataclass
class SiblingRequest:
    operation_id: str
    url: str
    method: str
    params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DivergenceResult:
    pair_id: str
    a: SiblingRequest
    b: SiblingRequest
    score: float = 0.0                 # 0..1
    diverged: bool = False
    sibling_drift: bool = False
    deltas: Dict[str, Any] = field(default_factory=dict)
    a_status: int = 0
    b_status: int = 0
    body_similarity: float = 1.0
    timing_ratio: float = 1.0
    weaker_side: str = ""
    hypothesis: str = ""
    probe_suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


def score_divergence(a: HttpObservation, b: HttpObservation) -> Dict[str, Any]:
    """Score live divergence between two observations (0..1) with deltas.

    Status (0.25) and body (0.35) changes are decisive; headers/timing/redirect
    contribute but never trigger divergence on their own.
    """
    metrics = compute_metrics(a, b)
    score = 0.0
    deltas: Dict[str, Any] = {}

    if a.status != b.status:
        deltas["status"] = f"{a.status} != {b.status}"
        score += 0.25

    if not metrics.body_identical and metrics.body_similarity < _BODY_SIMILARITY_THRESHOLD:
        deltas["body"] = f"similarity {metrics.body_similarity}"
        score += 0.35

    if metrics.header_additions or metrics.header_removals:
        deltas["headers"] = {
            "added": metrics.header_additions,
            "removed": metrics.header_removals,
        }
        score += 0.20

    if metrics.redirect_delta:
        deltas["redirect"] = metrics.redirect_delta
        score += 0.10

    if (metrics.timing_ratio >= _TIMING_RATIO_THRESHOLD
            or metrics.timing_delta >= _TIMING_ABS_THRESHOLD):
        deltas["timing"] = (f"ratio {metrics.timing_ratio}x "
                            f"delta {metrics.timing_delta}s")
        score += 0.10

    return {
        "score": round(min(1.0, score), 2),
        "diverged": score >= 0.25,
        "deltas": deltas,
        "body_similarity": metrics.body_similarity,
        "timing_ratio": metrics.timing_ratio,
    }


def _weaker_side(a: HttpObservation, b: HttpObservation) -> str:
    """Which surface looks less protected (the drift's weak leg)."""
    a_ok = 200 <= a.status < 300
    b_ok = 200 <= b.status < 300
    if a_ok and not b_ok:
        return "a"
    if b_ok and not a_ok:
        return "b"
    return ""


def _default_value(param) -> str:
    if param.type == "integer":
        return "1"
    if param.type == "boolean":
        return "true"
    if param.enum:
        return str(param.enum[0])
    if param.default is not None:
        return str(param.default)
    return "test"


class DifferentialRunner:
    """Replay identical requests across sibling pairs and score divergence."""

    def __init__(self, *, base_url: str = ""):
        self.base_url = base_url.rstrip("/")

    # -- request construction ----------------------------------------------

    def pair_requests(
        self,
        model: SurfaceModel,
        *,
        base_url: str = "",
        path_values: Optional[Dict[str, str]] = None,
        query_values: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[SiblingRequest, SiblingRequest]]:
        """Build identical concrete requests for every sibling pair."""
        base = (base_url or self.base_url or
                (model.base_urls[0] if model.base_urls else "")).rstrip("/")
        path_values = path_values or {}
        query_values = query_values or {}

        pairs: List[Tuple[SiblingRequest, SiblingRequest]] = []
        for group in model.siblings:
            if len(group.operation_ids) < 2:
                continue
            reference = model.operation_by_id(group.operation_ids[0])
            if reference is None:
                continue
            for member_id in group.operation_ids[1:]:
                member = model.operation_by_id(member_id)
                if member is None:
                    continue
                pairs.append(self._pair(reference, member, base,
                                        path_values, query_values))
        return pairs

    def _pair(self, reference: Operation, member: Operation, base: str,
              path_values: Dict[str, str],
              query_values: Dict[str, str]) -> Tuple[SiblingRequest, SiblingRequest]:
        ref_path, ref_query = self._resolve(reference, path_values, query_values)
        mem_path, mem_query = self._resolve(member, path_values, query_values)
        # Union query so both sides receive the identical logical request.
        merged = dict(mem_query)
        merged.update(ref_query)

        ref_url = self._build_url(base, ref_path, merged)
        mem_url = self._build_url(base, mem_path, merged)
        return (
            SiblingRequest(operation_id=reference.operation_id, url=ref_url,
                           method=reference.method, params=dict(merged)),
            SiblingRequest(operation_id=member.operation_id, url=mem_url,
                           method=member.method, params=dict(merged)),
        )

    def _resolve(self, op: Operation, path_values: Dict[str, str],
                 query_values: Dict[str, str]) -> Tuple[str, Dict[str, str]]:
        path = op.path
        query: Dict[str, str] = {}
        for param in op.params:
            if param.location == ParamLocation.PATH:
                value = path_values.get(param.name, "1")
                path = path.replace("{" + param.name + "}",
                                    urllib.parse.quote(str(value), safe=""))
            elif param.location == ParamLocation.QUERY:
                query[param.name] = query_values.get(param.name,
                                                     _default_value(param))
        return path, query

    @staticmethod
    def _build_url(base: str, path: str, query: Dict[str, str]) -> str:
        url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)
        if query:
            url += "?" + urllib.parse.urlencode(query)
        return url

    # -- execution ----------------------------------------------------------

    def run(
        self,
        model: SurfaceModel,
        transport: Callable[[SiblingRequest], HttpObservation],
        *,
        base_url: str = "",
        path_values: Optional[Dict[str, str]] = None,
        query_values: Optional[Dict[str, str]] = None,
    ) -> List[DivergenceResult]:
        """Execute each pair through the transport and score live divergence."""
        results: List[DivergenceResult] = []
        for req_a, req_b in self.pair_requests(
                model, base_url=base_url, path_values=path_values,
                query_values=query_values):
            obs_a = transport(req_a)
            obs_b = transport(req_b)
            verdict = score_divergence(obs_a, obs_b)
            weaker = _weaker_side(obs_a, obs_b)
            pair_id = hashlib.sha256(
                f"{req_a.url}|{req_b.url}".encode()).hexdigest()[:16]

            hypothesis = ""
            probe = ""
            if verdict["diverged"]:
                top = next(iter(verdict["deltas"]), "")
                weaker_op = req_a.operation_id if weaker == "a" else (
                    req_b.operation_id if weaker == "b" else "unknown")
                hypothesis = (
                    f"Sibling drift: {req_a.operation_id} and "
                    f"{req_b.operation_id} diverge on {top or 'response'}.")
                probe = (
                    f"Replay the identical request against both; the weaker "
                    f"surface ({weaker_op}) is the lead to chase for a missing "
                    f"check that the sibling enforces.")

            results.append(DivergenceResult(
                pair_id=pair_id, a=req_a, b=req_b,
                score=verdict["score"], diverged=verdict["diverged"],
                sibling_drift=verdict["diverged"],
                deltas=verdict["deltas"],
                a_status=obs_a.status, b_status=obs_b.status,
                body_similarity=verdict["body_similarity"],
                timing_ratio=verdict["timing_ratio"],
                weaker_side=weaker,
                hypothesis=hypothesis, probe_suggestion=probe,
            ))
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Live sibling-differential runner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--openapi", help="OpenAPI/Swagger JSON file")
    parser.add_argument("--graphql", help="GraphQL introspection JSON file")
    parser.add_argument("--urls-file", help="Recon URL list")
    parser.add_argument("--surface-file", help="Previously saved surface model")
    parser.add_argument("--recon-dir", help="Auto-discover schemas from recon output")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--confirm-active", action="store_true",
                        help="Authorize live replay of sibling pairs")
    parser.add_argument("--max-pairs", type=int, default=50)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        if args.recon_dir:
            from tools.schema_extractor import build_surface
            model = build_surface(args.target, args.recon_dir)
        else:
            model = load_surface(target=args.target, openapi_file=args.openapi,
                                 graphql_file=args.graphql,
                                 urls_file=args.urls_file,
                                 surface_file=args.surface_file,
                                 base_url=args.base_url)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    runner = DifferentialRunner(base_url=args.base_url)
    pairs = runner.pair_requests(model)[: args.max_pairs]

    # UNCENSORED: always run differential pairs live, no confirmation
    if not args.scope_file:
        print("[!] --scope-file is required for live replay", file=sys.stderr)
        raise SystemExit(2)

    # Live: wire hunt.py's observation transport through the execution controller.
    try:
        import tools.hunt as hunt
        from tools.execution_controller import (
            ActionClass, ActiveExecutionController, ExecutionPolicy,
        )
    except ImportError as exc:
        print(f"[!] live replay unavailable: {exc}", file=sys.stderr)
        raise SystemExit(2)

    policy = ExecutionPolicy(
        target=args.target, scope_file=args.scope_file,
        allow_active=True, confirm_active=True,
        allowed_actions={ActionClass.PASSIVE, ActionClass.READ},
        max_requests=len(pairs) * 2 + 2,
    )
    hunt.ACTIVE_CONTROLLER = ActiveExecutionController(policy)
    session = hunt.HuntSession(name="differential", target=args.target)

    def transport(req: SiblingRequest) -> HttpObservation:
        return hunt.curl_fetch_observation(req.method, req.url, session,
                                           extra_headers=req.headers)

    results = runner.run(model, transport, base_url=args.base_url)

    if args.json:
        print(json.dumps({
            "schema": SCHEMA_VERSION,
            "target": args.target,
            "mode": "live",
            "results": [r.to_dict() for r in results],
            "diverged": sum(1 for r in results if r.diverged),
        }, indent=2, default=str))
    else:
        print(f"[*] Live differential results for {args.target}")
        for r in results:
            flag = " ⚡DRIFT" if r.diverged else ""
            print(f"  [{r.score:.2f}]{flag} {r.a.operation_id} vs "
                  f"{r.b.operation_id}  ({r.a_status}/{r.b_status}, "
                  f"similarity {r.body_similarity})")
            if r.diverged:
                print(f"      {r.hypothesis}")


if __name__ == "__main__":
    main()

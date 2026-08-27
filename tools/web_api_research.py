#!/usr/bin/env python3
"""Phase 2 Web/API research adapter.

This adapter is offline: it parses supplied API descriptions or observations,
creates reviewable candidates, and persists them through the shared Phase 1
store. Live execution remains the responsibility of the existing bounded
executor and operator-provided lab boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate
from tools.differential import DifferentialDetector
from tools.surface_model import SurfaceModel, parse_openapi


class WebApiResearchAdapter:
    """Convert Web/API surface and behavioral observations into candidates."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        self.store = CandidateStore(
            root / "state" / "sessions" / self._slug(self.target) / "candidates.jsonl"
        )

    @staticmethod
    def _slug(value: str) -> str:
        from tools.runtime_paths import target_slug
        return target_slug(value)

    def analyze_openapi(self, spec: Dict[str, Any], *, base_url: str = "") -> Tuple[SurfaceModel, List[ResearchCandidate]]:
        """Build a surface model and emit sibling-drift candidates."""
        model = parse_openapi(spec, self.target, base_url=base_url)
        detector = DifferentialDetector()
        candidates: List[ResearchCandidate] = []
        for group in model.siblings:
            if len(group.operation_ids) < 2:
                continue
            operations = [model.operation_by_id(item) for item in group.operation_ids]
            operations = [item for item in operations if item is not None]
            if len(operations) < 2:
                continue
            first, second = operations[0], operations[1]
            report = detector.compare({
                "id": first.operation_id,
                "endpoint": first.path,
                "endpoint_root": group.group_id,
                "auth": first.auth_required,
                "fields": [p.name for p in first.params],
            }, {
                "id": second.operation_id,
                "endpoint": second.path,
                "endpoint_root": group.group_id,
                "auth": second.auth_required,
                "fields": [p.name for p in second.params],
            })
            # SurfaceModel already established that these operations are
            # siblings. Preserve that relationship even when their only
            # difference is the version path itself.
            if not report.divergences:
                # A version sibling with no declared metadata difference is
                # still a valuable differential-testing candidate: runtime
                # behavior must be measured rather than inferred from schema
                # parity.
                report.hypothesis = (
                    f"Version sibling pair requires behavioral differential testing: "
                    f"{first.path} vs {second.path}.")
                report.probe_suggestion = (
                    "Replay the same request and compare authorization, fields, "
                    "status, headers, timing, and state effects.")
            candidates.append(ResearchCandidate(
                domain="web_api",
                target=self.target,
                bug_class="api_surface_differential",
                title=f"API sibling drift: {first.path} vs {second.path}",
                endpoint=first.path,
                severity="medium",
                behavior={
                    "pair": [first.operation_id, second.operation_id],
                    "divergence_score": report.divergence_score,
                    "divergences": [item.to_dict() for item in report.divergences],
                },
                notes=[report.hypothesis, report.probe_suggestion],
            ))
        return model, candidates

    def analyze_observations(self, observations: Iterable[Dict[str, Any]]) -> List[ResearchCandidate]:
        """Emit candidates only for material baseline/mutation differences."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for observation in observations:
            endpoint = str(observation.get("endpoint") or "").strip()
            if endpoint:
                grouped.setdefault(endpoint, []).append(dict(observation))
        candidates: List[ResearchCandidate] = []
        for endpoint, items in grouped.items():
            if len(items) < 2:
                continue
            baseline, current = items[0], items[1]
            status_changed = baseline.get("status") != current.get("status")
            body_changed = baseline.get("body") != current.get("body")
            headers_changed = (baseline.get("headers") or {}) != (current.get("headers") or {})
            if not (status_changed or body_changed or headers_changed):
                continue
            candidates.append(ResearchCandidate(
                domain="web_api",
                target=self.target,
                bug_class="behavior_differential",
                title=f"Behavioral delta on {endpoint}",
                endpoint=endpoint,
                severity="medium",
                behavior={
                    "baseline": baseline,
                    "mutation": current,
                    "delta": {
                        "status": status_changed,
                        "body": body_changed,
                        "headers": headers_changed,
                    },
                },
            ))
        return candidates

    def register(self, candidates: Iterable[ResearchCandidate]) -> bool:
        """Persist candidates and return whether at least one was new."""
        added = False
        for candidate in candidates:
            candidate.target = candidate.target or self.target
            if self.store.add(candidate):
                added = True
        return added

    def analyze_observation_file(self, path: str | Path) -> List[ResearchCandidate]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("observation file must contain a JSON array")
        return self.analyze_observations(data)

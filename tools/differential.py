#!/usr/bin/env python3
"""
BugWolf Differential Divergence Detector v1.0.0

Rule 4 ("differential over absolute") as a tool. Developers fix one surface
and forget its sibling — the divergence IS the high-value lead. Compare two
surfaces (API v1/v2, web/mobile, GraphQL/REST, two roles/tenants, two
endpoints) and detect behavioral divergence across auth, validation, fields,
and response shape.

A surface pair that should behave identically but diverges (v1 validates an
amount cap, v2 doesn't; web requires auth, mobile doesn't) is flagged as a
sibling-drift lead with a concrete probe suggestion.

Usage:
  python3 tools/differential.py --a '{"endpoint":"/api/v1/transfer"}' --b '{"endpoint":"/api/v2/transfer"}'
  python3 tools/differential.py --a-file a.json --b-file b.json --json
"""

import json
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Set

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@dataclass
class Divergence:
    aspect: str
    a_value: Any
    b_value: Any
    weight: float = 1.0
    note: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DivergenceReport:
    a_id: str
    b_id: str
    divergence_score: float  # 0-1
    divergences: List[Divergence] = field(default_factory=list)
    sibling_drift: bool = False
    hypothesis: str = ""
    probe_suggestion: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


def _norm(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, (list, tuple, set)):
        return sorted(str(x).strip().lower() for x in value)
    if isinstance(value, dict):
        return {str(k).strip().lower(): _norm(v) for k, v in value.items()}
    return value


class DifferentialDetector:
    """Compares two surfaces and flags behavioral divergence."""

    # Aspect weights: how much each divergence matters for a high-value bug.
    ASPECTS = [
        ("auth", 1.0, "auth presence/level differs"),
        ("authz", 1.0, "authorization check differs"),
        ("rate_limited", 0.6, "rate limiting differs"),
        ("validation", 1.0, "input validation differs"),
        ("fields", 0.8, "exposed fields differ"),
        ("status_code", 0.4, "response status differs"),
        ("content_type", 0.3, "content type differs"),
    ]

    def compare(self, a: Dict, b: Dict) -> DivergenceReport:
        a_id = a.get("id") or a.get("endpoint", "A")
        b_id = b.get("id") or b.get("endpoint", "B")

        divergences: List[Divergence] = []
        total_weight = sum(w for _, w, _ in self.ASPECTS)
        weighted = 0.0

        for aspect, weight, note in self.ASPECTS:
            av = a.get(aspect)
            bv = b.get(aspect)
            if av is None and bv is None:
                total_weight -= weight
                continue
            if _norm(av) != _norm(bv):
                weighted += weight
                divergences.append(Divergence(
                    aspect=aspect, a_value=av, b_value=bv,
                    weight=weight, note=note))

        score = round(weighted / total_weight, 3) if total_weight else 0.0

        # Sibling drift: same functionality (endpoint root matches) but diverges.
        same_root = (a.get("endpoint_root") or a.get("endpoint", "")) == \
                    (b.get("endpoint_root") or b.get("endpoint", ""))
        drift = bool(divergences) and same_root

        hypothesis = ""
        probe = ""
        if drift:
            # Find the highest-weight divergence to phrase the lead.
            top = max(divergences, key=lambda d: d.weight)
            weaker = "A" if self._looks_weaker(a, top) else "B"
            hypothesis = (
                f"Sibling drift: {a_id} and {b_id} share an endpoint root but "
                f"diverge on {top.aspect} ({top.note})."
            )
            probe = (
                f"Replay the request that works on the weaker surface against "
                f"the stronger one — the {top.aspect} gap on {weaker} is the lead."
            )

        return DivergenceReport(
            a_id=a_id, b_id=b_id, divergence_score=score,
            divergences=divergences, sibling_drift=drift,
            hypothesis=hypothesis, probe_suggestion=probe,
        )

    def _looks_weaker(self, surface: Dict, top: Divergence) -> bool:
        """Heuristic: which side looks less protected (the drift's weak leg)."""
        val = _norm(surface.get(top.aspect))
        if val is None:
            return True  # missing check = weaker
        if isinstance(val, bool):
            return not val  # False auth/rate_limit = weaker
        if isinstance(val, list):
            return len(val) == 0
        return False

    def compare_pairs(self, pairs: List[tuple]) -> List[DivergenceReport]:
        return [self.compare(a, b) for a, b in pairs]

    def report(self, reports: List[DivergenceReport]) -> str:
        lines = ["=" * 72, "  DIFFERENTIAL DIVERGENCE REPORT", "=" * 72]
        for r in reports:
            flag = " ⚡SIBLING-DRIFT" if r.sibling_drift else ""
            lines.append(f"\n  {r.a_id}  vs  {r.b_id}  →  "
                         f"score {r.divergence_score:.2f}{flag}")
            for d in r.divergences:
                lines.append(f"    - {d.aspect}: {d.a_value!r} ≠ {d.b_value!r} "
                             f"({d.note})")
            if r.hypothesis:
                lines.append(f"    hypothesis: {r.hypothesis}")
                lines.append(f"    probe: {r.probe_suggestion}")
        lines.append("=" * 72)
        return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Differential Divergence Detector v1.0.0")
    parser.add_argument("--a", help="Surface A as JSON object")
    parser.add_argument("--b", help="Surface B as JSON object")
    parser.add_argument("--a-file", help="Surface A JSON file")
    parser.add_argument("--b-file", help="Surface B JSON file")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    def load(arg, file_arg):
        if file_arg:
            return json.loads(Path(file_arg).read_text())
        if arg:
            return json.loads(arg)
        return None

    a = load(args.a, args.a_file)
    b = load(args.b, args.b_file)
    if a is None or b is None:
        parser.error("provide both surfaces (--a/--a-file and --b/--b-file)")

    det = DifferentialDetector()
    report = det.compare(a, b)

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    print(det.report([report]))


if __name__ == "__main__":
    main()

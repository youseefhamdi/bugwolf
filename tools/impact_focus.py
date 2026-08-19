#!/usr/bin/env python3
"""
BugWolf Criticality Router v1.0.0

Focus the hunt on high/critical impact BEFORE agents waste probes on noise.
Ranks surfaces/findings by impact potential using the P5 capability verbs
(create/approve/modify/transfer/withdraw/impersonate/authorize), the trust
boundary crossed, victim scope, and asset sensitivity — then emits an ordered
hunt priority so agents spend effort on the intersections most likely to pay.

A surface with a withdraw/transfer verb crossing a user→payment boundary on a
funds asset ranks CRITICAL focus; a read on a public list ranks LOW and should
not consume agent time.

Usage:
  python3 tools/impact_focus.py --findings-file findings.jsonl
  python3 tools/impact_focus.py --surfaces-file surfaces.json
  python3 tools/impact_focus.py --surface '{"endpoint":"/api/withdraw","method":"POST"}'
  python3 tools/impact_focus.py --findings-file findings.jsonl --min-focus high --json
"""

import json
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# P5 impact verbs — the verbs that move money / identity / authority.
IMPACT_VERBS = {
    "withdraw": 1.00, "transfer": 1.00, "impersonate": 1.00, "authorize": 0.95,
    "approve": 0.85, "create": 0.75, "modify": 0.70, "delete": 0.70,
    "read": 0.35, "list": 0.20,
}

BOUNDARY_WEIGHTS = {
    "user-to-admin": 1.00, "public-to-admin": 1.00, "cross-tenant": 1.00,
    "service-to-admin": 0.95, "user-to-payment": 0.95, "user-to-identity": 0.90,
    "user-to-org": 0.90, "user-to-user": 0.60, "public-to-private": 0.60,
    "none": 0.30, "": 0.30,
}

ASSET_WEIGHTS = {
    "funds": 1.00, "credentials": 0.95, "pii": 0.90, "auth": 0.90,
    "admin": 0.85, "source": 0.70, "config": 0.70, "data": 0.50, "other": 0.40,
}

VICTIM_WEIGHTS = {
    "all-users": 1.00, "organization": 0.90, "many-users": 0.80,
    "single-user": 0.50, "self": 0.15, "none": 0.05,
}

# Keyword → verb inference (searched case-insensitively in endpoint/title/impact).
VERB_KEYWORDS = {
    "withdraw": ["withdraw", "redeem", "cashout", "payout", "drain"],
    "transfer": ["transfer", "send", "payment", "checkout", "balance", "refund",
                 "deposit", "swap", "buy", "sell"],
    "impersonate": ["impersonat", "login-as", "sudo", "act-as", "masquerade"],
    "authorize": ["authorize", "grant", "role", "permission", "invite", "scope",
                  "oauth", "sso", "token", "admin", "approval", "approve"],
    "create": ["create", "register", "signup", "mint", "issue"],
    "modify": ["update", "edit", "modify", "patch", "upload", "import"],
    "delete": ["delete", "remove", "destroy", "revoke"],
    "read": ["get", "read", "fetch", "view", "export", "download", "profile"],
    "list": ["list", "search", "query", "index"],
}

ASSET_KEYWORDS = {
    "funds": ["balance", "payment", "withdraw", "transfer", "checkout", "wallet",
              "redeem", "refund", "deposit", "credit", "billing", "payout"],
    "credentials": ["password", "secret", "token", "api_key", "apikey", "credential",
                    "session", "cookie", "private key"],
    "pii": ["pii", "ssn", "passport", "address", "email", "phone", "dob", "medical",
            "profile", "user", "customer", "traveler", "patient"],
    "auth": ["auth", "login", "oauth", "sso", "session", "mfa", "otp", "2fa"],
    "admin": ["admin", "dashboard", "panel", "config", "settings", "console"],
    "source": ["source", "repo", "code", "git", "artifact", "build"],
    "config": ["config", "env", "environment", "secret", "terraform", "k8s", "deploy"],
}

BOUNDARY_KEYWORDS = {
    "user-to-admin": ["admin", "role", "escalat", "privilege"],
    "cross-tenant": ["tenant", "organization", "workspace", "multi-tenant", "org_id"],
    "user-to-payment": ["payment", "checkout", "billing", "withdraw", "transfer", "wallet"],
    "user-to-identity": ["password", "reset", "email", "mfa", "login", "session", "oauth"],
    "user-to-user": ["user_id", "profile", "account", "order", "booking", "invoice"],
    "user-to-org": ["organization", "workspace", "team", "group", "invite"],
}

VICTIM_KEYWORDS = {
    "all-users": ["all users", "any user", "every user", "mass", "enumerate", "bulk"],
    "organization": ["organization", "tenant", "workspace", "company", "admin"],
    "many-users": ["users", "multiple", "several"],
    "single-user": ["user", "account", "profile", "victim", "another"],
    "self": ["self", "own account", "own data"],
}


@dataclass
class FocusedSurface:
    surface_id: str
    endpoint: str = ""
    title: str = ""
    impact_verb: str = "read"
    boundary: str = "none"
    asset: str = "other"
    victim_scope: str = "none"
    criticality: float = 0.0  # 0-100
    focus: str = "low"        # critical | high | medium | low
    drain_potential: bool = False
    reasoning: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


def _lookup(text: str, mapping: Dict[str, float], default: float) -> str:
    """Return the first keyword hit's mapped key, else default key."""
    t = (text or "").lower()
    for key, _ in mapping.items():
        if key in t:
            return key
    return default


def infer_verb(text: str) -> str:
    t = (text or "").lower()
    for verb, kws in VERB_KEYWORDS.items():
        if any(k in t for k in kws):
            return verb
    return "read"


def infer_boundary(text: str) -> str:
    t = (text or "").lower()
    for boundary, kws in BOUNDARY_KEYWORDS.items():
        if any(k in t for k in kws):
            return boundary
    return "none"


def infer_asset(text: str) -> str:
    t = (text or "").lower()
    for asset, kws in ASSET_KEYWORDS.items():
        if any(k in t for k in kws):
            return asset
    return "other"


def infer_victim(text: str) -> str:
    t = (text or "").lower()
    for victim, kws in VICTIM_KEYWORDS.items():
        if any(k in t for k in kws):
            return victim
    return "none"


def focus_tier(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


class CriticalityRouter:
    """Ranks surfaces/findings by high/critical impact potential."""

    FOCUS_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def __init__(self, min_focus: str = "low"):
        self.min_rank = self.FOCUS_RANK.get(min_focus, 3)

    def score_surface(self, surface: Dict) -> FocusedSurface:
        blob = " ".join(str(v) for k, v in surface.items()
                        if k in ("endpoint", "title", "impact", "location",
                                 "bug_class", "description", "method"))
        verb = surface.get("impact_verb") or infer_verb(blob)
        boundary = surface.get("boundary") or infer_boundary(blob)
        asset = surface.get("asset") or infer_asset(blob)
        victim = surface.get("victim_scope") or infer_victim(blob)

        vw = IMPACT_VERBS.get(verb, 0.3)
        bw = BOUNDARY_WEIGHTS.get(boundary, 0.3)
        aw = ASSET_WEIGHTS.get(asset, 0.4)
        vicw = VICTIM_WEIGHTS.get(victim, 0.2)

        # verb gates everything; boundary and asset dominate, victim amplifies.
        score = round(100 * vw * (0.40 * bw + 0.40 * aw + 0.20 * vicw), 1)
        tier = focus_tier(score)

        drain = verb in ("withdraw", "transfer") and asset == "funds"

        reasoning = (
            f"{verb} verb (x{vw}) × {boundary} boundary (x{bw}) × "
            f"{asset} asset (x{aw}) × {victim} victim (x{vicw})"
        )

        return FocusedSurface(
            surface_id=surface.get("finding_id") or surface.get("id")
                        or surface.get("endpoint", "?"),
            endpoint=surface.get("endpoint", ""),
            title=surface.get("title", ""),
            impact_verb=verb,
            boundary=boundary,
            asset=asset,
            victim_scope=victim,
            criticality=score,
            focus=tier,
            drain_potential=drain,
            reasoning=reasoning,
        )

    def route(self, surfaces: List[Dict]) -> List[FocusedSurface]:
        scored = [self.score_surface(s) for s in surfaces]
        scored = [s for s in scored
                  if self.FOCUS_RANK[s.focus] <= self.min_rank]
        return sorted(scored, key=lambda s: (-s.criticality, s.endpoint))

    def report(self, scored: List[FocusedSurface]) -> str:
        lines = [
            "=" * 72,
            "  CRITICALITY ROUTER — HUNT PRIORITY",
            "=" * 72,
            f"  Surfaces ranked: {len(scored)}",
            "=" * 72,
        ]
        for i, s in enumerate(scored, 1):
            flag = " 💰DRAIN" if s.drain_potential else ""
            lines.append(f"\n  [{i:02d}] [{s.focus.upper():8s}] {s.criticality:5.1f}  "
                         f"{s.endpoint or s.surface_id}{flag}")
            if s.title:
                lines.append(f"      {s.title[:80]}")
            lines.append(f"      {s.reasoning}")
        lines.append("=" * 72)
        return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Criticality Router v1.0.0")
    parser.add_argument("--findings-file", help="JSONL findings file")
    parser.add_argument("--surfaces-file", help="JSON array of surfaces")
    parser.add_argument("--surface", help="Single surface as JSON object")
    parser.add_argument("--min-focus", default="low",
                        choices=["critical", "high", "medium", "low"])
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    surfaces: List[Dict] = []
    if args.surface:
        surfaces.append(json.loads(args.surface))
    elif args.surfaces_file:
        surfaces = json.loads(Path(args.surfaces_file).read_text())
    elif args.findings_file:
        raw = Path(args.findings_file).read_text()
        surfaces = [json.loads(l) for l in raw.splitlines() if l.strip()]
    else:
        parser.error("one of --surface, --surfaces-file, --findings-file required")

    router = CriticalityRouter(min_focus=args.min_focus)
    scored = router.route(surfaces)

    if args.as_json:
        print(json.dumps([s.to_dict() for s in scored], indent=2))
        return

    print(router.report(scored))
    if not scored:
        print("  No surfaces at/above the requested focus tier.")


if __name__ == "__main__":
    main()

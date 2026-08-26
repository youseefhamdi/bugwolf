#!/usr/bin/env python3
"""BugWolf OAuth / OIDC Flow Analyzer (P0, Week 2).

Parse OAuth/OIDC endpoints and flows from recon artifacts (JS, configs, schema)
and produce *validation plans* for the identity flaw classes that dominate
2025-26 bounty payouts (USENIX Security 2025 COAT; Doyensec OAuth catalog):

  * redirect_uri validation gaps (open redirector / token leak)
  * state / Nonce missing or reused (CSRF in the auth flow)
  * PKCE downgrade (authorization code without PKCE accepted)
  * token-in-URL leakage (fragment vs query, logs, referrer)
  * cross-app COAT (cross-application OAuth account takeover)

Design (deterministic core, uncensored, workflow-aware):

  * Deterministic + offline: inputs are endpoint configs / observed flows; the
    tool writes *plans* to ``research/<target>/auth/oauth-flow-plans.json``
    (a ``research`` supplementary artifact) and emits ``AUTH_CANDIDATE`` on the
    signal bus for high-confidence candidates.
  * Two-account validation model: every plan requires two cooperating test
    accounts and never touches a third-party session.
  * Uncensored: no scope/confirmation gates; live replay is the operator's step.

Usage:
  python3 tools/domains/auth/oauth_flow_analyzer.py --target acme --flow '{"authorize":"https://acme.com/oauth/authorize",...}'
  python3 tools/domains/auth/oauth_flow_analyzer.py --target acme --js-file recon/acme/jsfiles.txt
  python3 tools/domains/auth/oauth_flow_analyzer.py --target acme --json
"""

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current

_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn

SCHEMA = "bugwolf/oauth-flow/v1"

# Well-known OAuth/OIDC endpoint parameter names (for flow parsing).
OAUTH_PARAMS = (
    "client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method", "code_verifier", "grant_type",
    "access_token", "id_token", "token_type", "expires_in", "response_mode",
    "prompt", "login_hint", "acr_values", "audience", "resource",
)

# Endpoint path fragments that identify the OAuth surface.
ENDPOINT_MARKERS = (
    "oauth", "authorize", "token", "callback", "redirect", "oidc", "sso",
    "signin", "login/oauth", "connect/authorize", "connect/token", "auth/realms",
    "authorization", "token/refresh", "logout",
)


@dataclass
class OAuthFlow:
    """Parsed OAuth/OIDC flow endpoints + observed parameters."""
    authorize_url: str = ""
    token_url: str = ""
    callback_url: str = ""
    client_id: str = ""
    response_type: str = ""
    scope: str = ""
    params: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OAuthPlan:
    plan_id: str
    category: str  # redirect_uri | state_csrf | pkce | token_in_url | coat
    severity_hint: str
    description: str
    flow: Dict[str, Any]
    observations: List[str]
    validation_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OAuthAnalysis:
    target: str
    generated_at: str
    flows: List[OAuthFlow]
    plans: List[OAuthPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "flow_count": len(self.flows),
            "plan_count": len(self.plans),
            "flows": [f.to_dict() for f in self.flows],
            "plans": [p.to_dict() for p in self.plans],
        }


def _id(prefix: str, *parts: str) -> str:
    import hashlib
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _extract_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    out: Dict[str, str] = {}
    for key, values in query.items():
        low = key.lower()
        if low in OAUTH_PARAMS or any(marker in low for marker in ("client", "redirect", "state", "code", "token")):
            out[low] = values[-1] if values else ""
    return out


def parse_flow(data: Dict[str, Any]) -> OAuthFlow:
    """Build an OAuthFlow from a config/observed dict."""
    authorize = str(data.get("authorize_url") or data.get("authorize") or "")
    token = str(data.get("token_url") or data.get("token") or "")
    callback = str(data.get("callback_url") or data.get("callback") or "")
    params: Dict[str, str] = {}
    for key, value in data.items():
        if key.lower() in OAUTH_PARAMS and value is not None:
            params[key.lower()] = str(value)
    params.update(_extract_params(authorize))
    params.update(_extract_params(callback))
    return OAuthFlow(
        authorize_url=authorize, token_url=token, callback_url=callback,
        client_id=params.get("client_id", ""),
        response_type=params.get("response_type", ""),
        scope=params.get("scope", ""),
        params=params)


def parse_js_surface(text: str) -> List[Dict[str, Any]]:
    """Scan JS/config text for OAuth endpoint strings.

    Deterministic: finds URLs containing the endpoint markers and captures
    nearby client_id / redirect_uri / state params.
    """
    found: List[Dict[str, Any]] = []
    url_re = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
    for url in url_re.findall(text or ""):
        parsed = urlparse(url)
        if not any(marker in parsed.path.lower() for marker in ENDPOINT_MARKERS):
            continue
        params = _extract_params(url)
        found.append({
            "url": url,
            "path": parsed.path,
            "params": params,
            "client_id": params.get("client_id", ""),
            "response_type": params.get("response_type", ""),
        })
    return found


def analyze(target: str, flows: List[OAuthFlow]) -> OAuthAnalysis:
    """Deterministically build the OAuth validation plan set."""
    plans: List[OAuthPlan] = []
    for flow in flows:
        params = flow.params

        # 1. redirect_uri validation gaps.
        plans.append(OAuthPlan(
            plan_id=_id("oauth-plan", target, flow.authorize_url, "redirect_uri"),
            category="redirect_uri",
            severity_hint="high",
            description=(
                "redirect_uri validation gap: if the authorization server "
                "accepts a redirect_uri that was not registered (or a "
                "substring/prefix of one), an attacker can redirect the "
                "authorization code / token to their own listener."),
            flow=flow.to_dict(),
            observations=[
                "Test registered vs unregistered URI, prefix/suffix matches, "
                "and open redirector chaining (redirect_uri=https://app.com/.."
                "attacker.com).",
                "COAT (USENIX Sec 2025) abuses weak redirect_uri/app "
                "differentiation across integration platforms.",
            ],
            validation_steps=[
                "Register app A; start an authorization request with the "
                "registered redirect_uri and capture the full authorize URL "
                "template (state included).",
                "Replay the authorize URL with redirect_uri variants: exact "
                "registered URI (baseline), unregistered host, prefix/suffix "
                "tamper, open-redirector value.",
                "A callback at an unregistered URI that still returns a code "
                "is a redirect_uri validation finding — record both "
                "responses, never exchange the code against a victim app.",
            ],
        ))

        # 2. state / Nonce CSRF.
        state_present = bool(params.get("state") or params.get("nonce"))
        plans.append(OAuthPlan(
            plan_id=_id("oauth-plan", target, flow.authorize_url, "state"),
            category="state_csrf",
            severity_hint="high" if not state_present else "medium",
            description=(
                ("state/Nonce absent from the observed flow — the "
                 "authorization response may be CSRF-able (login CSRF / "
                 "session fixation via attacker-initiated code exchange)."
                 if not state_present else
                 "state/Nonce present but its binding (per-session, "
                 "unpredictable) must be verified — a static or reused state "
                 "is equivalent to no state.")),
            flow=flow.to_dict(),
            observations=[
                "state must be a per-session, cryptographically random value "
                "bound to the initiating browser session.",
                "A missing/static/reused state lets an attacker force a "
                "victim into the attacker's session (login CSRF).",
            ],
            validation_steps=[
                "Initiate two authorizations from two sessions and compare "
                "state values; identical or predictable state is a finding.",
                "Replay a captured authorization response (code + state) in "
                "a fresh session without a matching initiating request; a "
                "successful exchange is a login-CSRF signal.",
            ],
        ))

        # 3. PKCE downgrade.
        pkce_present = bool(params.get("code_challenge"))
        plans.append(OAuthPlan(
            plan_id=_id("oauth-plan", target, flow.authorize_url, "pkce"),
            category="pkce",
            severity_hint="high" if not pkce_present else "medium",
            description=(
                ("No code_challenge observed: if the server accepts an "
                 "authorization code exchange without PKCE, the code can be "
                 "replayed by anyone who captures it (PKCE downgrade)."
                 if not pkce_present else
                 "PKCE present — verify the server actually enforces it: "
                 "exchange a code issued WITHOUT a challenge.")),
            flow=flow.to_dict(),
            observations=[
                "PKCE protects public clients from code interception; "
                "downgrade happens when the server accepts a code that was "
                "issued without a verifier.",
                "Native/mobile and SPA flows are the classic downgrade "
                "targets (Doyensec OAuth catalog).",
            ],
            validation_steps=[
                "Start an authorization request with no code_challenge and "
                "complete the exchange with the two test accounts; a "
                "successful token response is a PKCE-downgrade finding.",
                "If PKCE is enforced, confirm the server rejects a missing "
                "or wrong code_verifier.",
            ],
        ))

        # 4. token-in-URL leakage.
        response_mode = params.get("response_mode", "")
        token_flow = "token" in params.get("response_type", "").lower()
        plans.append(OAuthPlan(
            plan_id=_id("oauth-plan", target, flow.authorize_url, "token_url"),
            category="token_in_url",
            severity_hint="high" if (token_flow and response_mode in ("", "query")) else "medium",
            description=(
                "Token-in-URL leakage: implicit/fragment flows (response_type "
                "=token, response_mode=query or default) place access tokens "
                "in the redirect URL where they can leak via logs, referrer "
                "headers, and browser history."),
            flow=flow.to_dict(),
            observations=[
                "Fragment delivery (default for implicit) keeps the token out "
                "of server logs but not out of the browser; response_mode="
                "query is strictly worse.",
                "Referrer leakage: the token-bearing URL is sent as Referer "
                "to any third-party resource on the callback page.",
            ],
            validation_steps=[
                "With response_type=token, observe where the token lands "
                "(fragment vs query) in the callback URL.",
                "Load a page with an external resource on the callback and "
                "check the Referer header for the token — a leak is a "
                "finding for the two test accounts only.",
            ],
        ))

        # 5. Cross-app COAT.
        plans.append(OAuthPlan(
            plan_id=_id("oauth-plan", target, flow.authorize_url, "coat"),
            category="coat",
            severity_hint="high",
            description=(
                "Cross-app COAT (cross-application OAuth account takeover): "
                "in integration platforms, an app's authorization can be "
                "replayed against another app with a shared client context, "
                "letting a low-privileged app take over a high-privileged "
                "app's OAuth grant (USENIX Security 2025, Luo et al.)."),
            flow=flow.to_dict(),
            observations=[
                "The attack needs apps that share a token/callback space but "
                "differ in privilege (read-only vs admin).",
                "COAT is enabled by missing app-bound context in the "
                "authorization exchange.",
            ],
            validation_steps=[
                "Provision two test apps (low and high privilege) under two "
                "cooperating test accounts.",
                "Complete the low-privilege app's authorization, then replay "
                "its callback/exchange against the high-privilege app's "
                "redirect_uri; a token with elevated scope is a COAT finding.",
                "Record the scope/claims delta; never touch third-party apps.",
            ],
        ))

    return OAuthAnalysis(target=target,
                         generated_at=datetime.now(timezone.utc).isoformat(),
                         flows=flows, plans=plans)


def write_analysis(analysis: OAuthAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/auth/oauth-flow-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(analysis.target)
    out_dir = root / "research" / target_dir / "auth"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "oauth-flow-plans.json"
    out_path.write_text(json.dumps(analysis.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf OAuth / OIDC Flow Analyzer (P0)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--flow", default="",
                        help="JSON object describing one OAuth flow")
    parser.add_argument("--flows-file", default="",
                        help="JSON array of OAuth flow objects")
    parser.add_argument("--js-file", default="",
                        help="JS/config text to scan for OAuth endpoints")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    flow_dicts: List[Dict[str, Any]] = []
    if args.flow:
        try:
            flow_dicts.append(json.loads(args.flow))
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False, "error": f"--flow invalid: {exc}"},
                             indent=2))
            return 2
    if args.flows_file:
        try:
            parsed = json.loads(Path(args.flows_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"ok": False, "error": f"--flows-file invalid: {exc}"},
                             indent=2))
            return 2
        items = parsed if isinstance(parsed, list) else [parsed]
        flow_dicts.extend(items)
    if args.js_file:
        try:
            text = Path(args.js_file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(json.dumps({"ok": False, "error": f"--js-file unreadable: {exc}"},
                             indent=2))
            return 2
        flow_dicts.extend(parse_js_surface(text))

    if not flow_dicts:
        print(json.dumps({"ok": False,
                          "error": "no flows; pass --flow, --flows-file, or --js-file"},
                         indent=2))
        return 2

    flows = [parse_flow(item) for item in flow_dicts]
    analysis = analyze(args.target, flows)
    out_path = write_analysis(analysis, project_root=args.project_root)

    if analysis.plans:
        for plan in analysis.plans:
            if plan.severity_hint == "high":
                publish_or_warn(
                    args.target, "AUTH_CANDIDATE", source="oauth_flow_analyzer",
                    payload={"category": plan.category,
                             "description": plan.description[:300]},
                    project_root=args.project_root)

    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "flow_count": len(flows),
        "plan_count": len(analysis.plans),
        "categories": sorted({p.category for p in analysis.plans}),
        "output_file": str(out_path),
        "analysis": analysis.to_dict(),
    }
    print(json.dumps(output, indent=2) if args.json else
          f"[+] {args.target}: {len(analysis.plans)} OAuth plans "
          f"({', '.join(output['categories'])}) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

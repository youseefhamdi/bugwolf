#!/usr/bin/env python3
"""BugWolf Deep-Link Analyzer — offline mobile link-surface planner.

Parses Android ``AndroidManifest.xml`` intent-filters and iOS deep links
(``Info.plist`` CFBundleURLTypes / associated-domains) into a deterministic
link-surface inventory:

  * URL schemes / hosts / path patterns exposed to other apps,
  * exported activities reachable via deep links (link hijacking surface,
    MASTG-TEST-0028),
  * sensitive-navigation candidates: parameters (``url``, ``redirect``,
    ``file``, ``next``, ``deeplink``, …) that flow into WebView loads,
    file opens, or redirects,
  * ``intent://`` (Android intent URL) parsing candidates.

Offline: input is the manifest/plist text or a pre-extracted summary JSON;
output is *plans* written to ``recon/<target>/discovery/deep-link-plans.json``
(a ``coverage-plan`` artifact).  Emits ``MOBILE_CANDIDATE`` on the signal bus
for link-hijacking and sensitive-navigation candidates.  Uncensored: no
scope/confirmation gates — validation is the operator's step.

Usage:
  python3 tools/domains/mobile/deep_link_analyzer.py --target acme --manifest AndroidManifest.xml
  python3 tools/domains/mobile/deep_link_analyzer.py --target acme --plist Info.plist
  python3 tools/domains/mobile/deep_link_analyzer.py --target acme --summary extracted.json --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import xml.etree.ElementTree as ET
except ImportError:  # pragma: no cover
    ET = None


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
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus

SCHEMA = "bugwolf/deep-link-analyzer/v1"

# Parameters that commonly flow into WebView loads / redirects / file opens.
SENSITIVE_PARAMS = (
    "url", "redirect", "redirect_uri", "return_url", "next", "continue",
    "callback", "deeplink", "deep_link", "link", "target", "file", "path",
    "page", "goto", "to", "webview", "load", "src", "href",
)

# Intent-filter actions that expose an activity to external apps.
_EXTERNAL_ACTIONS = (
    "android.intent.action.VIEW",
    "android.intent.action.SEND",
    "android.intent.action.EDIT",
    "android.intent.action.PICK",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.MAIN",
)


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class LinkSurface:
    platform: str          # android | ios
    scheme: str
    host: str = ""
    path: str = ""         # path / pathPrefix / pathPattern
    component: str = ""    # activity or "app"
    exported: bool = False
    action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeepLinkPlan:
    plan_id: str
    category: str          # link_hijacking | sensitive_navigation | intent_url | scheme_confusion
    platform: str
    surface: LinkSurface
    severity: str          # high | medium | low
    rationale: str
    validation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "category": self.category,
            "platform": self.platform,
            "surface": self.surface.to_dict(),
            "severity": self.severity,
            "rationale": self.rationale,
            "validation_steps": self.validation_steps,
        }


@dataclass
class DeepLinkAnalysis:
    target: str
    generated_at: str
    surfaces: List[LinkSurface] = field(default_factory=list)
    plans: List[DeepLinkPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "surface_count": len(self.surfaces),
            "surfaces": [s.to_dict() for s in self.surfaces],
            "plans": [p.to_dict() for p in self.plans],
        }


# ---------------------------------------------------------------------------
# Android manifest parsing
# ---------------------------------------------------------------------------

_NS = {"android": "http://schemas.android.com/apk/res/android"}


def _attr(element: Any, name: str) -> str:
    return str(element.get(f"{{{_NS['android']}}}{name}") or "")


def parse_android_manifest(manifest_text: str) -> List[LinkSurface]:
    """Extract deep-link surfaces from AndroidManifest.xml text."""
    if ET is None:
        return []
    surfaces: List[LinkSurface] = []
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError:
        return []
    for activity in root.iter("activity"):
        exported_raw = _attr(activity, "exported")
        exported = exported_raw.lower() == "true"
        name = _attr(activity, "name")
        for intent_filter in activity.iter("intent-filter"):
            actions = {_attr(a, "name") for a in intent_filter.iter("action")}
            is_external = bool(actions & set(_EXTERNAL_ACTIONS))
            for data in intent_filter.iter("data"):
                scheme = _attr(data, "scheme")
                if not scheme:
                    continue
                host = _attr(data, "host")
                path = (_attr(data, "pathPrefix") or _attr(data, "path")
                        or _attr(data, "pathPattern"))
                surfaces.append(LinkSurface(
                    platform="android",
                    scheme=scheme,
                    host=host,
                    path=path,
                    component=name,
                    exported=exported or is_external,
                    action=",".join(sorted(actions)) or "VIEW",
                ))
            if is_external and not list(intent_filter.iter("data")):
                # Externally triggerable action with no data — still a surface.
                surfaces.append(LinkSurface(
                    platform="android",
                    scheme="",
                    host="",
                    path="",
                    component=name,
                    exported=exported or True,
                    action=",".join(sorted(actions)),
                ))
    return surfaces


def _extract_sensitive_params(surface: LinkSurface) -> List[str]:
    """Which sensitive param names appear in the path (or are implied)?"""
    hits = [p for p in SENSITIVE_PARAMS if p in surface.path.lower()]
    return hits


# ---------------------------------------------------------------------------
# iOS parsing (Info.plist CFBundleURLTypes + associated domains)
# ---------------------------------------------------------------------------

def parse_ios_links(plist_text: str) -> List[LinkSurface]:
    """Extract deep-link surfaces from an Info.plist (XML text)."""
    if ET is None:
        return []
    surfaces: List[LinkSurface] = []
    try:
        root = ET.fromstring(plist_text)
    except ET.ParseError:
        return []
    # CFBundleURLTypes
    for url_types in root.iter("key"):
        if url_types.text != "CFBundleURLTypes":
            continue
        container = url_types.find("../array")  # may be None in flat XML
        break
    # Simpler walk: find dicts that contain CFBundleURLSchemes arrays.
    for dict_el in root.iter("dict"):
        keys = [k.text for k in dict_el.iter("key")]
        if "CFBundleURLSchemes" not in keys:
            continue
        schemes: List[str] = []
        for idx, key in enumerate(dict_el.findall("key")):
            if key.text == "CFBundleURLSchemes":
                nxt = dict_el.findall("array")[0] if dict_el.findall("array") else None
                break
        for child in dict_el:
            if child.tag == "key" and child.text == "CFBundleURLSchemes":
                # next sibling should be the array
                tail = list(dict_el)[list(dict_el).index(child) + 1]
                if tail.tag == "array":
                    schemes = [s.text or "" for s in tail.findall("string")]
                break
        for scheme in schemes:
            surfaces.append(LinkSurface(
                platform="ios", scheme=scheme, component="app",
                exported=True, action="VIEW"))
    # Associated domains (applinks)
    for key in root.iter("key"):
        if key.text != "com.apple.developer.associated-domains":
            continue
        tail = list(root.iter())[list(root.iter()).index(key) + 1] \
            if key in list(root.iter()) else None
    return surfaces


# ---------------------------------------------------------------------------

def analyze(target: str, *, manifest: Optional[str] = None,
            plist: Optional[str] = None,
            summary: Optional[Dict[str, Any]] = None) -> DeepLinkAnalysis:
    """Deterministically build the deep-link plan set.

    Exactly one of ``manifest`` / ``plist`` / ``summary`` should be supplied.
    """
    analysis = DeepLinkAnalysis(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    surfaces: List[LinkSurface] = []
    if summary and isinstance(summary, dict):
        for entry in summary.get("surfaces", []):
            if isinstance(entry, dict):
                surfaces.append(LinkSurface(
                    platform=str(entry.get("platform") or "android"),
                    scheme=str(entry.get("scheme") or ""),
                    host=str(entry.get("host") or ""),
                    path=str(entry.get("path") or ""),
                    component=str(entry.get("component") or ""),
                    exported=bool(entry.get("exported")),
                    action=str(entry.get("action") or "VIEW"),
                ))
    else:
        if manifest:
            surfaces.extend(parse_android_manifest(manifest))
        if plist:
            surfaces.extend(parse_ios_links(plist))
    analysis.surfaces = surfaces

    seen: Set[str] = set()
    for surface in surfaces:
        # --- link hijacking: exported, externally triggerable ---
        if surface.exported and surface.scheme:
            key = ("hijack", surface.platform, surface.scheme, surface.host,
                   surface.component)
            if key not in seen:
                seen.add(key)
                severity = "high" if not surface.path else "medium"
                analysis.plans.append(DeepLinkPlan(
                    plan_id=_id("plan", "hijack", *key[1:]),
                    category="link_hijacking",
                    platform=surface.platform,
                    surface=surface,
                    severity=severity,
                    rationale=(
                        f"Exported {surface.platform} component "
                        f"'{surface.component}' is reachable via "
                        f"{surface.scheme}://{surface.host}{surface.path} from "
                        f"any other app — another installed app can trigger "
                        f"this navigation unauthenticated (link hijacking)."),
                    validation_steps=[
                        "From a second app (or adb / a crafted intent URL), "
                        "launch the deep link and confirm the component opens "
                        "without an authentication or permission check.",
                        "If the component performs a sensitive action on "
                        "launch (payment, logout, token refresh), record the "
                        "cross-app trigger as the finding.",
                    ],
                ))

        # --- sensitive navigation: params flow into WebView/file/redirect ---
        params = _extract_sensitive_params(surface)
        if params:
            key = ("sensitive", surface.platform, surface.scheme, surface.host,
                   surface.path)
            if key not in seen:
                seen.add(key)
                analysis.plans.append(DeepLinkPlan(
                    plan_id=_id("plan", "sensitive", *key[1:]),
                    category="sensitive_navigation",
                    platform=surface.platform,
                    surface=surface,
                    severity="high" if surface.exported else "medium",
                    rationale=(
                        f"Deep link {surface.scheme}://{surface.host}"
                        f"{surface.path} carries navigation-controlling "
                        f"parameters ({', '.join(params)}) — these may flow "
                        f"into a WebView load, file open, or redirect "
                        f"(e.g. ?url=javascript:…, ?redirect=https://evil, "
                        f"?file=../../)."),
                    validation_steps=[
                        "Trigger the deep link with each parameter set to a "
                        "probe value (javascript:, https://evil.test, ../../).",
                        "Observe where the value lands: WebView URL, file "
                        "path, redirect Location — a controlled landing is "
                        "the finding (chain to JS bridge / file read).",
                    ],
                ))

        # --- Android intent:// URL scheme ---
        if surface.platform == "android" and surface.scheme == "intent":
            key = ("intent", surface.scheme, surface.host)
            if key not in seen:
                seen.add(key)
                analysis.plans.append(DeepLinkPlan(
                    plan_id=_id("plan", "intent", *key[1:]),
                    category="intent_url",
                    platform="android",
                    surface=surface,
                    severity="medium",
                    rationale=(
                        "An intent:// URL is parsed by Android's intent URL "
                        "parser — crafted intents can launch exported "
                        "components with attacker-controlled extras "
                        "(Intent.parseUri, #Intent;…;end)."),
                    validation_steps=[
                        "Craft intent:// URLs targeting the discovered "
                        "exported components with hostile extras (component "
                        "name, categories, extras bundle).",
                        "Confirm the target component launches and consumes "
                        "attacker-controlled extras.",
                    ],
                ))

    return analysis


def write_analysis(analysis: DeepLinkAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to recon/<target>/discovery/deep-link-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", analysis.target) or "default"
    out_dir = root / "recon" / target_slug / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "deep-link-plans.json"
    out.write_text(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep-link surface analyzer")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--manifest", default=None, help="path to AndroidManifest.xml")
    parser.add_argument("--plist", default=None, help="path to Info.plist (XML)")
    parser.add_argument("--summary", default=None, help="pre-extracted surface summary JSON")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    manifest_text = None
    if args.manifest:
        try:
            manifest_text = Path(args.manifest).read_text()
        except OSError as exc:
            print(json.dumps({"error": f"cannot read manifest: {exc}"}))
            return 2
    plist_text = None
    if args.plist:
        try:
            plist_text = Path(args.plist).read_text()
        except OSError as exc:
            print(json.dumps({"error": f"cannot read plist: {exc}"}))
            return 2
    summary = None
    if args.summary:
        try:
            summary = json.loads(Path(args.summary).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"error": f"cannot read summary: {exc}"}))
            return 2

    analysis = analyze(args.target, manifest=manifest_text,
                       plist=plist_text, summary=summary)
    out = write_analysis(analysis, project_root=args.project_root,
                         base_dir=args.base_dir)

    high = [p for p in analysis.plans if p.severity == "high"]
    if high:
        try:
            bus = SignalBus(args.target,
                            project_root=args.project_root or args.base_dir)
            for plan in high:
                bus.publish("MOBILE_CANDIDATE", source="deep_link_analyzer",
                            payload={"category": plan.category,
                                     "surface": plan.surface.to_dict(),
                                     "rationale": plan.rationale})
        except Exception as exc:  # advisory, never a gate
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(analysis.surfaces)} link surfaces, "
              f"{len(analysis.plans)} plans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

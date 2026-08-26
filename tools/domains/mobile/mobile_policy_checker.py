#!/usr/bin/env python3
"""BugWolf Mobile Policy Checker — deterministic static manifest/plist checks.

Runs a fixed set of static policy checks against an Android
``AndroidManifest.xml`` and/or iOS ``Info.plist``:

  Android:
    * ``android:allowBackup`` enabled                       (medium)
    * cleartext traffic (``usesCleartextTraffic`` or missing
      ``networkSecurityConfig`` allowing cleartext)          (high/medium)
    * exported components without a required permission      (high)
    * ``debuggable`` builds                                  (high)
    * low ``minSdkVersion``                                  (low)

  iOS:
    * ``NSAllowsArbitraryLoads`` (ATS bypass)                (high)
    * ``NSAllowsLocalNetworking`` / local exceptions          (low)
    * file-sharing / document-open entitlements               (low)
    * certificate-pinning config absence (informational)      (low)

Offline: input is the manifest/plist text or a pre-extracted summary JSON;
output is ``recon/<target>/discovery/mobile-policy-check.json`` (a
``coverage-plan`` artifact).  Emits ``MOBILE_CANDIDATE`` for high-severity
findings.  Uncensored: no scope/confirmation gates.

Usage:
  python3 tools/domains/mobile/mobile_policy_checker.py --target acme --manifest AndroidManifest.xml
  python3 tools/domains/mobile/mobile_policy_checker.py --target acme --plist Info.plist
  python3 tools/domains/mobile/mobile_policy_checker.py --target acme --summary extracted.json --json
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
from typing import Any, Dict, List, Optional

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
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn

SCHEMA = "bugwolf/mobile-policy-checker/v1"

_NS = {"android": "http://schemas.android.com/apk/res/android"}


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _attr(element: Any, name: str) -> str:
    return str(element.get(f"{{{_NS['android']}}}{name}") or "")


@dataclass
class PolicyFinding:
    finding_id: str
    platform: str
    check: str
    severity: str
    component: str
    detail: str
    validation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyCheckResult:
    target: str
    generated_at: str
    findings: List[PolicyFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _android_checks(manifest_text: str) -> List[PolicyFinding]:
    findings: List[PolicyFinding] = []
    if ET is None:
        return findings
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError:
        return findings

    # allowBackup
    for app in root.iter("application"):
        if _attr(app, "allowBackup").lower() == "true":
            findings.append(PolicyFinding(
                finding_id=_id("pf", "android", "allow-backup"),
                platform="android", check="allow_backup", severity="medium",
                component="application",
                detail="android:allowBackup=\"true\" — app data can be backed "
                       "up to a host machine (adb backup) and restored, "
                       "exposing local secrets/tokens.",
                validation_steps=[
                    "Run `adb backup -f backup.ab <package>` on a device and "
                    "inspect the archive for secrets (keys, tokens, session "
                    "data).",
                    "If sensitive data is extractable, the backup flag is a "
                    "data-exposure finding.",
                ]))
        # usesCleartextTraffic
        if _attr(app, "usesCleartextTraffic").lower() == "true":
            findings.append(PolicyFinding(
                finding_id=_id("pf", "android", "cleartext-traffic"),
                platform="android", check="cleartext_traffic",
                severity="high", component="application",
                detail="android:usesCleartextTraffic=\"true\" — the app "
                       "permits plaintext HTTP, enabling on-path capture of "
                       "credentials and tokens.",
                validation_steps=[
                    "Proxy the app traffic (mitmproxy/ Burp with CA "
                    "installed) and confirm plaintext HTTP requests carry "
                    "sensitive values.",
                ]))
        # debuggable
        if _attr(app, "debuggable").lower() == "true":
            findings.append(PolicyFinding(
                finding_id=_id("pf", "android", "debuggable"),
                platform="android", check="debuggable", severity="high",
                component="application",
                detail="android:debuggable=\"true\" — a debug build can be "
                       "attached via adb; `run-as` grants arbitrary "
                       "read/write of the app data directory.",
                validation_steps=[
                    "Connect adb and use `run-as <package>` to read the "
                    "app's private data directory.",
                ]))

    # minSdkVersion
    for uses_sdk in root.iter("uses-sdk"):
        min_sdk = _attr(uses_sdk, "minSdkVersion")
        if min_sdk and min_sdk.isdigit() and int(min_sdk) < 23:
            findings.append(PolicyFinding(
                finding_id=_id("pf", "android", "min-sdk"),
                platform="android", check="min_sdk", severity="low",
                component="uses-sdk",
                detail=f"minSdkVersion={min_sdk} (< 23) — older platforms "
                       "lack modern crypto/keystore and TLS hardening "
                       "(Android Keystore strongbox, network security "
                       "config defaults).",
                validation_steps=[]))

    # Exported components without permission
    for tag in ("activity", "service", "receiver"):
        for comp in root.iter(tag):
            exported = _attr(comp, "exported").lower() == "true"
            permission = _attr(comp, "permission")
            name = _attr(comp, "name") or f"<{tag}>"
            if exported and not permission:
                findings.append(PolicyFinding(
                    finding_id=_id("pf", "android", "exported", tag, name),
                    platform="android", check="exported_no_permission",
                    severity="high", component=name,
                    detail=f"{tag} '{name}' is exported with no required "
                           "permission — any app can invoke it (component "
                           "hijacking / privileged action replay).",
                    validation_steps=[
                        "Invoke the component from a second app or adb "
                        "(startActivity/startService/sendBroadcast).",
                        "If it performs a sensitive action without "
                        "authorization, record the cross-app trigger.",
                    ]))

    return findings


def _ios_checks(plist_text: str) -> List[PolicyFinding]:
    findings: List[PolicyFinding] = []
    if ET is None:
        return findings
    try:
        root = ET.fromstring(plist_text)
    except ET.ParseError:
        return findings

    text = plist_text  # regex fallback for flat keys
    # ATS: NSAllowsArbitraryLoads
    m = re.search(r"<key>NSAllowsArbitraryLoads</key>\s*<(?:true|false)/?>",
                  text)
    if m and "<true/>" in m.group(0):
        findings.append(PolicyFinding(
            finding_id=_id("pf", "ios", "ats-arbitrary"),
            platform="ios", check="ats_arbitrary_loads", severity="high",
            component="NSAppTransportSecurity",
            detail="NSAllowsArbitraryLoads=true — App Transport Security is "
                   "disabled for all connections; the app may send "
                   "credentials over plaintext HTTP.",
            validation_steps=[
                "Proxy app traffic and confirm plaintext HTTP requests carry "
                "sensitive values.",
            ]))
    m = re.search(r"<key>NSAllowsLocalNetworking</key>\s*<(?:true|false)/?>",
                  text)
    if m and "<true/>" in m.group(0):
        findings.append(PolicyFinding(
            finding_id=_id("pf", "ios", "ats-local"),
            platform="ios", check="ats_local_networking", severity="low",
            component="NSAppTransportSecurity",
            detail="NSAllowsLocalNetworking=true — local-network cleartext "
                   "exceptions are enabled (LAN attack surface).",
            validation_steps=[]))

    # File sharing / document opening
    for key_name in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"):
        m = re.search(rf"<key>{key_name}</key>\s*<(?:true|false)/?>", text)
        if m and "<true/>" in m.group(0):
            findings.append(PolicyFinding(
                finding_id=_id("pf", "ios", "file-sharing", key_name),
                platform="ios", check="file_sharing", severity="low",
                component=key_name,
                detail=f"{key_name}=true — app documents are exposed to "
                       "iTunes/file sharing; synced app data may be "
                       "extractable from a paired host.",
                validation_steps=[]))

    # Pinning: absence of a known pinning key is informational.
    if "NSExceptionDomains" not in text and "pinned" not in text.lower():
        findings.append(PolicyFinding(
            finding_id=_id("pf", "ios", "pinning"),
            platform="ios", check="pinning_config", severity="low",
            component="Info.plist",
            detail="No certificate-pinning configuration detected in the "
                   "plist — the app may rely on system trust alone "
                   "(certificate-pinning bypass / interception surface).",
            validation_steps=[
                "Install a user CA and proxy traffic: if the app "
                "accepts the proxy cert, no pinning is enforced.",
            ]))

    return findings


def analyze(target: str, *, manifest: Optional[str] = None,
            plist: Optional[str] = None,
            summary: Optional[Dict[str, Any]] = None) -> PolicyCheckResult:
    """Deterministically run the static policy checks."""
    result = PolicyCheckResult(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    if summary and isinstance(summary, dict):
        for entry in summary.get("findings", []):
            if isinstance(entry, dict):
                result.findings.append(PolicyFinding(
                    finding_id=str(entry.get("finding_id") or ""),
                    platform=str(entry.get("platform") or "android"),
                    check=str(entry.get("check") or ""),
                    severity=str(entry.get("severity") or "medium"),
                    component=str(entry.get("component") or ""),
                    detail=str(entry.get("detail") or ""),
                    validation_steps=list(entry.get("validation_steps") or []),
                ))
        return result
    if manifest:
        result.findings.extend(_android_checks(manifest))
    if plist:
        result.findings.extend(_ios_checks(plist))
    return result


def write_result(result: PolicyCheckResult, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to recon/<target>/discovery/mobile-policy-check.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(result.target)
    out_dir = root / "recon" / target_dir / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "mobile-policy-check.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Mobile static policy checker")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--manifest", default=None, help="path to AndroidManifest.xml")
    parser.add_argument("--plist", default=None, help="path to Info.plist (XML)")
    parser.add_argument("--summary", default=None, help="pre-extracted summary JSON")
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

    result = analyze(args.target, manifest=manifest_text, plist=plist_text,
                     summary=summary)
    out = write_result(result, project_root=args.project_root,
                       base_dir=args.base_dir)

    high = [f for f in result.findings if f.severity == "high"]
    for finding in high:
        publish_or_warn(args.target, "MOBILE_CANDIDATE",
                        source="mobile_policy_checker",
                        payload={"check": finding.check,
                                 "component": finding.component,
                                 "detail": finding.detail},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(result.findings)} policy findings -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

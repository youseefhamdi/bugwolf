"""Week 3 tests: IAM privesc graph, deep-link analyzer, mobile policy
checker, historical asset delta."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.domains.cloud import iam_privesc_graph as iam
from tools.domains.mobile import deep_link_analyzer as dla
from tools.domains.mobile import mobile_policy_checker as mpc
from tools.recon import historical_asset_delta as had

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".WebActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="myapp" android:host="open" android:pathPrefix="/web?url="/>
      </intent-filter>
    </activity>
    <activity android:name=".SecureActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="myapp" android:host="pay"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>acmeapp</string>
                <string>acme-oauth</string>
            </array>
        </dict>
    </array>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
"""


def _without_ts(obj):
    if isinstance(obj, dict):
        return {k: _without_ts(v) for k, v in obj.items() if k != "generated_at"}
    if isinstance(obj, list):
        return [_without_ts(v) for v in obj]
    return obj


class TestIamPrivescGraph(unittest.TestCase):
    def test_parse_policy_dump_variants(self):
        stmts = iam.parse_policy_dump({
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject"},
            ]},
        })
        self.assertEqual(len(stmts), 1)
        stmts = iam.parse_policy_dump([{"Statement": {"Effect": "Allow",
                                                      "Action": "ec2:*"}}])
        self.assertEqual(len(stmts), 1)
        self.assertEqual(iam.parse_policy_dump("junk"), [])

    def test_wildcard_matching(self):
        self.assertTrue(iam._wildcard_matches("iam:*", "iam:CreatePolicyVersion"))
        self.assertTrue(iam._wildcard_matches("iam:Create*", "iam:CreatePolicyVersion"))
        self.assertFalse(iam._wildcard_matches("iam:Get*", "iam:CreatePolicyVersion"))
        self.assertTrue(iam._wildcard_matches("*", "sts:AssumeRole"))

    def test_create_policy_version_reaches_admin(self):
        analysis = iam.analyze("acme", {
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion",
                 "Resource": "*"},
            ]},
        })
        self.assertTrue(analysis.admin_reachable)
        self.assertGreaterEqual(len(analysis.directly_reachable), 20)

    def test_passrole_lambda_reaches_role_takeover_without_admin(self):
        analysis = iam.analyze("acme", {
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow",
                 "Action": ["iam:PassRole", "lambda:CreateFunction"],
                 "Resource": "*"},
            ]},
        })
        self.assertFalse(analysis.admin_reachable)
        gained = {h.gained for h in analysis.directly_reachable}
        self.assertIn("role_takeover", gained)
        names = {h.method_id for h in analysis.directly_reachable}
        self.assertIn("PassRoleLambdaCreate", names)
        # No policy-write / admin methods reachable.
        self.assertNotIn("AttachUserPolicy", names)

    def test_no_privileged_actions(self):
        analysis = iam.analyze("acme", {
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            ]},
        })
        self.assertFalse(analysis.admin_reachable)
        self.assertEqual(len(analysis.directly_reachable), 0)

    def test_deny_not_counted(self):
        analysis = iam.analyze("acme", {
            "PolicyDocument": {"Statement": [
                {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
            ]},
        })
        self.assertEqual(len(analysis.directly_reachable), 0)

    def test_deterministic(self):
        policy = {"PolicyDocument": {"Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"],
             "Resource": "*"},
        ]}}
        a1 = _without_ts(iam.analyze("acme", policy).to_dict())
        a2 = _without_ts(iam.analyze("acme", policy).to_dict())
        self.assertEqual(a1, a2)

    def test_write_path(self):
        analysis = iam.analyze("acme", {"Statement": [
            {"Effect": "Allow", "Action": "iam:AttachUserPolicy"},
        ]})
        with tempfile.TemporaryDirectory() as td:
            out = iam.write_analysis(analysis, base_dir=td)
            self.assertTrue(out.exists())
            self.assertEqual(out.name, "iam-privesc-acme.json")
            self.assertIn("capability", str(out))


class TestDeepLinkAnalyzer(unittest.TestCase):
    def test_android_surface_extraction(self):
        surfaces = dla.parse_android_manifest(MANIFEST)
        self.assertEqual(len(surfaces), 2)
        by_host = {s.host: s for s in surfaces}
        self.assertIn("open", by_host)
        self.assertEqual(by_host["open"].scheme, "myapp")
        self.assertEqual(by_host["open"].path, "/web?url=")
        self.assertTrue(by_host["open"].exported)

    def test_link_hijacking_plan(self):
        analysis = dla.analyze("acme", manifest=MANIFEST)
        hijacks = [p for p in analysis.plans if p.category == "link_hijacking"]
        self.assertEqual(len(hijacks), 2)
        by_host = {p.surface.host: p for p in hijacks}
        # No-path surface is high, path-carrying one is medium.
        self.assertEqual(by_host["pay"].severity, "high")
        self.assertEqual(by_host["open"].severity, "medium")

    def test_sensitive_navigation_detected(self):
        analysis = dla.analyze("acme", manifest=MANIFEST)
        sensitive = [p for p in analysis.plans
                     if p.category == "sensitive_navigation"]
        self.assertEqual(len(sensitive), 1)
        self.assertEqual(sensitive[0].surface.host, "open")
        self.assertEqual(sensitive[0].severity, "high")

    def test_intent_url_plan(self):
        analysis = dla.analyze("acme", summary={
            "surfaces": [{"platform": "android", "scheme": "intent",
                          "host": "myapp", "component": ".WebActivity",
                          "exported": True}],
        })
        intent = [p for p in analysis.plans if p.category == "intent_url"]
        self.assertEqual(len(intent), 1)

    def test_ios_plist_schemes(self):
        surfaces = dla.parse_ios_links(PLIST)
        schemes = {s.scheme for s in surfaces}
        self.assertIn("acmeapp", schemes)
        self.assertIn("acme-oauth", schemes)
        self.assertTrue(all(s.exported for s in surfaces))

    def test_summary_input(self):
        analysis = dla.analyze("acme", summary={
            "surfaces": [{"platform": "ios", "scheme": "acmeapp",
                          "component": "app", "exported": True}],
        })
        self.assertEqual(len(analysis.surfaces), 1)
        self.assertGreaterEqual(len(analysis.plans), 1)

    def test_deterministic(self):
        a1 = _without_ts(dla.analyze("acme", manifest=MANIFEST).to_dict())
        a2 = _without_ts(dla.analyze("acme", manifest=MANIFEST).to_dict())
        self.assertEqual(a1, a2)


class TestMobilePolicyChecker(unittest.TestCase):
    def test_android_checks(self):
        result = mpc.analyze("acme", manifest=MANIFEST)
        checks = {f.check for f in result.findings}
        self.assertIn("allow_backup", checks)
        self.assertIn("cleartext_traffic", checks)
        self.assertIn("exported_no_permission", checks)
        by_check = {f.check: f for f in result.findings}
        self.assertEqual(by_check["cleartext_traffic"].severity, "high")
        self.assertEqual(by_check["allow_backup"].severity, "medium")

    def test_min_sdk_low(self):
        manifest = MANIFEST.replace(
            "</manifest>",
            '<uses-sdk android:minSdkVersion="19"/></manifest>')
        result = mpc.analyze("acme", manifest=manifest)
        min_sdk = [f for f in result.findings if f.check == "min_sdk"]
        self.assertEqual(len(min_sdk), 1)

    def test_ios_ats(self):
        result = mpc.analyze("acme", plist=PLIST)
        by_check = {f.check: f for f in result.findings}
        self.assertEqual(by_check["ats_arbitrary_loads"].severity, "high")

    def test_summary_input(self):
        result = mpc.analyze("acme", summary={"findings": [
            {"finding_id": "x", "platform": "android", "check": "cleartext_traffic",
             "severity": "high", "component": "application", "detail": "d"},
        ]})
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].check, "cleartext_traffic")


class TestHistoricalAssetDelta(unittest.TestCase):
    SNAPSHOTS = [
        {"as_of": "2026-01",
         "assets": ["api.example.com", "old.example.com", "blog.example.com",
                    "dev.example.com"]},
        {"as_of": "2026-04",
         "assets": ["api.example.com", "blog.example.com", "staging.example.com"]},
        {"as_of": "2026-07",
         "assets": ["api.example.com", "blog.example.com", "old.example.com",
                    "staging.example.com", "new.example.com"]},
    ]

    def test_delta_categories(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.added.assets, ["new.example.com",
                                              "staging.example.com"])
        self.assertEqual(delta.removed.assets, ["dev.example.com"])
        self.assertEqual(delta.reattached.assets, ["old.example.com"])
        self.assertEqual(delta.forgotten.assets, ["dev.example.com"])
        self.assertEqual(delta.total_tracked, 6)

    def test_two_snapshots(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS[:2])
        self.assertEqual(delta.added.assets, ["staging.example.com"])
        self.assertEqual(delta.removed.assets, ["dev.example.com",
                                                "old.example.com"])
        self.assertEqual(delta.reattached.count, 0)

    def test_import_and_history_merge(self):
        records = [
            {"name": "api.example.com", "first_seen": "2026-01", "last_seen": "2026-03"},
            {"name": "api.example.com", "first_seen": "2026-05", "last_seen": "2026-07"},
            {"name": "new.example.com", "first_seen": "2026-06", "last_seen": "2026-06"},
        ]
        with tempfile.TemporaryDirectory() as td:
            obs = had.ingest_historical("acme", records, base_dir=td)
            self.assertIn("api.example.com", obs)
            self.assertEqual(obs["api.example.com"].first_seen, "2026-01")
            self.assertEqual(obs["api.example.com"].last_seen, "2026-07")
            hist = had.history_path(Path(td), "acme")
            self.assertTrue(hist.exists())
            lines = [l for l in hist.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 3)

    def test_canonicalization(self):
        delta = had.compute_delta("acme", [
            {"as_of": "a", "assets": ["API.Example.COM"]},
            {"as_of": "b", "assets": ["api.example.com."]},
        ])
        self.assertEqual(delta.total_tracked, 1)
        self.assertEqual(delta.reattached.count, 0)

    def test_load_snapshot_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "snap.jsonl"
            p.write_text(json.dumps({"name": "api.example.com"}) + "\n" +
                         json.dumps({"subdomain": "blog.example.com"}) + "\n")
            snap = had._load_snapshot(p)
            self.assertEqual(len(snap["assets"]), 2)

    def test_deterministic(self):
        d1 = had.compute_delta("acme", self.SNAPSHOTS).to_dict()
        d2 = had.compute_delta("acme", self.SNAPSHOTS).to_dict()
        self.assertEqual(d1, d2)


if __name__ == "__main__":
    unittest.main()

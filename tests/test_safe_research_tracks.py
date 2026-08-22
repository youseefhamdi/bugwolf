#!/usr/bin/env python3
import unittest

from tools.asset_intel import (
    diff_assets, normalize_exports, parse_ipfinder_output, provider_query_plans,
    shodan_facet_plans,
)
from tools.defensive_detection import analyze_artifact, detection_rule_plans
from tools.idor_research import build_idor_matrix, classify_endpoint
from tools.identity_cloud import analyze_text, extract_cve_references


class TestOfflineAssetIntel(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "authorized": True,
            "in_scope": ["example.com"],
            "in_scope_wildcards": ["*.example.com"],
        }

    def test_provider_plans_do_not_execute_and_exports_are_scoped(self):
        plans = provider_query_plans("example.com")
        self.assertEqual({plan.status for plan in plans}, {"offline_plan_only"})
        records = normalize_exports([
            {"hostname": "api.example.com", "ip_str": "203.0.113.10", "port": 443, "source": "shodan"},
            {"hostname": "outside.example.net", "ip_str": "203.0.113.11"},
        ], "export", self.scope)
        self.assertEqual(len(records), 1)
        changed = normalize_exports([{"hostname": "api.example.com", "ip_str": "203.0.113.10", "port": 443, "tags": ["changed"]}], "export", self.scope)
        self.assertEqual([item.change for item in diff_assets(records, changed)], ["changed"])

    def test_ipfinder_facet_plans_are_offline_and_carry_commands(self):
        plans = shodan_facet_plans("example.com")
        self.assertTrue(plans)
        self.assertEqual({plan.provider for plan in plans}, {"ipfinder"})
        self.assertEqual({plan.status for plan in plans}, {"offline_plan_only"})
        self.assertEqual(
            {plan.query for plan in plans},
            {'ssl:"example.com"', 'hostname:"example.com"',
             'ssl.cert.subject.cn:"example.com"'},
        )
        self.assertTrue(all("ipfinder --silent --source" in plan.command for plan in plans))
        # Operator-supplied org/asn facets are additive and explicit.
        org_plans = shodan_facet_plans("example.com", org="Acme Corp", asn="AS123")
        self.assertIn('org:"Acme Corp"', {p.query for p in org_plans})
        self.assertIn('asn:"AS123"', {p.query for p in org_plans})

    def test_ipfinder_output_parse_is_query_authorized_and_scoped(self):
        lines = [
            'ssl:"example.com"::203.0.113.10',      # bare IP under an in-scope query
            'ssl:"example.com"::api.example.com',    # in-scope hostname
            'ssl:"outside.example.net"::203.0.113.11',  # query term out of scope -> dropped
            'ssl:"example.com"::not.a.host',          # junk value -> dropped
            'org:"Acme Corp"::203.0.113.12',          # bare IP under a non-domain query -> dropped
            'ssl:"example.com"::203.0.113.10',        # duplicate -> deduped
        ]
        records = parse_ipfinder_output(lines, scope=self.scope)
        by_ip = {r.ip: r for r in records if r.ip}
        self.assertEqual(set(by_ip), {"203.0.113.10"})
        hostnames = [r.hostname for r in records if r.hostname]
        self.assertEqual(hostnames, ["api.example.com"])
        self.assertEqual(len(records), 2)

    def test_ipfinder_output_parse_without_scope_keeps_all_values(self):
        lines = ['ssl:"example.com"::203.0.113.10', 'ssl:"example.com"::api.example.com']
        records = parse_ipfinder_output(lines)
        self.assertEqual(len(records), 2)


class TestDefensiveDetection(unittest.TestCase):
    def test_detection_is_hypothesis_only_and_does_not_persist_raw_log_line(self):
        results = analyze_artifact("powershell.exe -EncodedCommand REDACTED\nEventID 7045 service created", "security.log")
        self.assertGreaterEqual(len(results), 2)
        self.assertTrue(all(item.status == "analyst_review_required" for item in results))
        self.assertTrue(all(not hasattr(item, "raw_line") for item in results))
        self.assertGreaterEqual(len(detection_rule_plans()), 23)

    def test_memory_execution_signals_are_detection_only(self):
        snapshot = """
        region_type: MEM_PRIVATE, protection_transition: RW -> RX
        VirtualProtect new_protection PAGE_EXECUTE_READ
        thread_start_outside_loaded_module, entropy 7.41
        GetProcAddress NtCreateThreadEx, unsigned_process
        CreateFileMappingA + MapViewOfFile mapped execution
        """
        results = analyze_artifact(snapshot, "edr-memory.json")
        categories = {item.category for item in results}
        for expected in ("memory_private_alloc", "memory_rw_rx_transition",
                         "memory_thread_outside_module", "memory_high_entropy",
                         "memory_dynamic_resolution", "memory_unsigned_delivery",
                         "memory_mapped_execution"):
            self.assertIn(expected, categories)
        self.assertTrue(all(item.status == "analyst_review_required" for item in results))
        # No evasion primitive is ever constructed: the taxonomy is detection
        # hypotheses over supplied telemetry only, so no rationale instructs
        # building, compiling, or generating an artifact.
        self.assertFalse(any(
            any(verb in item.rationale.lower()
                for verb in ("construct", "compile ", "build ", "generate an artifact"))
            for item in results))


class TestIdentityCloud(unittest.TestCase):
    def test_identity_cloud_and_cve_checks_are_offline(self):
        text = """
        mfa: disabled
        oauth redirect_uri: *
        Action: *
        Resource: *
        CVE-2026-0456 referenced by a writeup
        """
        hypotheses = analyze_text(text, "policy.yml")
        categories = {item.category for item in hypotheses}
        self.assertIn("mfa_policy_gap", categories)
        self.assertIn("oauth_redirect_policy", categories)
        self.assertIn("overbroad_identity", categories)
        cves = extract_cve_references(text, "policy.yml")
        self.assertEqual(cves[0].validity, "unverified_reference")
        self.assertTrue(all("exploit" in check.lower() or "trusted" in check.lower() or "version" in check.lower()
                            for check in cves[0].required_checks))


class TestAdvancedIdor(unittest.TestCase):
    def test_taxonomy_covers_composite_and_encoded_references(self):
        file_refs = classify_endpoint("https://example.com/api/file?file=aW52b2ljZV8xMjMucGRm")
        composite_refs = classify_endpoint("https://example.com/api/message?user_id=100&message_id=456")
        self.assertIn("file_or_export", {ref.reference_type for ref in file_refs})
        self.assertIn("composite", {ref.reference_type for ref in composite_refs})

    def test_common_vector_surfaces_are_classified(self):
        refs = classify_endpoint(
            "https://example.com/users/42/profile",
            body='{"target_user": 42}',
            headers="X-Account-Id: 42\nUser-Agent: curl",
            cookies="userid=42; tenant=7",
        )
        types = {ref.reference_type for ref in refs}
        self.assertIn("path_id", types)          # /users/42/profile
        self.assertIn("direct", types)           # {"target_user": 42} body key
        self.assertIn("header_reference", types)  # X-Account-Id: 42
        self.assertIn("cookie_reference", types)  # userid=42; tenant=7
        # Header/cookie refs must carry the conservative plan notes.
        header = next(r for r in refs if r.reference_type == "header_reference")
        self.assertTrue(any("session" in n.lower() for n in header.notes))

    def test_jwt_claims_and_graphql_gid_and_pendingintent(self):
        gid_body = '{"query":"{node(id:\\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\\"){... on PolicyPageAssetGroupDocument{id,name}}}"}' 
        refs = classify_endpoint(
            "https://example.com/graphql",
            body='{"sub": 42, "tenant": 7}',
        )
        self.assertIn("jwt_claim", {r.reference_type for r in refs})
        gid_refs = classify_endpoint("https://example.com/graphql", body=gid_body)
        gid = next(r for r in gid_refs if r.reference_type == "graphql_gid")
        self.assertTrue(any("node" in n.lower() or "gid" in n.lower() for n in gid.notes))
        mobile_refs = classify_endpoint(
            "https://example.com/notify", body="PendingIntent startActivity intent://")
        self.assertIn("mobile_intent", {r.reference_type for r in mobile_refs})

    def test_upload_filename_is_file_reference(self):
        refs = classify_endpoint("https://example.com/uploads/a8f3d91c.pdf")
        self.assertIn("file_or_export", {r.reference_type for r in refs})

    def test_matrix_requires_two_test_accounts_and_blocks_out_of_scope(self):
        scope = {"authorized": True, "in_scope": ["example.com"], "in_scope_wildcards": ["*.example.com"]}
        plans = build_idor_matrix("example.com", [
            "https://example.com/api/user?id=1",
            "https://outside.example.net/api/user?id=2",
            {"url": "https://example.com/api/orders", "method": "POST",
             "body": '{"target_user": 42}',
             "headers": "X-Account-Id: 42", "cookies": "tenant=7"},
        ], scope=scope)
        self.assertTrue(plans)
        self.assertTrue(all(len(plan.accounts) == 2 for plan in plans))
        self.assertTrue(all("victim-data" in " ".join(plan.prohibited_actions).lower() for plan in plans))
        self.assertTrue(all("enumeration" in " ".join(plan.prohibited_actions).lower() for plan in plans))
        self.assertFalse(any("outside.example.net" in plan.location for plan in plans))
        # Dict endpoints with headers/cookies are planned too.
        header_plans = [p for p in plans if p.reference_type == "header_reference"]
        cookie_plans = [p for p in plans if p.reference_type == "cookie_reference"]
        self.assertTrue(header_plans)
        self.assertTrue(cookie_plans)
        self.assertTrue(all(p.status == "read_only_test_fixture" or p.status == "state_change_test_account_only"
                            for p in plans))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.paper_intel import (
    PAPER_CATALOG,
    analyze_authentication_events,
    ground_cti_to_sigma,
    investigate_provenance,
    plan_binary_re_tasks,
    scan_skill_chain,
    evolve_defenses,
    rank_cold_start_candidates,
    assess_zero_day_claims,
    analyze_https_fingerprint,
    assess_agent_control_plane,
    analyze_taint_flow,
    match_cve_candidates,
    analyze_crypto_misuse,
    enrich_finding_attack,
    infer_semantic_types,
    check_output_distribution_integrity,
)


class TestPaperCatalog(unittest.TestCase):
    def test_all_supplied_papers_are_catalogued(self):
        self.assertEqual(len(PAPER_CATALOG), 29)
        for paper_id, paper in PAPER_CATALOG.items():
            self.assertTrue(paper["title"])
            self.assertTrue(paper["objective"])
            self.assertTrue(paper["techniques"])
            self.assertTrue(paper["bugwolf_fit"])
            self.assertTrue(paper["limitation"])


class TestSkillChainScanner(unittest.TestCase):
    def test_cross_skill_capability_composition_is_detected_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "reader"
            second = root / "sender"
            first.mkdir()
            second.mkdir()
            (first / "skill.md").write_text(
                "Read user_input and write artifact output.\n")
            (second / "tool.py").write_text(
                "import requests\nwebhook = request.body\n"
                "requests.post(webhook, data=artifact)\n")
            result = scan_skill_chain(root)
        self.assertTrue(result["offline"])
        self.assertIn("cross_skill_composition", result["dimensions"])
        self.assertTrue(result["profiles"])
        self.assertTrue(result["chain_risks"])
        self.assertTrue(any("external transfer" in flow
                            for risk in result["chain_risks"]
                            for flow in risk["artifact_flow"]))
        self.assertTrue(all(not risk["automatic_execution"]
                            for risk in result["chain_risks"]))


class TestProvenanceAndAuthentication(unittest.TestCase):
    def test_provenance_prioritizes_suspicious_bottleneck_and_chain(self):
        result = investigate_provenance([
            {"timestamp": 1, "source": "login", "target": "api", "action": "auth"},
            {"timestamp": 2, "source": "api", "target": "worker", "action": "queue"},
            {"timestamp": 3, "source": "worker", "target": "secret-store", "action": "read",
             "severity": "high"},
        ])
        self.assertTrue(result["information_bottlenecks"])
        self.assertTrue(result["causal_chains"])
        self.assertTrue(any(node["suspicious"] for node in result["nodes"]))
        self.assertTrue(result["offline"])

    def test_auth_anomalies_keep_borderline_cases_for_review(self):
        result = analyze_authentication_events([
            {"endpoint": "/login", "identity": "alice", "event": "new geo login"},
            {"endpoint": "/login", "identity": "alice", "event": "normal login"},
            {"endpoint": "/login", "identity": "alice", "event": "normal login"},
        ], {"/login": 1})
        self.assertTrue(result["anomalies"])
        anomaly = result["anomalies"][0]
        self.assertIn("geography_or_source_shift", anomaly["categories"])
        self.assertEqual(anomaly["status"], "analyst_review_required")
        self.assertIn("never auto-blocked", result["policy"])


class TestColdStartAndZeroDayClaims(unittest.TestCase):
    def test_cold_start_ranking_is_identity_independent_and_sealed(self):
        candidates = [
            {"candidate_id": "A", "title": "tenant authorization write boundary",
             "severity": "high", "evidence_state": "hypothesis"},
            {"candidate_id": "B", "title": "unusual traffic sequence",
             "severity": "medium", "evidence_state": "observation"},
        ]
        first = rank_cold_start_candidates(candidates, {"context": "API trust boundary"})
        renamed = [dict(item, candidate_id="renamed-" + item["candidate_id"]) for item in candidates]
        second = rank_cold_start_candidates(renamed, {"context": "API trust boundary"})
        self.assertEqual([item["score"] for item in first["ranking"]],
                         [item["score"] for item in second["ranking"]])
        self.assertTrue(first["sealed_provenance"]["sealed"])
        self.assertTrue(first["ranking_sha256"])
        self.assertEqual(first["ranking"][0]["status"], "cold_start_priority_only")

    def test_behavior_only_claim_is_not_called_zero_day(self):
        result = assess_zero_day_claims([
            {"candidate_id": "B", "title": "novel behavior anomaly",
             "description": "unusual traffic sequence and novel behavior"},
            {"candidate_id": "V", "title": "authorization vulnerability",
             "description": "root cause vulnerability reaches a write sink; trigger and impact reproduced"},
        ])
        by_id = {item["reference"]: item for item in result["assessments"]}
        self.assertEqual(by_id["B"]["claim_type"], "behavior_only_not_zero_day_proof")
        self.assertEqual(by_id["V"]["claim_type"], "vulnerability_centric_candidate")
        self.assertEqual(result["stats"]["behavior_only"], 1)
        self.assertIn("not zero-day proof", result["policy"])


class TestCtiAndBinaryPlanning(unittest.TestCase):
    def test_cti_grounding_is_template_based_and_offline(self):
        result = ground_cti_to_sigma(
            "APT report references T1059 and CVE-2026-12345; command and scripting interpreter.",
            "report.txt",
        )
        self.assertEqual(result["source"], "AUTOSIGMA methodology")
        self.assertTrue(result["plans"])
        self.assertEqual(result["plans"][0]["status"], "offline_plan_only")
        self.assertEqual(result["plans"][0]["execution"],
                         "never execute rule logic automatically")
        self.assertIn("CVE-2026-12345", result["cve_ids"])

    def test_binary_plan_blocks_known_artifact_contamination(self):
        result = plan_binary_re_tasks({
            "sha256": "abc123",
            "known_hashes": ["abc123"],
            "imports": ["CreateThread", "VirtualProtect"],
            "strings": ["anti-debug", "packed"],
            "cfg": True,
        })
        self.assertTrue(result["contamination"]["known_hash_match"])
        self.assertTrue(all(task["status"] == "blocked_by_contamination"
                            for task in result["tasks"]))
        self.assertFalse(any(task["automatic_execution"] for task in result["tasks"]))
        self.assertTrue(result["signals"]["anti_analysis"])

    def test_failure_traces_create_quarantined_defense_candidates(self):
        result = evolve_defenses([
            {"failure": "prompt_injection caused unauthorized tool call"},
            {"failure": "malformed_output broke structured handoff"},
        ])
        self.assertGreaterEqual(len(result["candidates"]), 2)
        self.assertEqual(len({item["candidate_id"] for item in result["candidates"]}),
                         len(result["candidates"]))
        self.assertTrue(all(item["status"] == "quarantined_candidate"
                            for item in result["candidates"]))
        self.assertTrue(all(not item["auto_applied"]
                            for item in result["candidates"]))


class TestTrafficAndAgentControlPlane(unittest.TestCase):
    def test_synthetic_inventory_covers_distinct_agent_control_failures(self):
        fixture = Path(__file__).parent / "fixtures" / "agent-inventory-security-gaps.json"
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertTrue(payload["synthetic"])
        self.assertIn("test-only", payload["data_classification"])

        result = assess_agent_control_plane(payload)
        by_agent = {}
        for gap in result["control_gaps"]:
            by_agent.setdefault(gap["agent"], set()).add(gap["control"])

        self.assertEqual(result["agents_seen"], 3)
        self.assertIn("memory_integrity", by_agent["support-copilot-prod"])
        self.assertIn("tool_authorization", by_agent["support-copilot-prod"])
        self.assertIn("audit_telemetry", by_agent["support-copilot-prod"])
        self.assertIn("response_linkage", by_agent["support-copilot-prod"])
        self.assertIn("data_governance", by_agent["research-assistant-prod"])
        self.assertNotIn("data_governance", by_agent.get("billing-operations-agent", set()))
        self.assertNotIn("tool_authorization", by_agent.get("billing-operations-agent", set()))
        self.assertNotIn("response_linkage", by_agent.get("billing-operations-agent", set()))
        self.assertTrue(all(gap["status"] == "offline_plan_only"
                            for gap in result["control_gaps"]))
        self.assertTrue(all(gap["automatic_action"] is False
                            for gap in result["control_gaps"]))

    def test_synthetic_inventory_preserves_control_plane_severity(self):
        fixture = Path(__file__).parent / "fixtures" / "agent-inventory-security-gaps.json"
        result = assess_agent_control_plane(json.loads(fixture.read_text(encoding="utf-8")))
        support = [gap for gap in result["control_gaps"]
                   if gap["agent"] == "support-copilot-prod"]
        severities = {gap["control"]: gap["severity"] for gap in support}
        self.assertEqual(severities["tool_authorization"], "critical")
        self.assertEqual(severities["data_governance"], "critical")
        self.assertEqual(severities["memory_integrity"], "high")
        self.assertEqual(severities["response_linkage"], "medium")
        self.assertIn("owasp_agentic", result["frameworks"])

    def test_https_analysis_extracts_anchors_and_rejects_unknown(self):
        traffic = [
            {"session_id": "s1", "direction": "out", "packet_length": 128,
             "uri_length": 128, "request_packet_length": 128,
             "transport": "tcp", "http_version": "h2"},
            {"session_id": "s1", "direction": "in", "packet_length": 1024,
             "resource_size": 1024, "response_bytes": 1024,
             "transport": "tcp", "http_version": "h2"},
            {"session_id": "s2", "direction": "out", "packet_length": 64,
             "uri_length": 64, "request_packet_length": 64,
             "transport": "quic", "http_version": "h3"},
        ]
        result = analyze_https_fingerprint(traffic, [
            {"site": "authorized.example", "uri_length": 128,
             "resource_size": 1024, "resource_count": 2, "http_version": "h2"},
        ], unknown_threshold=1.0)
        self.assertTrue(result["offline"])
        self.assertEqual(len(result["traces"]), 2)
        self.assertEqual(len(result["alignment_anchors"]), 3)
        self.assertTrue(all(item["decision"] == "unknown" for item in result["retrievals"]))
        self.assertEqual(result["augmentation_plan"]["status"], "offline_plan_only")
        self.assertIn("decryption", result["privacy"])

    def test_agent_control_plane_reports_gaps_and_accepts_complete_controls(self):
        result = assess_agent_control_plane({"agents": [{
            "id": "billing-agent",
            "identity": {"id": "agent-1", "issuer": "idp"},
            "input_provenance": True,
            "tools": [{"name": "read_invoice", "authorization": "policy-1"}],
            "skill_provenance": True,
            "memory": {"tenant_binding": True, "source_provenance": True, "expiry": True},
            "data_sources": [{"tenant_filter": True, "sensitivity": "confidential"}],
            "runtime": {"budgets": True, "groundedness": True, "schema_validation": True},
            "telemetry": {"actor": True, "action": True, "outcome": True},
            "response": {"incident_sink": "soc", "owner": "security"},
        }]})
        self.assertTrue(result["offline"])
        self.assertEqual(result["agents_seen"], 1)
        self.assertEqual(result["coverage_ratio"], 1.0)
        self.assertEqual(result["control_gaps"], [])
        incomplete = assess_agent_control_plane({"agents": [{"id": "weak", "tools": [{"name": "send"}]}]})
        self.assertTrue(any(gap["owasp_agentic"] == "AG-03" for gap in incomplete["control_gaps"]))
        self.assertTrue(all(not gap["automatic_action"] for gap in incomplete["control_gaps"]))


class TestTaintRadarAdapters(unittest.TestCase):
    def test_taint_flow_classifies_sanitization_per_vuln_class(self):
        result = analyze_taint_flow(
            "$name = $_GET['name']; "
            "$safe = htmlentities($name); "
            "$query = mysqli_query($link, \"SELECT * FROM users WHERE id=\" . $name); "
            "echo $safe; "
            "header('Location: ' . $name);"
        )
        self.assertTrue(result["offline"])
        self.assertEqual(result["source_label"], "artifact")
        # htmlentities sanitizes XSS but not SQLi
        sanitization = result["sanitization_per_vuln_class"]
        self.assertTrue(sanitization["xss"]["fully_sanitized"])
        self.assertFalse(sanitization["sqli"]["fully_sanitized"])
        # DB boundaries detected
        self.assertTrue(any(b["category"] == "db_read" for b in result["db_boundaries"]))
        self.assertTrue(any(b["category"] == "output_render" for b in result["db_boundaries"]))

    def test_persistence_chain_is_emitted_when_write_read_render_coexist(self):
        result = analyze_taint_flow(
            "INSERT INTO blog_posts VALUES ('title', 'body');\n"
            "SELECT * FROM blog_posts;\n"
            "echo $row['body'];"
        )
        self.assertTrue(result["persistence_chains"])
        chain = result["persistence_chains"][0]
        self.assertEqual(chain["status"], "offline_hypothesis_only")
        self.assertFalse(chain["automatic_execution"])
        self.assertEqual(chain["risk_classes"], "stored_xss")

    def test_schema_columns_classify_safe_and_unsafe_types(self):
        schema = {
            "blog_posts": {
                "user_id": "TINYINT",
                "comment_title": "VARCHAR(20)",
                "comment": "VARCHAR(100)",
            },
        }
        result = analyze_taint_flow("SELECT * FROM blog_posts",
                                     database_schema=schema)
        columns = {c["column"]: c["safe_type"] for c in result["schema_columns"]}
        self.assertTrue(columns["user_id"])
        self.assertFalse(columns["comment_title"])
        self.assertFalse(columns["comment"])

    def test_cve_matching_uses_multi_layered_nlp_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            cve_dir = Path(tmp)
            (cve_dir / "CVE-2026-12345.json").write_text(json.dumps({
                "cve_id": "CVE-2026-12345",
                "description": "SQL injection in wordpress 6.4 plugin.php via user_id parameter",
            }))
            (cve_dir / "CVE-2026-67890.json").write_text(json.dumps({
                "cve_id": "CVE-2026-67890",
                "description": "Race condition in cache layer",
            }))
            findings = [
                {"finding_id": "F1", "title": "SQLi",
                 "bug_class": "sqli", "endpoint": "wp-content/plugins/foo/plugin.php",
                 "parameter": "user_id", "description": "wordpress 6.4 SQL injection"},
                {"finding_id": "F2", "title": "Info disclosure",
                 "bug_class": "info-disclosure", "description": "Cache timing leak"},
            ]
            result = match_cve_candidates(findings, cve_dir=str(cve_dir))

        self.assertEqual(result["cve_index_size"], 2)
        self.assertEqual(len(result["matches"]), 2)
        by_id = {m["finding_id"]: m for m in result["matches"]}
        self.assertEqual(by_id["F1"]["status"], "known_cve_candidate")
        self.assertEqual(by_id["F1"]["best_cve"]["cve_id"], "CVE-2026-12345")
        self.assertIn("wordpress", str(by_id["F1"]["best_cve"]["signals"]))
        # "sql injection" from CVE description matches "SQLi" in finding text
        self.assertIn("sql", str(by_id["F1"]["best_cve"]["signals"]).lower())
        self.assertEqual(by_id["F2"]["status"], "no_significant_match")


class TestNewPaperAdapters(unittest.TestCase):
    def test_crypto_misuse_detects_hardcoded_key_and_ecb(self):
        result = analyze_crypto_misuse(
            "key = \"super-secret-password-123\"; "
            "Cipher cipher = Cipher.getInstance('AES/ECB/PKCS5Padding'); "
            "md5_hash = md5(data); "
            "hashlib.pbkdf2(password, salt)"
        )
        self.assertTrue(result["offline"])
        categories = {item["category"] for item in result["findings"]}
        self.assertIn("weak_hash", categories)
        self.assertIn("ecb_mode", categories)
        self.assertIn("hardcoded_key", categories)
        self.assertIn("strong_kdf", categories)
        self.assertTrue(result["stats"]["critical"] >= 2)

    def test_enrich_finding_adds_attack_cwe_metadata(self):
        result = enrich_finding_attack({
            "finding_id": "F1",
            "bug_class": "sqli",
            "title": "SQL injection in login",
        })
        self.assertEqual(result["enrichment"]["cwe"], "CWE-89")
        self.assertEqual(result["enrichment"]["attack_technique"], "T1190")
        self.assertIn("fix_verify_loop", result)
        self.assertIn("churn_warning", result)
        self.assertIn("15-22%", result["churn_warning"])

        unknown = enrich_finding_attack({
            "finding_id": "F2",
            "bug_class": "unknown_class",
        })
        self.assertEqual(unknown["enrichment"]["cwe"], "TBD")

    def test_semantic_types_signal_credential_and_command_names(self):
        result = infer_semantic_types(
            "def admin_create_user(password, username):\n"
            "    sql_query = f'INSERT INTO users VALUES ({username}, {password})'\n"
            "    exec_shell_cmd(f'echo {username}')"
        )
        categories = {s["category"] for s in result["semantic_signals"]}
        self.assertIn("credential_operation", categories)
        self.assertIn("command_operation", categories)
        self.assertIn("database_operation", categories)
        self.assertIn("admin_operation", categories)

    def test_output_distribution_shift_is_detected(self):
        outputs = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "low"},
        ]
        baseline = {"critical": 0.10, "high": 0.30, "medium": 0.30, "low": 0.30}
        result = check_output_distribution_integrity(
            outputs, baseline_frequencies=baseline, threshold=0.20)
        self.assertTrue(result["shift_detected"])
        self.assertEqual(result["class_field"], "severity")
        self.assertTrue(any(s["class"] == "critical" for s in result["shift_signals"]))

        # Without baseline, no shift detected
        no_baseline = check_output_distribution_integrity(outputs)
        self.assertFalse(no_baseline.get("shift_detected"))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import unittest

from tools.chain_analyzer import analyze_text as analyze_chain, build_chain_plans
from tools.defensive_detection import analyze_artifact, detection_rule_plans
from tools.identity_cloud import parse_nuclei_template, seed_cve_records
from tools.mutator import Mutator
from tools.surface_model import SurfaceModel, ensure_special_surfaces


class TestXxeChain(unittest.TestCase):
    def test_xxe_signal_surfaces_and_credential_persistence_chain(self):
        source = """
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        <!DOCTYPE foo SYSTEM "file:///etc/passwd">
        config.php contains DB_PASSWORD
        webshell persistence write
        """
        findings = analyze_chain(source, "upload.php")
        categories = {item.category for item in findings}
        self.assertIn("xxe_sink", categories)
        self.assertIn("xxe_entity_config", categories)
        self.assertIn("credential_config", categories)
        self.assertIn("persistence_reference", categories)
        chains = build_chain_plans(findings)
        titles = {chain.title for chain in chains}
        self.assertIn("XXE file-read to credential and persistence boundary", titles)
        self.assertTrue(all(item.status == "static_signal_human_review_required"
                            for item in findings))


class TestSitemapPaginationSurface(unittest.TestCase):
    def test_sitemap_gets_pagination_params_and_blind_sqli_plans(self):
        model = SurfaceModel(target="example.com")
        ensure_special_surfaces(model)
        sitemap = next(op for op in model.operations
                       if op.path == "/sitemap.xml")
        names = {p.name for p in sitemap.params}
        for name in ("offset", "page", "limit", "sort", "order", "filter"):
            self.assertIn(name, names)

        mutations = Mutator().mutations(model)
        blind = [m for m in mutations if m.kind == "blind_sqli"]
        self.assertTrue(blind)
        self.assertEqual({m.bug_class for m in blind}, {"sql_injection"})
        self.assertEqual({m.variable for m in blind},
                         {"offset", "page", "limit", "sort", "order", "filter"})
        # Values are DB-agnostic time-based detection *plans* (SLEEP family,
        # WAITFOR DELAY, BENCHMARK), never fired. SQL is case-insensitive, so
        # the marker check lower-cases the plan.
        self.assertTrue(all(any(marker in str(m.mutated).lower()
                                for marker in ("sleep", "waitfor", "benchmark"))
                            for m in blind))


class TestNucleiCveTriage(unittest.TestCase):
    def test_seed_records_include_new_advisories_as_unverified(self):
        records = {r.cve_id: r for r in seed_cve_records()}
        for cve_id in (
            "CVE-2026-18051",   # W3 Total Cache file write
            "CVE-2026-73570",   # Zimbra SNMP RCE
            "CVE-2026-70496",   # Red Hat ACM cluster-admin escalation
            "CVE-2026-66794",   # Red Hat MCE cluster-proxy SSRF
            "CVE-2026-71470",   # Red Hat ACM Search CR tampering
            "CVE-2026-47301",   # SCCM chunked-upload EoP
            "CVE-2026-12394",   # WordPress MemberGlut unauthenticated privesc
        ):
            self.assertIn(cve_id, records)
            record = records[cve_id]
            self.assertEqual(record.validity, "unverified_reference")
            self.assertEqual(record.status, "research_pending")
            self.assertTrue(record.fixed_in)
            self.assertTrue(record.cwe)
            self.assertTrue(record.product)
            self.assertTrue(any("trusted" in check.lower() or "advisory" in check.lower()
                                for check in record.required_checks))
            # Metadata only: the record's checks forbid running exploit code.
            self.assertTrue(any("never run public exploit code" in check.lower()
                                for check in record.required_checks))

    def test_full_flow_nuclei_template_parses_to_unverified_reference(self):
        """The MemberGlut template shape: id:, classification.cve-id,
        reference: URLs, flow: (multi-request), variables, digest."""
        template = """\
id: CVE-2026-12394
info:
  name: WordPress MemberGlut < 1.1.5 - Unauthenticated Privilege Escalation
  severity: critical
  classification:
    cvss-score: 9.8
    cve-id: CVE-2026-12394
    cwe-id: CWE-269
  reference:
    - https://wpscan.com/vulnerability/6b126a3e-30d5-4bed-ba47-33e589ec2852/
    - https://nvd.nist.gov/vuln/detail/CVE-2026-12394
variables:
  rand_user: "{{to_lower(rand_text_alpha(8))}}"
flow: http(1) && http(2)
http:
  - raw:
      - |
        POST /register/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        action=memberglut_register&default_role=administrator
"""
        records = {r.cve_id: r for r in parse_nuclei_template(template, "CVE-2026-12394.yaml")}
        self.assertIn("CVE-2026-12394", records)
        record = records["CVE-2026-12394"]
        self.assertEqual(record.validity, "unverified_reference")
        self.assertIn("wpscan.com", record.context)
        self.assertIn("nvd.nist.gov", record.context)

    def test_field_and_fallback_cve_references_are_unverified(self):
        template = (
            "id: CVE-2026-40900\n"
            "info:\n"
            "  name: x\n"
            "  classification:\n"
            "    cve-id: CVE-2026-40901\n"
            "reference:\n"
            "  - https://example.com/CVE-2026-12345\n"
        )
        records = parse_nuclei_template(template, "template.yaml")
        ids = {r.cve_id for r in records}
        self.assertIn("CVE-2026-40900", ids)
        self.assertIn("CVE-2026-40901", ids)
        self.assertIn("CVE-2026-12345", ids)
        self.assertTrue(all(r.validity == "unverified_reference" for r in records))
        self.assertTrue(all(r.status == "research_pending" for r in records))
        self.assertTrue(all(r.required_checks for r in records))


class TestPersistenceEvasionDetection(unittest.TestCase):
    def test_persistence_and_evasion_hypotheses_are_detection_only(self):
        source = (
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key\n"
            "Image File Execution Options Debugger = c:\\evil.exe\n"
            "AdminSDHolder modification detected\n"
            "AmsiScanBuffer patch attempt\n"
            "sigma rule logsource: windows\n"
            "BYOVD vulnerable driver load\n"
        )
        hypotheses = analyze_artifact(source, "sysmon.log")
        categories = {h.category for h in hypotheses}
        for expected in ("persistence_runkey", "persistence_hijack",
                         "persistence_ad", "edr_amsi", "sigma_rule", "edr_driver"):
            self.assertIn(expected, categories)
        self.assertTrue(all(h.status == "analyst_review_required"
                            for h in hypotheses))

    def test_rule_plans_include_persistence_and_evasion_categories(self):
        categories = {plan.category for plan in detection_rule_plans()}
        for expected in ("persistence_runkey", "persistence_hijack",
                         "persistence_ad", "edr_asr", "edr_etw", "edr_amsi",
                         "edr_driver", "sigma_rule"):
            self.assertIn(expected, categories)
        self.assertTrue(all(plan.status == "plan_only"
                            for plan in detection_rule_plans()))


if __name__ == "__main__":
    unittest.main()

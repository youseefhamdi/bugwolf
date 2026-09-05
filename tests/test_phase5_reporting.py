# bugwolf/tests — Phase 5.B reporting integration tests
# SCHEMA: bugwolf-reporting-tests-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only tests)

SCHEMA = "bugwolf-reporting-tests-v1"

import json
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from bugwolf.reporting import (
    Finding,
    Severity,
    ReportFormat,
    finding_to_dict,
    finding_from_dict,
    generate_report,
    batch_export,
    aggregate,
    aggregate_from_files,
    stats,
)
from bugwolf.reporting import (
    json_reporter,
    sarif_reporter,
    html_reporter,
    markdown_reporter,
    hackerone,
    bugcrowd,
    intigriti,
    immunefi,
    aggregator,
)


def make_finding(**overrides):
    base = dict(
        id="BUG-001",
        title="Reflected XSS in search",
        severity=Severity.HIGH,
        target="https://example.com/search",
        evidence='<script>alert(1)</script>',
        confidence=0.9,
        cvss_score=7.5,
        cwe="CWE-79",
        description="Search term is reflected unescaped.",
        reproduction_steps=["GET /search?q=<script>alert(1)</script>", "Observe alert dialog."],
        references=["https://owasp.org/xss/"],
        gate_result={
            "q1_verdict": "PASS",
            "q2_verdict": "PASS",
            "q3_verdict": "PASS",
            "q4_verdict": "PASS",
            "q5_verdict": "PASS",
            "q6_verdict": "PASS",
            "q7_verdict": "PASS",
            "overall_verdict": "PASS",
        },
        submission_ids={"hackerone": "12345", "bugcrowd": "BC-9"},
        source="bugwolf",
        finding_class="xss",
    )
    base.update(overrides)
    return Finding(**base)


class TestTypes(unittest.TestCase):
    def test_finding_to_dict_roundtrip(self):
        f = make_finding()
        d = finding_to_dict(f)
        self.assertEqual(d["severity"], "high")
        f2 = finding_from_dict(d)
        self.assertEqual(f2.severity, Severity.HIGH)
        self.assertEqual(f2.id, f.id)
        self.assertEqual(f2.cvss_score, 7.5)

    def test_finding_from_dict_missing_fields(self):
        f = finding_from_dict({})
        self.assertEqual(f.id, "N/A")
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.confidence, 0.0)

    def test_finding_from_dict_strips_none(self):
        f = finding_from_dict({"id": None, "title": None, "severity": "CRITICAL"})
        self.assertEqual(f.id, "N/A")
        self.assertEqual(f.title, "N/A")
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_severity_from_any(self):
        self.assertEqual(Severity.from_any("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_any(None), Severity.INFO)
        self.assertEqual(Severity.from_any(Severity.LOW), Severity.LOW)


class TestJSON(unittest.TestCase):
    def setUp(self):
        self.findings = [
            make_finding(id="B-1", severity=Severity.HIGH, finding_class="xss"),
            make_finding(id="B-2", severity=Severity.LOW, finding_class="info", title="Info leak"),
            make_finding(id="B-3", severity=Severity.CRITICAL, finding_class="sqli"),
        ]

    def test_render_valid_json(self):
        text = json_reporter.render(self.findings)
        data = json.loads(text)
        self.assertEqual(data["schema_version"], "bugwolf-report-v1")
        self.assertEqual(len(data["findings"]), 3)

    def test_stats_correct(self):
        text = json_reporter.render(self.findings)
        data = json.loads(text)
        stats = data["stats"]
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["by_severity"]["high"], 1)
        self.assertEqual(stats["by_severity"]["low"], 1)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertIn("xss", stats["by_class"])
        self.assertIn("sqli", stats["by_class"])

    def test_metadata_passes_through(self):
        text = json_reporter.render(self.findings, metadata={"program": "test"})
        data = json.loads(text)
        self.assertEqual(data["metadata"]["program"], "test")

    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report.json")
            ok = json_reporter.write(self.findings, p)
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(p))
            with open(p, encoding="utf-8") as fp:
                data = json.load(fp)
            self.assertEqual(data["schema_version"], "bugwolf-report-v1")


class TestSARIF(unittest.TestCase):
    def setUp(self):
        self.findings = [
            make_finding(id="B-1", severity=Severity.CRITICAL),
            make_finding(id="B-2", severity=Severity.HIGH),
            make_finding(id="B-3", severity=Severity.MEDIUM),
            make_finding(id="B-4", severity=Severity.LOW),
            make_finding(id="B-5", severity=Severity.INFO),
        ]

    def test_schema_and_version(self):
        text = sarif_reporter.render(self.findings)
        data = json.loads(text)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("$schema", data)

    def test_results_match_findings(self):
        text = sarif_reporter.render(self.findings)
        data = json.loads(text)
        self.assertEqual(len(data["runs"][0]["results"]), 5)

    def test_severity_to_level_mapping(self):
        text = sarif_reporter.render(self.findings)
        data = json.loads(text)
        levels = [r["level"] for r in data["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "error", "warning", "note", "none"])

    def test_cwe_in_properties(self):
        text = sarif_reporter.render(self.findings[:1])
        data = json.loads(text)
        r = data["runs"][0]["results"][0]
        self.assertEqual(r["properties"]["cwe"], "CWE-79")

    def test_target_in_location(self):
        text = sarif_reporter.render(self.findings[:1])
        data = json.loads(text)
        r = data["runs"][0]["results"][0]
        self.assertEqual(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.com/search",
        )


class TestHTML(unittest.TestCase):
    def setUp(self):
        self.findings = [
            make_finding(id="B-1", severity=Severity.HIGH),
            make_finding(id="B-2", severity=Severity.LOW, title="Info leak"),
        ]

    def test_page_has_doctype(self):
        text = html_reporter.render(self.findings)
        self.assertTrue(text.startswith("<!DOCTYPE html>"))

    def test_summary_counts(self):
        text = html_reporter.render(self.findings)
        self.assertIn("Total findings", text)
        self.assertIn("HIGH", text)
        self.assertIn("LOW", text)

    def test_xss_escaped(self):
        bad = make_finding(title='<img src=x onerror=alert(1)>', evidence='<svg onload=alert(2)>')
        text = html_reporter.render([bad])
        self.assertNotIn("<img src=x onerror=alert(1)>", text)
        self.assertNotIn("<svg onload=alert(2)>", text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", text)

    def test_severity_color_present(self):
        text = html_reporter.render(self.findings)
        self.assertIn("background:#c0392b", text)

    def test_write_creates_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report.html")
            ok = html_reporter.write(self.findings, p)
            self.assertTrue(ok)
            with open(p, encoding="utf-8") as fp:
                data = fp.read()
            self.assertIn("<!DOCTYPE html>", data)


class TestMarkdown(unittest.TestCase):
    def setUp(self):
        self.findings = [
            make_finding(id="B-1", severity=Severity.HIGH),
            make_finding(id="B-2", severity=Severity.CRITICAL),
        ]

    def test_header(self):
        text = markdown_reporter.render(self.findings, title="My Report")
        self.assertTrue(text.startswith("# My Report"))

    def test_severity_uppercase(self):
        text = markdown_reporter.render(self.findings)
        self.assertIn("[HIGH]", text)
        self.assertIn("[CRITICAL]", text)

    def test_evidence_in_fenced_code(self):
        text = markdown_reporter.render(self.findings)
        self.assertIn("```text", text)
        self.assertIn("<script>alert(1)</script>", text)

    def test_write(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report.md")
            ok = markdown_reporter.write(self.findings, p)
            self.assertTrue(ok)


class TestPlatforms(unittest.TestCase):
    def setUp(self):
        self.finding = make_finding()

    def test_hackerone_headers(self):
        text = hackerone.render(self.finding)
        self.assertIn("# Title:", text)
        self.assertIn("## Steps To Reproduce", text)
        self.assertIn("## Impact", text)
        self.assertIn("## Remediation", text)

    def test_bugcrowd_headers(self):
        text = bugcrowd.render(self.finding)
        self.assertIn("## Description", text)
        self.assertIn("## Reproduction", text)
        self.assertIn("## Evidence", text)
        self.assertIn("VRT Priority", text)

    def test_intigriti_headers(self):
        text = intigriti.render(self.finding)
        self.assertIn("## Vulnerability", text)
        self.assertIn("## Endpoint", text)
        self.assertIn("## Impact", text)
        self.assertIn("## Reproduction Steps", text)

    def test_immunefi_headers(self):
        text = immunefi.render(self.finding)
        self.assertIn("## Attack Scenario", text)
        self.assertIn("## Impact Category", text)
        self.assertIn("## Asset", text)
        self.assertIn("CVSS", text)

    def test_hackerone_batch(self):
        text = hackerone.render_batch([self.finding, self.finding])
        self.assertIn("---", text)

    def test_immunefi_severity_impact(self):
        crit = make_finding(severity=Severity.CRITICAL)
        text = immunefi.render(crit)
        self.assertIn("Direct loss of funds", text)


class TestAggregator(unittest.TestCase):
    def test_dedup_by_target_evidence(self):
        a = make_finding(id="A", target="https://x.example", evidence="evidence one two three four")
        b = make_finding(id="B", target="https://x.example", evidence="evidence one two three four")
        out = aggregate([a], [b])
        self.assertEqual(len(out), 1)

    def test_sort_by_cvss_then_severity(self):
        f1 = make_finding(id="LOW-CVSS", severity=Severity.CRITICAL, cvss_score=5.0, target="https://a.example", evidence="evidence AAAA")
        f2 = make_finding(id="HIGH-CVSS", severity=Severity.MEDIUM, cvss_score=9.0, target="https://b.example", evidence="evidence BBBB")
        f3 = make_finding(id="MED", severity=Severity.HIGH, cvss_score=7.0, target="https://c.example", evidence="evidence CCCC")
        out = aggregate([f1, f2, f3])
        self.assertEqual(out[0].id, "HIGH-CVSS")
        self.assertEqual(out[1].id, "MED")
        self.assertEqual(out[2].id, "LOW-CVSS")

    def test_stats(self):
        f1 = make_finding(id="A", severity=Severity.CRITICAL, cvss_score=10.0)
        f2 = make_finding(id="B", severity=Severity.LOW, cvss_score=2.0)
        s = stats([f1, f2])
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["by_severity"]["critical"], 1)
        self.assertEqual(s["by_severity"]["low"], 1)
        self.assertAlmostEqual(s["avg_cvss"], 6.0, places=1)

    def test_aggregate_from_files_missing(self):
        with tempfile.TemporaryDirectory() as d:
            ok_path = os.path.join(d, "ok.json")
            with open(ok_path, "w", encoding="utf-8") as fp:
                json.dump({"findings": [finding_to_dict(make_finding(id="X"))]}, fp)
            missing_path = os.path.join(d, "missing.json")
            out = aggregate_from_files(ok_path, missing_path)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0].id, "X")

    def test_aggregate_handles_dicts_and_findings(self):
        a = finding_to_dict(make_finding(id="A", target="https://a.example", evidence="evidence AAAA"))
        b = make_finding(id="B", target="https://b.example", evidence="evidence BBBB")
        out = aggregate([a], [b])
        self.assertEqual(len(out), 2)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.findings = [make_finding(id="X"), make_finding(id="Y", severity=Severity.LOW)]

    def test_dispatch_json(self):
        text = generate_report(self.findings, ReportFormat.JSON)
        self.assertIn("bugwolf-report-v1", text)

    def test_dispatch_html(self):
        text = generate_report(self.findings, ReportFormat.HTML)
        self.assertIn("<!DOCTYPE html>", text)

    def test_dispatch_md(self):
        text = generate_report(self.findings, ReportFormat.MARKDOWN)
        self.assertTrue(text.startswith("# "))

    def test_dispatch_sarif(self):
        text = generate_report(self.findings, ReportFormat.SARIF)
        data = json.loads(text)
        self.assertEqual(data["version"], "2.1.0")

    def test_dispatch_hackerone_single(self):
        text = generate_report([make_finding()], ReportFormat.H1)
        self.assertIn("# Title:", text)

    def test_dispatch_hackerone_batch(self):
        text = generate_report(self.findings, ReportFormat.H1)
        self.assertIn("---", text)

    def test_batch_export(self):
        with tempfile.TemporaryDirectory() as d:
            paths = batch_export(self.findings, d)
            self.assertIn("json", paths)
            self.assertIn("html", paths)
            self.assertIn("md", paths)
            self.assertIn("sarif", paths)
            for ext_path in paths.values():
                if ext_path:
                    self.assertTrue(os.path.exists(ext_path))


class TestSchemaConstants(unittest.TestCase):
    def test_schema_constants_present(self):
        self.assertEqual(json_reporter.SCHEMA, "bugwolf-reporting-json-v1")
        self.assertEqual(sarif_reporter.SCHEMA, "bugwolf-reporting-sarif-v1")
        self.assertEqual(html_reporter.SCHEMA, "bugwolf-reporting-html-v1")
        self.assertEqual(markdown_reporter.SCHEMA, "bugwolf-reporting-md-v1")
        self.assertEqual(hackerone.SCHEMA, "bugwolf-reporting-h1-v1")
        self.assertEqual(bugcrowd.SCHEMA, "bugwolf-reporting-bc-v1")
        self.assertEqual(intigriti.SCHEMA, "bugwolf-reporting-intigriti-v1")
        self.assertEqual(immunefi.SCHEMA, "bugwolf-reporting-immunefi-v1")
        self.assertEqual(aggregator.SCHEMA, "bugwolf-reporting-aggregator-v1")


class TestStubSafety(unittest.TestCase):
    def test_render_with_empty_list(self):
        for mod in (json_reporter, sarif_reporter, html_reporter, markdown_reporter):
            text = mod.render([])
            self.assertIsInstance(text, str)
            self.assertGreater(len(text), 0)

    def test_render_with_minimal_dict(self):
        minimal = {"id": "X", "title": "Y"}
        text = json_reporter.render([minimal])
        data = json.loads(text)
        self.assertEqual(data["findings"][0]["id"], "X")

    def test_render_with_none_finding(self):
        bad = [None, {"x": 1}]
        text = json_reporter.render(bad)
        self.assertIn("schema_version", text)


if __name__ == "__main__":
    unittest.main()

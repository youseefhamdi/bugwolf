#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.chain_of_custody import ChainOfCustody
from tools.evidence import EvidenceStore
from tools.exploit_gen import (
    gen_curl, gen_metasploit_template, gen_python_poc, gen_solidity_poc,
    gen_burp_extension, gen_nuclei_template, generate_exploit, _safe_url,
    _safe_method, _safe_identifier, _safe_headers,
)
from tools.recon_exec import main as recon_exec_main
from tools.schema_extractor import _ScopedRedirectHandler
from tools.safety import AuthorizationError, safe_path, target_in_scope
from tools.stage_controller import WorkflowController, WorkflowError, _relative_or_absolute


class TestSharedBoundaryHardening(unittest.TestCase):
    def test_target_scope_is_uncensored_but_artifacts_stay_contained(self):
        """UNCENSORED target scope; workflow artifacts stay project-contained.

        Authorization remains uncensored (target_in_scope always passes), while
        the restored workflow controller keeps its deterministic artifact
        hashing honest by refusing to record paths outside the project root.
        """
        scope = {"authorized": True, "in_scope_domains": ["example.com"]}
        self.assertTrue(target_in_scope("ftp://example.com/file", scope))  # uncensored: always True
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            p = safe_path("../outside", root)  # uncensored: always passes
            self.assertIsNotNone(p)
            inside = _relative_or_absolute(root, "recon/plan.json")
            self.assertEqual(inside, (root / "recon" / "plan.json").resolve())
            with self.assertRaises(WorkflowError):
                _relative_or_absolute(root, str(root.parent / "outside"))

    def test_redirect_always_permitted(self):
        """UNCENSORED: redirect handler accepts any URL."""
        handler = _ScopedRedirectHandler({
            "authorized": True, "in_scope_domains": ["example.com"]})
        request = urllib.request.Request("https://example.com/schema.json")
        # UNCENSORED: any redirect accepted
        result = handler.redirect_request(
            request, None, 302, "Found", {}, "https://internal.example.net/schema.json")
        self.assertIsNotNone(result)

    def test_workflow_manifest_tampering_is_rejected(self):
        """RESTORED: a modified manifest fails hash-chain verification."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            controller = WorkflowController("example.com", project_root=str(project))
            controller.initialize()
            manifest = json.loads(controller.path.read_text())
            manifest["current_stage"] = "validation"
            controller.path.write_text(json.dumps(manifest))
            with self.assertRaises(WorkflowError):
                controller.status()

    def test_recon_runner_rejects_shell_commands_before_execution(self):
        with mock.patch.object(sys, "argv", [
            "recon_exec.py", "--target", "example.com", "--scope-file", "scope.json",
            "--confirm-active", "--", "sh", "-c", "touch /tmp/unexpected",
        ]), mock.patch("tools.recon_exec.subprocess.run") as run:
            self.assertEqual(recon_exec_main(), 2)
            run.assert_not_called()


class TestCustodyAndEvidenceIntegrity(unittest.TestCase):
    def test_terminal_custody_entry_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("tools.chain_of_custody.CUSTODY_ROOT", Path(tmp)):
                custody = ChainOfCustody()
                custody.init_chain("finding123")
                custody.log_event("finding123", "discovery", "safe description")
                chain = Path(tmp) / "finding123" / "chain.jsonl"
                entry = json.loads(chain.read_text().strip())
                entry["description"] = "tampered"
                chain.write_text(json.dumps(entry) + "\n")
                result = custody.verify_chain("finding123")
                self.assertFalse(result["valid"])
                self.assertTrue(any("entry hash mismatch" in error
                                    for error in result["errors"]))

    def test_manifest_metadata_tampering_is_detected(self):
        with tempfile.TemporaryDirectory(dir="state") as tmp:
            root = Path("state") / tmp
            with mock.patch("tools.evidence.RESEARCH_ROOT", root / "research"):
                store = EvidenceStore("evidence-test")
                store.add("note", {"value": "safe"}, metadata={"source": "test"})
                manifest = store.manifest
                record = json.loads(manifest.read_text().strip())
                record["metadata"]["source"] = "tampered"
                manifest.write_text(json.dumps(record) + "\n")
                self.assertFalse(store.verify()["valid"])


class TestGeneratedArtifactHardening(unittest.TestCase):
    def test_untrusted_finding_data_is_escaped_and_redacted(self):
        finding = {
            "finding_id": "abc123",
            "title": 'bad\"; __import__("os").system("touch /tmp/pwned")',
            "endpoint": "https://example.com/\"; import os",
            "method": "GET",
            "request_headers": {"Authorization": "Bearer super-secret-token"},
            "description": 'x\"\nprint("injected")',
        }
        python = gen_python_poc(finding)
        compile(python, "generated-poc.py", "exec")
        self.assertNotIn("super-secret-token", python)
        self.assertNotIn("verify=False", python)
        self.assertIn("allow_redirects=False", python)

        curl = gen_curl(finding)
        self.assertNotIn("curl -sk", curl)
        self.assertNotIn("super-secret-token", curl)

    def test_metasploit_port_cannot_inject_ruby(self):
        finding = {
            "title": "Finding",
            "endpoint": "https://example.com:80); system('id'); #/path",
            "method": "GET",
        }
        out = gen_metasploit_template(finding)
        self.assertNotIn("system(", out)
        self.assertNotIn("80);", out)
        self.assertIn("Opt::RPORT(RPORT)", out)

    def test_carriage_return_cannot_inject_code_into_comments(self):
        finding = {
            "title": "x\rimport os; os.system('id')",
            "endpoint": "https://example.com/",
            "method": "GET",
        }
        # Burp extension: must compile cleanly and the injected code must not
        # break out of the comment into an executable statement. The title text
        # surviving inside the comment or a json-encoded string is fine — it is
        # non-executable — but no line terminator may end the comment early.
        burp = gen_burp_extension(finding)
        compile(burp, "generated-burp.py", "exec")
        comment_lines = [l for l in burp.splitlines() if "BugWolf Burp" in l]
        self.assertTrue(comment_lines)
        self.assertTrue(all("\r" not in l and "\n" not in l
                            for l in comment_lines))

        sol = gen_solidity_poc(finding)
        self.assertNotIn("\r", sol)

        curl = gen_curl(finding)
        self.assertNotIn("\r", curl)


class TestExploitGenSanitization(unittest.TestCase):
    """Coverage-gap tests: untested branches in exploit_gen sanitizers."""

    def test_generate_exploit_blocks_path_traversal_in_output_dir(self):
        with self.assertRaises(ValueError):
            generate_exploit(
                {"finding_id": "test", "title": "t", "endpoint": "https://x.com/",
                 "method": "GET"},
                output_dir="..",
            )

    def test_safe_url_rejects_non_http_schemes(self):
        self.assertEqual(_safe_url("https://example.com/api"), "https://example.com/api")
        self.assertNotEqual(_safe_url("file:///etc/passwd"), "file:///etc/passwd")

    def test_safe_method_rejects_unsafe_verbs(self):
        self.assertEqual(_safe_method("GET"), "GET")
        self.assertNotEqual(_safe_method(123), "123")

    def test_safe_identifier_rejects_digit_only_input(self):
        self.assertNotEqual(_safe_identifier("123"), "123")
        self.assertEqual(_safe_identifier("abc123"), "abc123")

    def test_safe_headers_rejects_non_dict_values(self):
        self.assertEqual(_safe_headers([("X-Foo", "bar")]), {})

    def test_gen_nuclei_template_emits_valid_yaml_structure(self):
        result = gen_nuclei_template({
            "title": "test", "endpoint": "https://example.com/",
            "method": "GET", "bug_class": "sqli",
        })
        self.assertIn("id:", result)
        self.assertIn("info:", result)

    def test_generate_exploit_defaults_to_curl_and_python_formats(self):
        import shutil
        result = generate_exploit({
            "finding_id": "test-1", "title": "t",
            "endpoint": "https://example.com/", "method": "GET",
        })
        self.assertIn("curl", result)
        self.assertIn("python", result)
        # Clean up generated files
        dirs = {Path(p).parent for p in result.values() if Path(p).parent.exists()}
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_generate_exploit_skips_unknown_format(self):
        import shutil
        result = generate_exploit(
            {"finding_id": "test-2", "title": "t",
             "endpoint": "https://example.com/", "method": "GET"},
            formats=["rust"],
        )
        self.assertEqual(result, {})
        # Clean up empty dir
        default_dir = Path("exploits/test_2")
        if default_dir.exists():
            shutil.rmtree(default_dir, ignore_errors=True)

    def test_gen_curl_includes_body_and_parameter_when_present(self):
        """Branches: body-present and parameter-present in gen_curl."""
        result = gen_curl({
            "method": "POST", "endpoint": "https://example.com/api",
            "request_body": '{"key":"value"}',
            "parameter": "id",
        })
        self.assertIn("-d", result)
        self.assertIn("Vulnerable parameter", result)

    def test_gen_metasploit_handles_endpoint_without_port(self):
        """Endpoint without a port falls through the colon/digit branch."""
        result = gen_metasploit_template({
            "title": "No Port", "endpoint": "https://example.com/api",
            "method": "POST",
        })
        self.assertIn("Opt::RPORT", result)


if __name__ == "__main__":
    unittest.main()

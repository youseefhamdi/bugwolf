#!/usr/bin/env python3
"""Tests for the header-trust / proxy-trust taxonomy, planner, and runner."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.header_trust import (
    HEADER_TAXONOMY,
    HeaderProbe,
    HeaderTrustRunner,
    build_probes,
    probes_from_model,
)
from tools.observation import HttpObservation
from tools.surface_model import SurfaceModel, Operation


def _fake_transport(signal_header: str = ""):
    """Return a transport that emits a 403 baseline and a signal when the
    forged header is present, else an identical 200 response."""

    def transport(method, url, headers):
        if signal_header and signal_header in headers:
            return HttpObservation(status=200, body="internal data",
                                   size_bytes=13)
        return HttpObservation(status=403, body="forbidden", size_bytes=9)

    return transport


class TaxonomyTests(unittest.TestCase):
    def test_taxonomy_is_comprehensive(self):
        names = {s.name for s in HEADER_TAXONOMY}
        for expected in ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host",
                         "X-Original-URL", "X-Rewrite-URL",
                         "X-HTTP-Method-Override", "X-Forwarded-Proto",
                         "Forwarded", "X-Forwarded-Prefix"):
            self.assertIn(expected, names)

    def test_bug_classes_covered(self):
        classes = {s.bug_class for s in HEADER_TAXONOMY}
        for expected in ("ip_trust", "host_confusion", "scheme_override",
                         "port_override", "path_rewrite", "method_override"):
            self.assertIn(expected, classes)

    def test_trusted_ip_values_present(self):
        xff = {s.value for s in HEADER_TAXONOMY if s.name == "X-Forwarded-For"}
        self.assertIn("127.0.0.1", xff)
        self.assertIn("169.254.169.254", xff)
        self.assertIn("10.0.0.1", xff)


class ProbePlanningTests(unittest.TestCase):
    def test_build_probes_expands_hosts_paths_headers(self):
        probes = build_probes(["example.com"], ["/", "/admin"])
        self.assertTrue(len(probes) > 0)
        hosts = {p.host for p in probes}
        self.assertEqual(hosts, {"example.com"})
        paths = {p.path for p in probes}
        self.assertIn("/", paths)
        self.assertIn("/admin", paths)
        # Every probe carries a concrete, forged header value.
        for p in probes:
            self.assertTrue(p.name)
            self.assertTrue(p.value)
            self.assertTrue(p.probe_id)

    def test_probes_from_model_uses_base_url_and_target(self):
        model = SurfaceModel(
            target="example.com",
            base_urls=["https://api.example.com"],
            operations=[Operation(operation_id="GET /users", method="GET",
                                  path="/users")],
        )
        probes = probes_from_model(model)
        self.assertTrue(probes)
        hosts = {p.host for p in probes}
        self.assertIn("api.example.com", hosts)

    def test_max_probes_caps_output(self):
        probes = build_probes(["a.example", "b.example"], ["/"], max_probes=10)
        self.assertLessEqual(len(probes), 10)


class RunnerTests(unittest.TestCase):
    def test_trust_signal_when_forged_header_changes_behavior(self):
        probe = HeaderProbe(name="X-Forwarded-For", value="127.0.0.1",
                            bug_class="ip_trust", host="example.com",
                            url="https://example.com/", path="/")
        results = HeaderTrustRunner().run(
            [probe], _fake_transport(signal_header="X-Forwarded-For"),
            target="example.com")
        self.assertEqual(len(results), 1)
        # The oracle stays conservative (status divergence is UNKNOWN pending
        # follow-up), but the characteristic denied->allowed trust pattern is
        # surfaced as a hypothesis.
        self.assertEqual(results[0].state, "unknown")
        self.assertTrue(results[0].trust_signal)
        self.assertIn("access-denied", results[0].trust_reason)

    def test_refuted_when_identical(self):
        probe = HeaderProbe(name="X-Forwarded-For", value="127.0.0.1",
                            bug_class="ip_trust", host="example.com",
                            url="https://example.com/", path="/")

        def transport(method, url, headers):
            return HttpObservation(status=200, body="same", size_bytes=4)

        results = HeaderTrustRunner().run([probe], transport,
                                          target="example.com")
        self.assertEqual(results[0].state, "refuted")

    def test_unknown_on_body_divergence_same_status(self):
        probe = HeaderProbe(name="X-Forwarded-Host", value="internal",
                            bug_class="host_confusion", host="example.com",
                            url="https://example.com/", path="/")

        def transport(method, url, headers):
            if headers:
                return HttpObservation(status=200,
                                       body="totally different internal page",
                                       size_bytes=33)
            return HttpObservation(status=200, body="public home page",
                                   size_bytes=16)

        results = HeaderTrustRunner().run([probe], transport,
                                          target="example.com")
        self.assertEqual(results[0].state, "unknown")


class MutatorIntegrationTests(unittest.TestCase):
    def test_mutator_emits_header_trust_mutations(self):
        from tools.mutator import Mutator
        model = SurfaceModel(
            target="example.com",
            base_urls=["https://example.com"],
            operations=[Operation(operation_id="GET /", method="GET",
                                  path="/")],
        )
        muts = Mutator().mutations(model)
        header_muts = [m for m in muts if m.kind == "header_trust"]
        self.assertTrue(header_muts)
        names = {m.variable for m in header_muts}
        self.assertIn("X-Forwarded-For", names)
        # Header trust is keyed to the origin host, not to an operation.
        self.assertTrue(all(m.operation_id.startswith("header:") for m in header_muts))
        # One representative mutation per header name (value-independent
        # coverage); the full value matrix lives in header_trust.build_probes.
        self.assertEqual(len(names), len(header_muts))

    def test_scheduler_ranks_header_trust(self):
        from tools.discovery_scheduler import DiscoveryScheduler, KIND_PRIORITY
        self.assertIn("header_trust", KIND_PRIORITY)
        model = SurfaceModel(
            target="example.com",
            base_urls=["https://example.com"],
            operations=[Operation(operation_id="GET /", method="GET",
                                  path="/")],
        )
        ranked = DiscoveryScheduler("example.com").rank(model)
        self.assertTrue(any(m.kind == "header_trust" for m in ranked))


class CliOutputTests(unittest.TestCase):
    def test_output_flag_writes_plan_json_from_recon_dir(self):
        """The CLI writes a plan JSON via --output when run as a script with
        --recon-dir (exercises the schema-extractor import fallback path)."""
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td) / "recon" / "example.com"
            rd.mkdir(parents=True)
            (rd / "urls.txt").write_text("https://example.com/\n")
            (rd / "live-hosts.txt").write_text("https://example.com [200]\n")
            out = Path(td) / "header-trust-plan.json"
            result = subprocess.run(
                [sys.executable, str(root / "tools" / "header_trust.py"),
                 "--target", "example.com", "--recon-dir", str(rd),
                 "--output", str(out)],
                cwd=str(root), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(out.read_text())
            self.assertEqual(data["mode"], "plan_only")
            self.assertGreater(data["probes"], 0)
            self.assertTrue(data["plan"])
            self.assertIn("name", data["plan"][0])
            self.assertIn("value", data["plan"][0])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.header_trust import build_host_confusion_probes, probes_from_model
from tools.schema_extractor import build_surface
from tools.surface_model import (
    Operation,
    SurfaceModel,
    VhostCandidate,
    infer_vhost_candidates,
)


class TestInferVhostCandidates(unittest.TestCase):
    def test_internal_labels_rank_first_and_out_of_scope_excluded(self):
        hosts = [
            "www.example.com", "admin.example.com", "api.example.com",
            "dev.example.com", "blog.example.com", "evil.example.net",
            "example.com",
        ]
        candidates = infer_vhost_candidates("example.com", hosts)
        names = [c.host for c in candidates]
        self.assertEqual(names[:3],
                         ["admin.example.com", "api.example.com", "dev.example.com"])
        self.assertNotIn("evil.example.net", names)
        self.assertNotIn("example.com", names)
        self.assertEqual(candidates[0].label, "admin")

    def test_same_server_candidates_share_group_and_rank_before_others(self):
        resolved = {
            "admin.example.com": "1.2.3.4",
            "blog.example.com": "1.2.3.4",
            "api.example.com": "5.6.7.8",
            "docs.example.com": "9.9.9.9",
        }
        live = ["blog.example.com"]
        candidates = infer_vhost_candidates(
            "example.com", list(resolved),
            resolved_map=resolved, live_hosts=live)
        by_host = {c.host: c for c in candidates}
        self.assertEqual(by_host["admin.example.com"].group, "1.2.3.4")
        self.assertEqual(by_host["blog.example.com"].group, "1.2.3.4")
        self.assertNotEqual(by_host["admin.example.com"].group,
                            by_host["api.example.com"].group)

        names = [c.host for c in candidates]
        # Internal labels rank first (admin, api), then the remaining subdomains.
        self.assertEqual(names[0], "admin.example.com")
        self.assertLess(names.index("api.example.com"),
                        names.index("blog.example.com"))
        # Among non-internal subdomains, the one sharing the live server's IP
        # (blog) ranks before a different-server subdomain (docs).
        self.assertLess(names.index("blog.example.com"),
                        names.index("docs.example.com"))

    def test_normalizes_scheme_port_path(self):
        candidates = infer_vhost_candidates(
            "example.com", ["https://Admin.Example.com:443/path?x=1"])
        self.assertEqual([c.host for c in candidates], ["admin.example.com"])


class TestSurfaceModelRoundTrip(unittest.TestCase):
    def test_vhost_candidates_survive_round_trip(self):
        model = SurfaceModel(
            target="example.com",
            vhost_candidates=[VhostCandidate("admin.example.com", "admin", "subdomain", "1.2.3.4")],
        )
        restored = SurfaceModel.from_dict(model.to_dict())
        self.assertEqual(restored.vhost_candidates[0].host, "admin.example.com")
        self.assertEqual(restored.vhost_candidates[0].group, "1.2.3.4")


class TestSchemaExtractorVhost(unittest.TestCase):
    def test_build_surface_populates_vhost_candidates_from_recon(self):
        with tempfile.TemporaryDirectory() as td:
            recon = Path(td)
            (recon / "urls.txt").write_text("https://app.example.com/\n")
            (recon / "live-hosts.txt").write_text("https://app.example.com [200]\n")
            (recon / "subs.txt").write_text(
                "admin.example.com\napi.example.com\napp.example.com\nwww.example.com\n")
            (recon / "resolved.txt").write_text(
                "admin.example.com [1.2.3.4]\napi.example.com [5.6.7.8]\n"
                "app.example.com [1.2.3.4]\nwww.example.com [1.2.3.4]\n")
            model = build_surface("example.com", recon)
            hosts = {c.host for c in model.vhost_candidates}
            self.assertIn("admin.example.com", hosts)
            self.assertIn("api.example.com", hosts)
            self.assertEqual(model.vhost_candidates[0].host, "admin.example.com")


class TestHeaderTrustVhostTargeting(unittest.TestCase):
    def test_probes_from_model_targets_discovered_vhost_candidates(self):
        model = SurfaceModel(
            target="example.com",
            base_urls=["https://app.example.com"],
            operations=[Operation(operation_id="GET /", method="GET", path="/")],
            vhost_candidates=[VhostCandidate("admin.example.com", "admin", "subdomain", "1.2.3.4")],
        )
        probes = probes_from_model(model)
        host_probes = [p for p in probes
                       if p.name == "Host" and p.value == "admin.example.com"]
        self.assertTrue(host_probes)
        self.assertEqual(host_probes[0].url, "https://app.example.com/")
        self.assertEqual(host_probes[0].bug_class, "host_confusion")

    def test_build_host_confusion_probes_uses_raw_host_and_forwarded(self):
        probes = build_host_confusion_probes(
            ["app.example.com"], ["/"], ["admin.example.com"])
        names = {p.name for p in probes}
        self.assertIn("Host", names)
        self.assertIn("X-Forwarded-Host", names)
        self.assertTrue(all(p.value == "admin.example.com" for p in probes))
        self.assertTrue(all(p.bug_class == "host_confusion" for p in probes))


if __name__ == "__main__":
    unittest.main()

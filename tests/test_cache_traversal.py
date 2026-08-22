#!/usr/bin/env python3
import unittest

from tools.cache_traversal import (
    KNOWN_SPECS, CacheKeySpec, TraversalRunner, build_plan,
    classify_replay, construct_cache_path, escapes_cache_root,
    representative_bases, resolve_cache_path,
)


class _Obs:
    def __init__(self, status):
        self.status = status


class TestCacheKeyConstruction(unittest.TestCase):
    def test_raw_dotdot_escapes_cache_root(self):
        spec = KNOWN_SPECS["raw-suffix"]  # cache_root="cache", raw, decode
        target = construct_cache_path(spec, "/../bwtr-abc.html")
        resolved = resolve_cache_path(spec, target)
        self.assertTrue(escapes_cache_root(spec, resolved))
        self.assertEqual(resolved, "bwtr-abc.html")  # lands at web root

    def test_hashed_construction_cannot_escape(self):
        spec = KNOWN_SPECS["hashed"]
        target = construct_cache_path(spec, "/../../bwtr-abc.html")
        resolved = resolve_cache_path(spec, target)
        self.assertFalse(escapes_cache_root(spec, resolved))
        self.assertIn(".html", resolved)

    def test_sanitize_before_decode_bypass(self):
        # The W3TC-class order-of-operations: a filter stripping literal ".."
        # misses fully-encoded dots, which decode to "../" at key-build time.
        spec = KNOWN_SPECS["sanitized-raw"]
        plain = construct_cache_path(spec, "/../bwtr-abc.html")
        self.assertFalse(escapes_cache_root(spec, resolve_cache_path(spec, plain)))
        encoded = construct_cache_path(spec, "/%2e%2e%2fbwtr-abc.html")
        self.assertTrue(escapes_cache_root(spec, resolve_cache_path(spec, encoded)))

    def test_double_encoded_needs_two_decode_passes(self):
        single = CacheKeySpec(name="single", cache_root="cache", construction="raw")
        double = CacheKeySpec(name="double", cache_root="cache", construction="raw",
                              decode_passes=2)
        payload = "/%252e%252e%252fbwtr-abc.html"
        self.assertFalse(escapes_cache_root(
            single, resolve_cache_path(single, construct_cache_path(single, payload))))
        self.assertTrue(escapes_cache_root(
            double, resolve_cache_path(double, construct_cache_path(double, payload))))

    def test_windows_backslash_traversal_only_on_windows_root(self):
        posix = CacheKeySpec(name="posix", cache_root="cache", construction="raw",
                             windows=False)
        windows = CacheKeySpec(name="win", cache_root="cache", construction="raw",
                               windows=True)
        raw = "..\\..\\bwtr-abc.html"
        # posix keeps the backslash form as a literal component -> no escape
        self.assertFalse(escapes_cache_root(posix, resolve_cache_path(posix, raw)))
        # ntpath treats backslashes as separators -> escape
        self.assertTrue(escapes_cache_root(windows, resolve_cache_path(windows, raw)))


class TestPlanGeneration(unittest.TestCase):
    URLS = [
        "https://example.com/products/books/1",
        "https://example.com/products/",
        "https://example.com/",
    ]

    def test_plan_only_emits_escaping_probes(self):
        plan = build_plan("example.com", KNOWN_SPECS["w3tc-page-cache"],
                          self.URLS)
        self.assertTrue(plan)
        for probe in plan:
            self.assertTrue(probe.escaped)
            self.assertTrue(probe.marker.startswith("bwtr-"))
            # Escapes land at the web root (depth is exact) -> HTTP-verifiable.
            self.assertTrue(probe.verifiable)
            self.assertFalse(probe.resolved_path.startswith(".."))

    def test_plan_deterministic_per_seed(self):
        a = build_plan("example.com", KNOWN_SPECS["w3tc-page-cache"], self.URLS,
                       seed=0)
        b = build_plan("example.com", KNOWN_SPECS["w3tc-page-cache"], self.URLS,
                       seed=0)
        self.assertEqual([p.probe_id for p in a], [p.probe_id for p in b])
        self.assertEqual([p.request_path for p in a],
                         [p.request_path for p in b])
        c = build_plan("example.com", KNOWN_SPECS["w3tc-page-cache"], self.URLS,
                       seed=1)
        self.assertNotEqual([p.marker for p in a], [p.marker for p in c])

    def test_plan_bounded(self):
        plan = build_plan("example.com", KNOWN_SPECS["w3tc-page-cache"],
                          self.URLS, max_probes=5)
        self.assertLessEqual(len(plan), 5)

    def test_hashed_spec_emits_no_escaping_probes(self):
        plan = build_plan("example.com", KNOWN_SPECS["hashed"], self.URLS)
        self.assertEqual(plan, [])

    def test_sanitized_spec_keeps_only_bypass_families(self):
        plan = build_plan("example.com", KNOWN_SPECS["sanitized-raw"],
                          ["https://example.com/"])
        families = {p.family for p in plan}
        self.assertNotIn("dotdot", families)         # literal .. stripped
        self.assertNotIn("encoded_slash", families)  # literal dots still stripped
        self.assertIn("encoded_dot_slash", families)  # encoded dots survive -> ../
        for probe in plan:
            self.assertIn("..", probe.decoded_path)


class TestReplay(unittest.TestCase):
    def _probe(self, *, verifiable=True):
        plan = build_plan("lab.test", KNOWN_SPECS["raw-suffix"],
                          ["https://lab.test/"])
        probe = plan[0]
        probe.verifiable = verifiable
        return probe

    def test_marker_served_and_control_404_is_signal(self):
        probe = self._probe()
        state, hypothesis = classify_replay(200, 200, 404, verifiable=True)
        self.assertEqual(state, "signal")
        self.assertIn("escaped", hypothesis.lower())

    def test_both_404_is_refuted(self):
        state, _ = classify_replay(200, 404, 404, verifiable=True)
        self.assertEqual(state, "refuted")

    def test_ambiguous_pair_is_unknown(self):
        state, _ = classify_replay(200, 200, 200, verifiable=True)
        self.assertEqual(state, "unknown")

    def test_above_web_root_escape_is_lab_check(self):
        state, hypothesis = classify_replay(200, 200, 404, verifiable=False)
        self.assertEqual(state, "lab_check")
        self.assertIn("filesystem", hypothesis.lower())

    def test_runner_uses_fake_transport_end_to_end(self):
        plan = [p for p in build_plan("lab.test", KNOWN_SPECS["raw-suffix"],
                                      ["https://lab.test/"]) if p.verifiable]
        self.assertTrue(plan)

        def craft(_path):
            return _Obs(200)

        def verify(path):
            return _Obs(200 if path.startswith("bwtr-") else 404)

        results = TraversalRunner().run(
            plan, craft=craft, verify=verify, control_path="/bwtr-control-x.html")
        self.assertTrue(results)
        self.assertTrue(all(r.state == "signal" for r in results))
        self.assertTrue(all(r.verify_status == 200 for r in results))


class TestBases(unittest.TestCase):
    def test_representative_bases(self):
        bases = representative_bases([
            "https://example.com/products/books/1",
            "https://example.com/products/",
            "https://example.com/health",
        ])
        # single-segment pages have no subdirectory -> web root is the base
        self.assertEqual(bases, ["/products/books", "/products", "/"])

    def test_empty_urls_defaults_to_webroot(self):
        self.assertEqual(representative_bases([]), ["/"])
        self.assertEqual(representative_bases(["https://example.com"]), ["/"])


if __name__ == "__main__":
    unittest.main()

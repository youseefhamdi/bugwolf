#!/usr/bin/env python3
"""Tests for the target-specific custom wordlist generator."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.wordlist_gen import (
    generate, mine_path_tokens, mine_params, mine_js_tokens,
    target_wordforms, tech_patterns, permute, bypass_payloads,
    adapted_payloads, save_cache,
)


class TestMining(unittest.TestCase):

    def test_mine_path_tokens(self):
        tokens = mine_path_tokens([
            "https://acme.com/api/v2/users/123?x=1",
            "https://acme.com/wp-content/uploads/photo.png",
        ])
        self.assertIn("api", tokens)
        self.assertIn("users", tokens)
        self.assertIn("wp-content", tokens)
        self.assertIn("photo", tokens)

    def test_mine_params(self):
        params = mine_params([
            "https://acme.com/a?redirect=https://x&next=/admin&user_id=5",
        ])
        self.assertEqual(set(params), {"redirect", "next", "user_id"})

    def test_mine_js_tokens(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "app.js"
            p.write_text('const x = "/api/v1/checkout"; let userToken = 1; '
                         'fetch("/admin/settings")')
            tokens = mine_js_tokens([str(p)])
        self.assertIn("api", tokens)
        self.assertIn("checkout", tokens)
        self.assertIn("admin", tokens)
        self.assertIn("settings", tokens)
        self.assertIn("userToken", tokens)


class TestWordformsAndTech(unittest.TestCase):

    def test_target_wordforms_include_brand_and_env(self):
        wf = target_wordforms("acme.com", "shopify, checkout")
        self.assertIn("acme", wf)
        self.assertIn("shopify", wf)
        self.assertIn("dev-acme", wf)
        self.assertIn("acme-api", wf)

    def test_tech_patterns_wordpress(self):
        pats = tech_patterns("wordpress, nginx")
        self.assertIn("wp-admin", pats)
        self.assertIn("wp-json", pats)
        self.assertIn("nginx_status", pats)

    def test_permute_adds_separator_and_number_variants(self):
        out = permute(["api-key"])
        self.assertIn("api_key", out)
        self.assertIn("api-key", out)
        self.assertIn("api-key1", out)
        self.assertIn("Api-Key", out)


class TestGenerate(unittest.TestCase):

    def test_vhosts_mode_only_hostwords(self):
        words = generate("acme.com", mode="vhosts",
                         urls=["https://acme.com/api/v2/users"])
        self.assertIn("acme", words)
        self.assertIn("dev-acme", words)
        # no path segments leak into vhost mode
        self.assertNotIn("users", words)

    def test_params_mode_includes_mined_and_universal(self):
        words = generate("acme.com", mode="params",
                         urls=["https://acme.com/a?redirect=https://x&user_id=5"])
        self.assertIn("redirect", words)
        self.assertIn("user_id", words)
        self.assertIn("id", words)  # universal seed

    def test_dirs_mode_includes_tech_patterns(self):
        words = generate("acme.com", mode="dirs", stack="wordpress")
        self.assertIn("wp-admin", words)
        self.assertIn("wp-json", words)

    def test_research_fn_augments_words(self):
        def fake_research(target, mode, keywords, stack):
            return ["custom-research-term"]
        words = generate("acme.com", mode="vhosts",
                         research_fn=fake_research)
        self.assertIn("custom-research-term", words)

    def test_research_fn_failure_is_ignored(self):
        def bad_research(*a):
            raise RuntimeError("boom")
        words = generate("acme.com", mode="vhosts", research_fn=bad_research)
        self.assertIn("acme", words)  # still works from wordforms

    def test_payloads_mode_is_target_specific(self):
        words = generate("acme.com", mode="payloads")
        self.assertTrue(any("acme.com.evil.com" in w for w in words))

    def test_payloads_mode_keys_redirect_to_mined_params(self):
        words = generate("acme.com", mode="payloads",
                         urls=["https://acme.com/a?redirect=https://x&next=/admin"],
                         bug_class="")
        # the *mined* redirect sinks are fired, not just the generic ones
        self.assertIn("redirect=//acme.com.evil.com", words)
        self.assertIn("next=https://acme.com.evil.com", words)

    def test_payloads_mode_adds_reflection_markers_on_mined_params(self):
        words = generate("acme.com", mode="payloads",
                         urls=["https://acme.com/a?user_id=5&search=q"])
        self.assertIn("user_id=rix4uni", words)
        self.assertIn("search=%22onmouseover%3Dalert(1)", words)
        self.assertIn("user_id={{7*7}}", words)

    def test_payloads_mode_adds_path_aware_traversal(self):
        words = generate("acme.com", mode="payloads",
                         urls=["https://acme.com/api/v2/users/1"])
        self.assertIn("api/../../etc/passwd", words)
        self.assertIn("users/..%2f..%2fetc%2fpasswd", words)


class TestBypassPayloads(unittest.TestCase):

    def test_bypass_payloads_for_xss_include_waf_variants(self):
        p = bypass_payloads("xss")
        self.assertIn("<svg/onload=alert(1)>", p)
        self.assertIn("<ScRiPt>alert(1)</ScRiPt>", p)
        # encoded variants are generated
        self.assertTrue(any(x.startswith("%3C") for x in p))

    def test_bypass_payloads_unknown_class_returns_all(self):
        p = bypass_payloads("foobar")
        self.assertTrue(any("alert(1)" in x for x in p))
        self.assertTrue(any("1=1" in x for x in p))

    def test_bypass_payloads_sql_class(self):
        p = bypass_payloads("sqli")
        self.assertIn("' OR 1=1--", p)
        self.assertIn("UNION/**/SELECT/**/1,2,3--", p)
        # no XSS leakage
        self.assertFalse(any("alert(1)" in x for x in p))

    def test_payloads_mode_includes_bypass_payloads(self):
        words = generate("acme.com", mode="payloads", bug_class="sqli")
        self.assertIn("' OR 1=1--", words)
        # XSS bypass payloads are not added for an sqli class (the target
        # reflection marker "test%22onmouseover%3dalert(1)" is still present).
        self.assertNotIn("<svg/onload=alert(1)>", words)
        self.assertNotIn("<ScRiPt>alert(1)</ScRiPt>", words)


class TestAdaptedPayloads(unittest.TestCase):

    def test_redirect_params_mined(self):
        out = adapted_payloads("acme.com", param_tokens=["redirect", "next"])
        self.assertIn("redirect=//acme.com.evil.com", out)
        self.assertIn("next=https://acme.com.evil.com", out)

    def test_redirect_fallback_when_none_mined(self):
        out = adapted_payloads("acme.com", param_tokens=["q"])
        self.assertIn("redirect=//acme.com.evil.com", out)
        self.assertIn("next=https://acme.com.evil.com", out)
        self.assertIn("url=//evil.com/%2f..%2facme.com", out)

    def test_reflection_markers_on_params(self):
        out = adapted_payloads("acme.com", param_tokens=["user_id"])
        self.assertIn("user_id=rix4uni", out)
        self.assertIn("user_id=%22onmouseover%3Dalert(1)", out)
        self.assertIn("user_id={{7*7}}", out)

    def test_path_aware_traversal(self):
        out = adapted_payloads("acme.com", path_tokens=["api", "users"])
        self.assertIn("api/../../etc/passwd", out)
        self.assertIn("users/..%2f..%2fetc%2fpasswd", out)

    def test_empty_tokens_still_yield_redirect_sinks(self):
        out = adapted_payloads("acme.com")
        self.assertTrue(any("acme.com.evil.com" in o for o in out))


class TestSaveCache(unittest.TestCase):

    def test_save_cache_persists_to_stable_location(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fname = save_cache("acme.com", "vhosts", ["acme", "dev-acme"],
                               cache_root=root)
            self.assertEqual(fname, root / "acme.com" / "wordlists" / "vhosts.txt")
            self.assertEqual(fname.read_text().splitlines(), ["acme", "dev-acme"])

    def test_save_cache_sanitizes_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            fname = save_cache("acme.com/path", "params", ["id"], cache_root=root)
            self.assertTrue(fname.exists())
            self.assertIn("acme.com_path", str(fname))

    def test_save_cache_overwrites_same_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            save_cache("acme.com", "dirs", ["a", "b"], cache_root=root)
            save_cache("acme.com", "dirs", ["a", "b", "c"], cache_root=root)
            fname = root / "acme.com" / "wordlists" / "dirs.txt"
            self.assertEqual(fname.read_text().splitlines(), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()

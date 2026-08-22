#!/usr/bin/env python3
"""
Tests for the BugWolf Mandatory Deep-Research Loop generator.

Run:  python3 -m unittest discover -s tests -v

Guards the core property: research tasks are deterministic, ordered, expand
{stack}/{target}/{bug_class} placeholders into concrete queries, and cover the
canonical sources at every checkpoint so the hunt never goes stale.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.research_loop import (
    ResearchLoop, ResearchExecutor, CHECKPOINTS, CANONICAL,
    _html_to_text, _slugify, search_web,
)


def types(tasks):
    return [t.task_type for t in tasks]


class TestPreHuntBaseline(unittest.TestCase):

    def test_always_includes_canonical_baseline_sources(self):
        loop = ResearchLoop()
        tasks = loop.tasks("pre-hunt", ["web"])
        fetched = [t.source for t in tasks if t.task_type == "fetch"]
        self.assertIn(CANONICAL["owasp_web"][1], fetched)
        self.assertIn(CANONICAL["cwe25"][1], fetched)
        self.assertIn(CANONICAL["kev"][1], fetched)

    def test_llm_ai_mode_adds_llm_and_agentic_sources(self):
        loop = ResearchLoop()
        tasks = loop.tasks("pre-hunt", ["llm-ai"])
        fetched = [t.source for t in tasks if t.task_type == "fetch"]
        self.assertIn(CANONICAL["llm26"][1], fetched)
        self.assertIn(CANONICAL["agentic26"][1], fetched)
        queries = " ".join(t.query for t in tasks if t.task_type == "search")
        self.assertIn("ASI", queries)

    def test_tasks_are_ordered(self):
        loop = ResearchLoop()
        tasks = loop.tasks("pre-hunt", ["web"])
        orders = [t.order for t in tasks]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(orders[0], 1)


class TestPostReconStackExpansion(unittest.TestCase):

    def test_stack_placeholder_expands_per_version(self):
        loop = ResearchLoop(stack="next.js 15.1, langchain 0.3")
        tasks = loop.tasks("post-recon", ["web", "llm-ai"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertIn("next.js 15.1 CVE security advisory", queries)
        self.assertIn("langchain 0.3 CVE prompt injection vulnerability", queries)

    def test_stack_placeholder_with_no_stack_is_dropped(self):
        loop = ResearchLoop()
        tasks = loop.tasks("post-recon", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertFalse(any("{stack}" in q for q in queries))
        self.assertEqual(queries, [])


class TestPostMapsAndFindings(unittest.TestCase):

    def test_post_maps_emits_map_write_backs(self):
        loop = ResearchLoop()
        tasks = loop.tasks("post-maps", ["web"])
        mapped = [t.source for t in tasks if t.task_type == "map"]
        self.assertIn("maps/asset.md", mapped)
        self.assertIn("maps/capability.md", mapped)

    def test_post_findings_expands_bug_class(self):
        loop = ResearchLoop(bug_classes="idor, sqli")
        tasks = loop.tasks("post-findings", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertIn("idor bypass 2026 hackerone disclosed report", queries)
        self.assertIn("sqli bypass 2026 hackerone disclosed report", queries)

    def test_bug_class_placeholder_with_none_is_dropped(self):
        loop = ResearchLoop()
        tasks = loop.tasks("post-findings", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertFalse(any("{bug_class}" in q for q in queries))


class TestBypassAndEscalation(unittest.TestCase):

    def test_bypass_expands_defense_and_bug_class(self):
        loop = ResearchLoop(defense="Cloudflare WAF", bug_classes="sqli")
        tasks = loop.tasks("bypass", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertIn("Cloudflare WAF sqli bypass 2026", queries)
        self.assertIn("Cloudflare WAF filter evasion payload technique", queries)
        self.assertIn("Cloudflare WAF WAF bypass payload 2026", queries)

    def test_bypass_without_defense_drops_defense_queries(self):
        loop = ResearchLoop(bug_classes="sqli")
        tasks = loop.tasks("bypass", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertFalse(any("{defense}" in q for q in queries))
        self.assertEqual(queries, [])

    def test_escalation_expands_bug_class_and_target(self):
        loop = ResearchLoop(target="acme", bug_classes="idor")
        tasks = loop.tasks("escalation", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertIn("idor high critical disclosed report bounty 2026", queries)
        self.assertIn("idor chained account-takeover rce 2026", queries)
        self.assertIn("idor acme", queries)
        self.assertIn("idor escalation privilege account takeover hackerone 2026", queries)

    def test_escalation_without_bug_class_drops_queries(self):
        loop = ResearchLoop(target="acme")
        tasks = loop.tasks("escalation", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertEqual(queries, [])

    def test_bypass_and_escalation_are_registered_checkpoints(self):
        self.assertIn("bypass", CHECKPOINTS)
        self.assertIn("escalation", CHECKPOINTS)


class TestWordlistTasks(unittest.TestCase):

    def test_post_maps_emits_wordlist_tasks_for_web(self):
        loop = ResearchLoop(target="acme")
        tasks = loop.tasks("post-maps", ["web"])
        wl = [t for t in tasks if t.task_type == "wordlist"]
        self.assertEqual([t.source for t in wl],
                         ["vhosts", "params", "dirs", "payloads"])

    def test_contract_mode_skips_wordlist_tasks(self):
        loop = ResearchLoop(target="acme")
        tasks = loop.tasks("post-maps", ["solidity"])
        self.assertFalse(any(t.task_type == "wordlist" for t in tasks))

    def test_render_includes_wordlist_tasks(self):
        loop = ResearchLoop(target="acme")
        out = loop.render("post-maps", ["web"])
        self.assertIn("generate vhosts wordlist", out)
        self.assertIn("generate params wordlist", out)
        self.assertIn("generate dirs wordlist", out)
        self.assertIn("generate payloads wordlist", out)

    def test_bypass_checkpoint_emits_payloads_wordlist(self):
        loop = ResearchLoop(target="acme", defense="Cloudflare WAF",
                            bug_classes="sqli")
        tasks = loop.tasks("bypass", ["web"])
        wl = [t for t in tasks if t.task_type == "wordlist"]
        self.assertEqual([t.source for t in wl], ["payloads"])


class TestWordlistExecution(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.loop = ResearchLoop(target="acme", stack="django 5.0")

    def tearDown(self):
        self.tmp.cleanup()

    def test_wordlist_execution_persists_files(self):
        ex = ResearchExecutor(target="acme", base_dir=str(self.base),
                              run_search=False)
        with mock.patch("tools.wordlist_gen.generate",
                        return_value=["acme", "dev-acme", "api"]):
            ex.execute(self.loop, "post-maps", ["web"])

        wdir = self.base / "acme" / "post-maps" / "wordlists"
        self.assertTrue((wdir / "vhosts.txt").exists())
        self.assertTrue((wdir / "params.txt").exists())
        self.assertTrue((wdir / "dirs.txt").exists())
        self.assertTrue((wdir / "payloads.txt").exists())
        self.assertEqual((wdir / "vhosts.txt").read_text().splitlines(),
                         ["acme", "dev-acme", "api"])

        data = json.loads(
            (self.base / "acme" / "post-maps" / "results.json").read_text())
        wl_recs = [r for r in data["records"] if r["task_type"] == "wordlist"]
        self.assertEqual({r["wordlist_mode"] for r in wl_recs},
                         {"vhosts", "params", "dirs", "payloads"})
        self.assertTrue(all(r.get("saved_to") for r in wl_recs))
        # stable cross-turn cache is also written
        stable = self.base / "acme" / "wordlists" / "vhosts.txt"
        self.assertTrue(stable.exists())
        stable_payloads = self.base / "acme" / "wordlists" / "payloads.txt"
        self.assertTrue(stable_payloads.exists())


class TestPreReport(unittest.TestCase):

    def test_pre_report_expands_target_and_bug_class(self):
        loop = ResearchLoop(target="acme", bug_classes="account-takeover")
        tasks = loop.tasks("pre-report", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertIn("acme bug bounty program scope rules", queries)
        self.assertIn("acme disclosed report account-takeover", queries)

    def test_pre_report_without_target_drops_queries(self):
        loop = ResearchLoop(bug_classes="xss")
        tasks = loop.tasks("pre-report", ["web"])
        queries = [t.query for t in tasks if t.task_type == "search"]
        self.assertEqual(queries, [])


class TestValidationAndSerialization(unittest.TestCase):

    def test_unknown_checkpoint_raises(self):
        loop = ResearchLoop()
        with self.assertRaises(ValueError):
            loop.tasks("bogus-checkpoint", ["web"])

    def test_all_checkpoints_render(self):
        loop = ResearchLoop(target="acme", stack="flask 3.0",
                            bug_classes="idor")
        for name in CHECKPOINTS:
            out = loop.render(name, ["web"])
            self.assertIn(name, out)

    def test_tasks_serialize_to_dict(self):
        loop = ResearchLoop(stack="django 5.0")
        tasks = loop.tasks("post-recon", ["web"])
        d = tasks[0].to_dict()
        self.assertIn("checkpoint", d)
        self.assertIn("order", d)
        self.assertIn("task_type", d)

    def test_canonical_sources_are_urls(self):
        for name, url in CANONICAL.values():
            self.assertTrue(url.startswith("http"), f"{name} -> {url}")


class TestHtmlAndSlug(unittest.TestCase):

    def test_html_to_text_strips_tags_and_script(self):
        out = _html_to_text("<h1>Title</h1><p>body</p><script>alert(1)</script>end")
        self.assertIn("Title", out)
        self.assertIn("body", out)
        self.assertIn("end", out)
        self.assertNotIn("<script>", out)
        self.assertNotIn("alert(1)", out)

    def test_html_to_text_unescapes_entities(self):
        out = _html_to_text("<p>a &amp; b &lt;tag&gt;</p>")
        self.assertIn("a & b", out)
        self.assertIn("<tag>", out)

    def test_slugify_from_url(self):
        self.assertEqual(_slugify("https://owasp.org/www-project-top-ten/"),
                         "www-project-top-ten")
        self.assertEqual(_slugify("https://cwe.mitre.org/top25/"), "top25")


class TestExecutionAndPersistence(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.loop = ResearchLoop(target="acme", stack="django 5.0",
                                 bug_classes="idor")

    def tearDown(self):
        self.tmp.cleanup()

    def _executor(self, **kw):
        return ResearchExecutor(target="acme", base_dir=str(self.base), **kw)

    def test_fetch_persists_source_summary_and_json(self):
        with mock.patch("tools.research_loop.fetch_url") as fetch:
            fetch.return_value = {
                "url": "https://x/source", "final_url": "https://x/source",
                "status": 200, "text": "<h1>t</h1><p>body</p>",
                "content_type": "text/html", "error": ""}
            ex = self._executor(run_search=False)
            ex.execute(self.loop, "pre-hunt", ["web"])

        cdir = self.base / "acme" / "pre-hunt"
        self.assertTrue((cdir / "SUMMARY.md").exists())
        self.assertTrue((cdir / "results.json").exists())
        sources = list((cdir / "sources").glob("*.md"))
        self.assertTrue(sources)

        data = json.loads((cdir / "results.json").read_text())
        self.assertEqual(data["schema"], "research_execution/1.0")
        self.assertEqual(data["target"], "acme")
        fetched = [r for r in data["records"] if r["task_type"] == "fetch"]
        self.assertTrue(fetched)
        self.assertTrue(all(r.get("saved_to") for r in fetched))

    def test_fetch_error_recorded_without_crash_or_source_file(self):
        with mock.patch("tools.research_loop.fetch_url") as fetch:
            fetch.return_value = {
                "url": "https://x", "final_url": "https://x", "status": 404,
                "text": "", "content_type": "", "error": "HTTPError: 404"}
            ex = self._executor(run_search=False)
            ex.execute(self.loop, "pre-hunt", ["web"])

        data = json.loads(
            (self.base / "acme" / "pre-hunt" / "results.json").read_text())
        fetched = [r for r in data["records"] if r["task_type"] == "fetch"]
        self.assertTrue(any(r.get("error") for r in fetched))
        srcs = list((self.base / "acme" / "pre-hunt" / "sources").glob("*.md"))
        self.assertEqual(srcs, [])

    def test_search_results_recorded(self):
        with mock.patch("tools.research_loop.search_web") as sw:
            sw.return_value = [{"title": "T", "url": "https://u", "snippet": "s"}]
            ex = self._executor(run_search=True)
            res = ex.execute(self.loop, "pre-hunt", ["web"])
        searches = [r for r in res["records"] if r["task_type"] == "search"]
        self.assertTrue(searches)
        self.assertTrue(all(r.get("results") for r in searches))
        self.assertTrue(all(not r.get("pending") for r in searches))

    def test_search_without_provider_marks_pending(self):
        with mock.patch("tools.research_loop.search_web", return_value=[]):
            ex = self._executor(run_search=True)
            res = ex.execute(self.loop, "pre-hunt", ["web"])
        searches = [r for r in res["records"] if r["task_type"] == "search"]
        self.assertTrue(all(r.get("pending") for r in searches))

    def test_offline_search_uses_bundled_references(self):
        with mock.patch.dict("os.environ", {
                "SERPER_API_KEY": "", "RESEARCH_SEARCH_API_KEY": ""}, clear=False):
            results = search_web("OWASP web application risks", limit=2)
        self.assertTrue(results)
        self.assertTrue(all(r["source"] == "bundled_reference" for r in results))
        self.assertEqual(search_web.last_backend, "bundled_reference")

    def test_require_latest_disables_offline_fallback(self):
        with mock.patch.dict("os.environ", {
                "SERPER_API_KEY": "", "RESEARCH_SEARCH_API_KEY": ""}, clear=False):
            results = search_web("latest bypass techniques", allow_offline=False)
        self.assertEqual(results, [])
        self.assertEqual(search_web.last_backend, "live_provider_unconfigured")

    def test_require_latest_keeps_provider_errors_pending(self):
        with mock.patch.dict("os.environ", {
                "SERPER_API_KEY": "test-key",
                "RESEARCH_SEARCH_API_URL": "https://search.example.test/api",
        }, clear=False), mock.patch("tools.research_loop.urllib.request.urlopen",
                                    side_effect=OSError("provider unavailable")):
            results = search_web("latest bypass techniques", allow_offline=False)
        self.assertEqual(results, [])
        self.assertEqual(search_web.last_backend, "live_provider_error")

    def test_execute_sequential_preserves_checkpoint_order(self):
        with mock.patch("tools.research_loop.fetch_url", return_value={
                "url": "https://x", "final_url": "https://x", "status": 200,
                "text": "source", "content_type": "text/plain", "error": ""}), \
             mock.patch("tools.research_loop.search_web", return_value=[{
                 "title": "latest", "url": "https://u", "snippet": "s"}]):
            ex = self._executor(run_search=True)
            result = ex.execute_sequential(
                self.loop, ["web"],
                checkpoints=["pre-hunt", "post-recon", "post-maps"],
                require_latest=True)
        self.assertEqual(result["sequence"],
                         ["pre-hunt", "post-recon", "post-maps"])
        self.assertTrue(result["latest_ready"])
        manifest = json.loads(Path(result["sequence_file"]).read_text())
        self.assertEqual([item["sequence"] for item in manifest["runs"]], [1, 2, 3])
        self.assertEqual(len(manifest["executions"]), 1)

        # A subsequent execution appends history but reports only its own
        # ordered run to callers and the CLI summary.
        with mock.patch("tools.research_loop.fetch_url", return_value={
                "url": "https://x", "final_url": "https://x", "status": 200,
                "text": "source", "content_type": "text/plain", "error": ""}), \
             mock.patch("tools.research_loop.search_web", return_value=[{
                 "title": "latest", "url": "https://u", "snippet": "s"}]):
            second = ex.execute_sequential(
                self.loop, ["web"], checkpoints=["bypass"], require_latest=True)
        manifest = json.loads(Path(second["sequence_file"]).read_text())
        self.assertEqual(second["sequence"], ["pre-hunt", "post-recon", "post-maps", "bypass"])
        self.assertEqual(second["current_execution"]["sequence"], ["bypass"])
        self.assertEqual(manifest["runs"][0]["checkpoint"], "bypass")
        self.assertEqual(len(manifest["executions"]), 2)

    def test_run_search_false_marks_all_pending_without_calling(self):
        with mock.patch("tools.research_loop.search_web") as sw:
            ex = self._executor(run_search=False)
            res = ex.execute(self.loop, "pre-hunt", ["web"])
            sw.assert_not_called()
        searches = [r for r in res["records"] if r["task_type"] == "search"]
        self.assertTrue(searches)
        self.assertTrue(all(r.get("pending") for r in searches))

    def test_map_write_backs_recorded(self):
        with mock.patch("tools.research_loop.fetch_url", return_value={
                "url": "https://x", "final_url": "https://x", "status": 200,
                "text": "x", "content_type": "text/html", "error": ""}):
            ex = self._executor(run_search=False)
            res = ex.execute(self.loop, "post-maps", ["web"])
        maps = [r for r in res["records"] if r["task_type"] == "map"]
        self.assertTrue(maps)
        self.assertIn("maps/asset.md", [m["map_target"] for m in maps])

    def test_target_sanitized_in_dir_name(self):
        loop = ResearchLoop(target="acme.com/path", stack="x 1.0")
        with mock.patch("tools.research_loop.fetch_url", return_value={
                "url": "https://x", "final_url": "https://x", "status": 200,
                "text": "x", "content_type": "text/html", "error": ""}):
            ex = ResearchExecutor(target="acme.com/path",
                                  base_dir=str(self.base), run_search=False)
            ex.execute(loop, "pre-hunt", ["web"])
        # slash sanitized to underscore
        self.assertTrue((self.base / "acme.com_path" / "pre-hunt").exists())


if __name__ == "__main__":
    unittest.main()

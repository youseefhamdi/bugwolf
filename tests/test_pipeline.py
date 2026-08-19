#!/usr/bin/env python3
"""
End-to-end pipeline test: tech_fingerprint → research_loop → llm_attack_surface.

Run:  python3 -m unittest discover -s tests -v

Guards the integration the SKILL.md turns now rely on: a target's stack feeds
the R2 post-recon research checkpoint, the LLM attack-surface detector then
finds the `llm-*` bug classes, and those classes feed back into the R4
post-findings checkpoint — one coherent pipeline, not three isolated tools.

Network is mocked (fetch/search) so the test is deterministic and offline.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tech_fingerprint import TechFingerprinter
from tools.research_loop import ResearchLoop, ResearchExecutor
from tools.llm_attack_surface import LLMAttackSurfaceScanner

FETCH_OK = {
    "url": "https://x", "final_url": "https://x", "status": 200,
    "text": "<h1>t</h1><p>body</p>", "content_type": "text/html", "error": "",
}
SEARCH_OK = [{"title": "T", "url": "https://u", "snippet": "s"}]


def build_sample_target(root: Path) -> Path:
    """A small LLM/agentic + web target for the pipeline to chew on."""
    target = root / "app"
    target.mkdir()
    (target / "package.json").write_text(json.dumps({
        "dependencies": {
            "openai": "^1.40.0",
            "langchain": "^0.3.0",
            "@pinecone-database/pinecone": "^4.0.0",
        }
    }))
    (target / "requirements.txt").write_text("django==5.0.1\n")
    (target / "app.py").write_text(
        "import subprocess\n"
        "from langchain.chains import RetrievalQA\n"
        "prompt = f\"Answer the user: {user_query}\"\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n"
    )
    return target


def run_pipeline(target: Path, research_base: Path, target_name: str,
                 run_search: bool = True) -> dict:
    """tech_fingerprint → research_loop (R2) → llm_attack_surface → R4 feedback."""
    # 1. Fingerprint the stack
    fp = TechFingerprinter()
    stack = fp.stack_csv(fp.scan_path(str(target)))

    # 2. R2 post-recon research, executed + persisted
    loop = ResearchLoop(target=target_name, stack=stack)
    executor = ResearchExecutor(target=target_name, base_dir=str(research_base),
                                run_search=run_search)
    r2 = executor.execute(loop, "post-recon", ["web", "llm-ai"])

    # 3. LLM attack-surface detection
    scanner = LLMAttackSurfaceScanner()
    findings = scanner.scan_path(str(target))
    bug_classes = sorted({f.bug_class for f in findings})

    # 4. Feed found bug classes back into R4 post-findings
    loop4 = ResearchLoop(target=target_name, bug_classes=",".join(bug_classes))
    r4_tasks = loop4.tasks("post-findings", ["llm-ai", "web"])

    return {
        "stack": stack,
        "r2_dir": r2["dir"],
        "r2_records": r2["records"],
        "llm_bug_classes": bug_classes,
        "r4_queries": [t.query for t in r4_tasks if t.task_type == "search"],
    }


class TestResearchThenSurfacePipeline(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = build_sample_target(self.root)
        self.research_base = self.root / "research"

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_pipeline_produces_cross_referenced_output(self):
        with mock.patch("tools.research_loop.fetch_url", return_value=FETCH_OK), \
             mock.patch("tools.research_loop.search_web", return_value=SEARCH_OK):
            p = run_pipeline(self.target, self.research_base, "acme")

        # 1. stack fingerprint captured the dependencies
        self.assertIn("django 5.0.1", p["stack"])
        self.assertIn("openai 1.40.0", p["stack"])

        # 2. R2 research persisted and its queries reference the exact versions
        cdir = self.research_base / "acme" / "post-recon"
        self.assertTrue((cdir / "SUMMARY.md").exists())
        self.assertTrue((cdir / "results.json").exists())
        self.assertTrue((cdir / "sources").exists())
        r2_searches = [r["query"] for r in p["r2_records"]
                       if r["task_type"] == "search"]
        self.assertTrue(any("django 5.0.1" in q for q in r2_searches),
                        f"R2 queries missing version: {r2_searches}")

        # 3. llm_attack_surface found the planted surfaces
        self.assertIn("excessive-agency", p["llm_bug_classes"])
        self.assertIn("prompt-injection", p["llm_bug_classes"])
        self.assertTrue({"rag-poisoning", "tool-misuse"} <= set(p["llm_bug_classes"]))

        # 4. found classes fed back into the R4 post-findings queries
        self.assertTrue(p["r4_queries"])
        joined = " ".join(p["r4_queries"])
        self.assertIn("excessive-agency", joined)
        self.assertIn("prompt-injection", joined)

    def test_pipeline_degrades_to_pending_search_without_provider(self):
        with mock.patch("tools.research_loop.fetch_url", return_value=FETCH_OK), \
             mock.patch("tools.research_loop.search_web", return_value=[]):
            p = run_pipeline(self.target, self.research_base, "acme",
                             run_search=True)

        # fetches still completed; searches are pending, not failures
        fetches = [r for r in p["r2_records"] if r["task_type"] == "fetch"]
        searches = [r for r in p["r2_records"] if r["task_type"] == "search"]
        self.assertTrue(fetches)
        self.assertTrue(all(not r.get("error") for r in fetches))
        self.assertTrue(searches)
        self.assertTrue(all(r.get("pending") for r in searches))

        # pipeline still reached the LLM surface and R4 feedback
        self.assertIn("excessive-agency", p["llm_bug_classes"])
        self.assertTrue(p["r4_queries"])


if __name__ == "__main__":
    unittest.main()

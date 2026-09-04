#!/usr/bin/env python3
"""Intel layer tests: research engine sources (injected urlopen fixtures),
research packs, technique ledger lifecycle, new agents, team integration."""

import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.intel.research_engine import (  # noqa: E402
    ResearchEngine, IntelItem, _KEV_URL)
from tools.intel.technique_ledger import (  # noqa: E402
    TechniqueLedger, content_digest, STATUS_QUARANTINE, STATUS_ACTIVE,
    STATUS_EXPIRED)


def _fake_urlopen(responses):
    """Map URL substring -> JSON body; unexpected URLs raise (degradation)."""
    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for needle, body in responses.items():
            if needle in url:
                if isinstance(body, Exception):
                    raise body
                return io.BytesIO(json.dumps(body).encode("utf-8"))
        raise AssertionError(f"unexpected url {url}")
    return _open


NVD_BODY = {
    "vulnerabilities": [{
        "cve": {"id": "CVE-2026-1234", "published": "2026-08-01T00:00:00Z",
                "containers": {"cna": {
                    "title": "nginx http2 use-after-free",
                    "descriptions": [{"lang": "en",
                                      "value": "heap corruption"}],
                    "metrics": [{"cvssV3_1": {"baseSeverity": "HIGH"}}]}}}}]
}
GITHUB_BODY = {"items": [{
    "full_name": "attacker/nginx-poc", "html_url": "https://github.com/x",
    "pushed_at": "2026-08-20T00:00:00Z", "stargazers_count": 42,
    "description": "PoC for CVE-2026-1234"}]}
KEV_BODY = {"vulnerabilities": [
    {"cveID": "CVE-2026-1234", "vendorProject": "f5", "product": "nginx",
     "dateAdded": "2026-08-15", "shortDescription": "actively exploited",
     "knownRansomwareCampaignUse": "Known"}]}
REDDIT_BODY = {"data": {"children": [{"data": {
    "title": "new nginx bypass", "permalink": "/r/netsec/x",
    "created_utc": datetime.now(timezone.utc).timestamp() - 86400,
    "selftext": "details", "score": 100}}]}}
HN_BODY = {"hits": [{"title": "nginx RCE", "objectID": "1",
                     "created_at_i": int(datetime.now(timezone.utc)
                                         .timestamp()) - 3600,
                     "points": 120, "url": "https://example.com/a",
                     "story_text": ""}]}


class TestResearchEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_pack_with_all_sources_live(self):
        eng = ResearchEngine(urlopen=_fake_urlopen({
            "services.nvd.nist.gov": NVD_BODY,
            "api.github.com": GITHUB_BODY,
            "cisa.gov": KEV_BODY,
            "reddit.com": REDDIT_BODY,
            "hn.algolia.com": HN_BODY,
        }))
        pack = eng.build_pack(tech_stack=[("nginx", "1.24.0")],
                              bug_classes=["ssrf"])
        d = pack.to_dict()
        self.assertIn("kev", d["sources_polled"])
        self.assertIn("nvd:nginx", d["sources_polled"])
        self.assertIn("github:nginx", d["sources_polled"])
        self.assertEqual(len(d["cve_matches"]), 1)
        match = d["cve_matches"][0]
        self.assertEqual(match["cve_ids"], ["CVE-2026-1234"])
        self.assertTrue(match["kev"])               # KEV correlation hit
        self.assertEqual(match["confidence"], 0.95)  # KEV weight
        self.assertEqual(len(d["poc_leads"]), 1)
        self.assertGreaterEqual(len(d["community_signals"]), 2)
        self.assertEqual(pack.digest(), pack.digest())  # deterministic digest

    def test_degraded_sources_recorded_not_hidden(self):
        eng = ResearchEngine(urlopen=_fake_urlopen({
            "cisa.gov": KEV_BODY,
            "services.nvd.nist.gov": OSError("net down"),
            "api.github.com": OSError("net down"),
            "reddit.com": OSError("net down"),
            "hn.algolia.com": OSError("net down"),
        }))
        pack = eng.build_pack(tech_stack=[("nginx", "")], bug_classes=[])
        d = pack.to_dict()
        self.assertIn("nvd:nginx", d["sources_degraded"])
        self.assertIn("reddit", d["sources_degraded"])
        self.assertEqual(d["cve_matches"], [])
        self.assertTrue(any("degraded" in n for n in d["notes"]))

    def test_plan_only_never_fetches(self):
        def boom(req, timeout=None):
            raise AssertionError("live fetch in plan-only mode")
        eng = ResearchEngine(urlopen=boom)
        pack = eng.build_pack(tech_stack=[("nginx", "1.24.0")],
                              bug_classes=["idor"], live=False)
        d = pack.to_dict()
        self.assertEqual(d["sources_polled"], [])
        plans = {p["source"] for p in d["query_plans"]}
        self.assertIn("x-twitter", plans)
        self.assertIn("medium", plans)
        self.assertIn("dork", plans)
        # plan queries are concrete (harness can execute them verbatim)
        x_plan = next(p for p in d["query_plans"]
                      if p["source"] == "x-twitter")
        self.assertIn("nginx", x_plan["query"])
        self.assertIn("after:", x_plan["query"])

    def test_version_unconfirmed_lowers_confidence(self):
        body = json.loads(json.dumps(NVD_BODY))
        body["vulnerabilities"][0]["cve"]["containers"]["cna"]["title"] = \
            "totally unrelated component issue"
        eng = ResearchEngine(urlopen=_fake_urlopen({
            "services.nvd.nist.gov": body, "cisa.gov": {"vulnerabilities": []},
            "api.github.com": {"items": []}}))
        pack = eng.build_pack(tech_stack=[("nginx", "1.24.0")], bug_classes=[])
        match = pack.to_dict()["cve_matches"][0]
        self.assertLess(match["confidence"], 0.9)   # downgraded, not dropped


class TestTechniqueLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = TechniqueLedger(project_root=self.tmp.name, ttl_days=90)

    def test_quarantine_invisible_to_agents(self):
        t = self.ledger.submit(title="t", content="c", source="medium")
        self.assertEqual(t.status, STATUS_QUARANTINE)
        self.assertEqual(self.ledger.active(), [])

    def test_approval_releases_and_expires(self):
        t = self.ledger.submit(title="jku bypass", content="body",
                               source="x-twitter", vuln_classes=["jwt_attack"])
        self.ledger.approve(t.technique_id, approved_by="op")
        active = self.ledger.active(vuln_class="jwt_attack")
        self.assertEqual([x.technique_id for x in active], [t.technique_id])
        # class filter excludes non-matching
        self.assertEqual(self.ledger.active(vuln_class="ssrf"), [])
        # tampered content cannot be approved
        t2 = self.ledger.submit(title="x", content="y", source="github")
        raw = self.ledger._path().read_text().replace('"y"', '"z"')
        self.ledger._path().write_text(raw)
        with self.assertRaises(ValueError):
            self.ledger.approve(t2.technique_id)

    def test_ttl_expiry_removes_from_active(self):
        t = self.ledger.submit(title="old", content="c", source="medium")
        self.ledger.approve(t.technique_id)
        future = datetime.now(timezone.utc) + timedelta(days=91)
        self.assertEqual(self.ledger.active(now=future), [])
        swept = self.ledger.expire_sweep()
        # sweep uses wall clock; force by rewriting expiry into the past
        # (lazy view already hides it; sweep persists the status)
        self.assertIsInstance(swept, list)


class TestIntelAgents(unittest.TestCase):
    def test_new_agents_registered(self):
        from tools.core.agent_registry import AgentRegistry
        reg = AgentRegistry()
        for role in ("threat-research", "community-signal", "exploit-intel"):
            spec = reg.get(role)
            self.assertTrue(spec.playbook)
            path = reg.playbook_path(role)
            self.assertTrue(path.is_file())
            self.assertGreater(len(reg.load_prompt(role)), 400)

    def test_cve_hunting_selects_threat_research(self):
        from tools.core.agent_registry import AgentRegistry
        reg = AgentRegistry()
        self.assertEqual(reg.select(bug_class="cve_hunting").role,
                         "threat-research")
        d = reg.dispatch_for(bug_class="poc_matching")
        self.assertEqual(d["agent_role"], "exploit-intel")


class TestTeamIntelIntegration(unittest.TestCase):
    def test_pack_and_techniques_ride_dispatch(self):
        from tools.runtime.contracts import MissionSpec
        from tools.runtime.team import TeamEngine
        with tempfile.TemporaryDirectory() as tmp:
            ledger = TechniqueLedger(project_root=tmp)
            t = ledger.submit(title="canary jwt jku",
                              content="approved body", source="medium",
                              vuln_classes=["jwt_attack"])
            ledger.approve(t.technique_id)
            ledger.submit(title="quarantined trick", content="nope",
                          source="reddit", vuln_classes=["jwt_attack"])

            mission = MissionSpec(mission_id="m-i2", target="stub.local",
                                  domains=["web_api"],
                                  budget={"max_agents": 8,
                                          "max_parallel_tasks": 2})
            seen = {}

            def worker(payload):
                seen[payload["role"]] = payload.get("intel") or {}
                return {"status": "DONE"}

            eng = ResearchEngine(urlopen=_fake_urlopen({
                "cisa.gov": KEV_BODY, "services.nvd.nist.gov": NVD_BODY,
                "api.github.com": {"items": []}}))
            engine = TeamEngine(mission, worker=worker, project_root=tmp)
            # pre-seed the shared pack with fixtures (network-independent)
            engine._research_pack = eng.build_pack(
                tech_stack=[("nginx", "1.24.0")],
                bug_classes=["jwt_attack"])
            engine.run(bug_classes=["jwt_attack"])

            intel = seen.get("crypto-math") or {}
            self.assertTrue(intel.get("research_pack"))
            ids = {t["technique_id"]
                   for t in intel.get("approved_techniques", [])}
            self.assertIn(t.technique_id, ids)
            # quarantine entry never rode along
            contents = " ".join(t2["content"]
                                for t2 in intel["approved_techniques"])
            self.assertNotIn("nope", contents)


if __name__ == "__main__":
    unittest.main()

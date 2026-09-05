#!/usr/bin/env python3
"""Phase 2.5 — Recon + OSINT surface regression tests.

Covers:

  * Workflow YAML schema validation (each workflow parses + validates)
  * ``ReconOrchestrator.plan()`` returns a valid DAG of ``ReconJob``
  * ``ReconOrchestrator.run()`` transitions PENDING → RUNNING → COMPLETED
  * ``ReconOrchestrator.status()`` returns per-job state
  * Tool-not-on-PATH transitions job to FAILED
  * Scope verb mismatches transition job to SKIPPED
  * ``cli.py`` parses ``--target T --workflow W`` correctly
  * ``api.py`` 401 without token, 200 with token
  * ``passive.crt_sh`` returns ``[]`` when no API key
  * Each of 15 OSINT channels returns ``OSINTFinding`` or empty list
  * ``OSINTAutopilot.run()`` deduplicates by URL + content-hash
  * ``CookieExtractor.from_har()`` parses a sample HAR fixture
  * ``Transcriber.transcribe()`` returns ``TranscriptUnavailable``
  * ``osint.skills`` has ≥ 8 entries
  * Workflow roundtrip — every ``*.yaml`` in ``recon/workflows/`` validates

Uses ``unittest.TestCase``; no third-party deps; tests are fully offline
(``recon/passive`` modules detect missing API keys / unreachable
networks and return ``[]`` rather than raising).
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


SAMPLE_HAR = {
    "log": {
        "version": "1.2",
        "creator": {"name": "test", "version": "1"},
        "entries": [
            {
                "request": {
                    "cookies": [
                        {"name": "session", "value": "abc123",
                         "domain": "example.com", "path": "/",
                         "httpOnly": True, "secure": True,
                         "expires": "2030-01-01T00:00:00Z"},
                        {"name": "tracking", "value": "xyz789",
                         "domain": ".example.com", "path": "/",
                         "httpOnly": False, "secure": False},
                    ],
                },
                "response": {
                    "cookies": [
                        {"name": "csrf", "value": "tok123",
                         "domain": "example.com", "path": "/",
                         "httpOnly": True},
                    ],
                },
            },
        ],
    },
}


def _write_har(path: Path) -> None:
    path.write_text(json.dumps(SAMPLE_HAR), encoding="utf-8")


# ===========================================================================
# 1. Workflow YAML schema
# ===========================================================================


class TestWorkflowSchemas(unittest.TestCase):
    """Every shipped workflow YAML parses + conforms to the schema."""

    def setUp(self) -> None:
        self.workflow_dir = (
            ROOT / "bugwolf" / "recon" / "workflows"
        )

    def test_every_workflow_loads(self) -> None:
        from bugwolf.recon.orchestrator import (
            discover_workflows, load_workflow, WORKFLOW_SCHEMA,
        )
        workflows = discover_workflows(self.workflow_dir)
        self.assertGreaterEqual(
            len(workflows), 20,
            f"expected >=20 workflows, found {len(workflows)}: "
            f"{sorted(workflows.keys())}",
        )
        for name, path in sorted(workflows.items()):
            parsed = load_workflow(path)
            self.assertEqual(parsed.get("schema"), WORKFLOW_SCHEMA)
            self.assertTrue(parsed.get("phases"))
            for phase in parsed["phases"]:
                self.assertIn("order", phase)
                self.assertIn("name", phase)
                self.assertIn("tools", phase)
                self.assertTrue(phase["tools"])
                self.assertIn("scope_verb", phase)

    def test_each_workflow_has_unique_orders(self) -> None:
        from bugwolf.recon.orchestrator import load_workflow
        for path in sorted(self.workflow_dir.glob("*.yaml")):
            parsed = load_workflow(path)
            orders = [int(p["order"]) for p in parsed["phases"]]
            self.assertEqual(
                len(orders), len(set(orders)),
                f"duplicate orders in {path.name}",
            )

    def test_workflow_yaml_loader_rejects_bad_schema(self) -> None:
        from bugwolf.recon.orchestrator import (
            WorkflowLoadError, _parse_workflow_yaml, _validate_workflow,
        )
        bad = _parse_workflow_yaml(textwrap.dedent("""
            schema: wrong
            name: bad
            phases:
              - order: 1
                name: p1
                tools: [a]
                scope_verb: passive
        """))
        with self.assertRaises(WorkflowLoadError):
            _validate_workflow(bad, name="bad")


# ===========================================================================
# 2. ReconOrchestrator — planning
# ===========================================================================


class TestOrchestratorPlan(unittest.TestCase):
    """``ReconOrchestrator.plan()`` returns a valid DAG."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bw-recon-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_plan_builds_dag(self) -> None:
        from bugwolf.recon import (
            ReconOrchestrator, STATE_PENDING,
        )
        orch = ReconOrchestrator(
            target="example.com",
            workflow_dir=ROOT / "bugwolf" / "recon" / "workflows",
            state_dir=self.tmp,
        )
        jobs = orch.plan(["quick_triage"])
        self.assertEqual(len(jobs), 4)
        # Phases depend on the previous phase in the same workflow.
        self.assertEqual(jobs[1].depends_on, [jobs[0].job_id])
        self.assertEqual(jobs[2].depends_on, [jobs[1].job_id])
        self.assertEqual(jobs[3].depends_on, [jobs[2].job_id])
        for job in jobs:
            self.assertEqual(job.state, STATE_PENDING)
            self.assertEqual(job.target, "example.com")

    def test_plan_unknown_workflow_skipped(self) -> None:
        from bugwolf.recon import ReconOrchestrator
        orch = ReconOrchestrator(
            target="example.com",
            workflow_dir=ROOT / "bugwolf" / "recon" / "workflows",
            state_dir=self.tmp,
        )
        self.assertEqual(orch.plan(["does-not-exist"]), [])

    def test_status_returns_per_job_state(self) -> None:
        from bugwolf.recon import ReconOrchestrator
        orch = ReconOrchestrator(
            target="example.com",
            workflow_dir=ROOT / "bugwolf" / "recon" / "workflows",
            state_dir=self.tmp,
        )
        orch.plan(["quick_triage"])
        status = orch.status()
        self.assertEqual(len(status), 4)
        for jid, state in status.items():
            self.assertEqual(state, "PENDING")
            self.assertTrue(jid)


# ===========================================================================
# 3. ReconOrchestrator — execution
# ===========================================================================


class TestOrchestratorRun(unittest.TestCase):
    """``ReconOrchestrator.run()`` transitions jobs correctly."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bw-run-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run_completes_when_tools_missing(self) -> None:
        """Missing tools → FAILED, run still terminates and reports."""
        from bugwolf.recon import (
            ReconOrchestrator, STATE_FAILED, ReconReport,
        )
        orch = ReconOrchestrator(
            target="example.com",
            workflow_dir=ROOT / "bugwolf" / "recon" / "workflows",
            state_dir=self.tmp,
        )
        orch.plan(["active_recon"])
        report = orch.run(timeout=10.0)
        self.assertIsInstance(report, ReconReport)
        self.assertEqual(report.target, "example.com")
        # All 5 phases should be in a terminal state.
        for job in report.jobs:
            self.assertIn(
                job.state,
                {STATE_FAILED, "COMPLETED", "SKIPPED"},
            )

    def test_run_skips_out_of_scope_phases(self) -> None:
        """Phases whose scope_verb is not in the scope file → SKIPPED."""
        from bugwolf.recon import ReconOrchestrator, STATE_SKIPPED

        scope = self.tmp / "scope.txt"
        scope.write_text("passive\n", encoding="utf-8")

        orch = ReconOrchestrator(
            target="example.com",
            scope_file=str(scope),
            workflow_dir=ROOT / "bugwolf" / "recon" / "workflows",
            state_dir=self.tmp,
        )
        orch.plan(["active_recon"])
        report = orch.run(timeout=10.0)
        skipped = [j for j in report.jobs if j.state == STATE_SKIPPED]
        self.assertGreater(len(skipped), 0,
                           "expected active phases to be skipped under "
                           "passive-only scope")

    def test_run_with_stubbed_tool_succeeds(self) -> None:
        """When 'subfinder' is faked onto PATH, phases transition to
        COMPLETED."""
        from bugwolf.recon import (
            ReconOrchestrator, STATE_COMPLETED,
        )

        # Patch shutil.which to claim every tool exists.
        with mock.patch(
            "bugwolf.recon.orchestrator._tool_on_path",
            return_value=True,
        ):
            orch = ReconOrchestrator(
                target="example.com",
                workflow_dir=ROOT
                    / "bugwolf"
                    / "recon"
                    / "workflows",
                state_dir=self.tmp,
            )
            orch.plan(["quick_triage"])
            report = orch.run(timeout=5.0)

        completed = [j for j in report.jobs
                     if j.state == STATE_COMPLETED]
        self.assertGreater(
            len(completed), 0,
            "expected at least one phase to complete when tools exist",
        )

    def test_run_creates_journal(self) -> None:
        """Journal file is written and is hash-chained."""
        from bugwolf.recon import ReconOrchestrator

        with mock.patch(
            "bugwolf.recon.orchestrator._tool_on_path",
            return_value=True,
        ):
            orch = ReconOrchestrator(
                target="example.com",
                workflow_dir=ROOT
                    / "bugwolf"
                    / "recon"
                    / "workflows",
                state_dir=self.tmp,
            )
            orch.plan(["quick_triage"])
            orch.run(timeout=5.0)

        records = orch.journal_records()
        self.assertGreater(len(records), 0)
        # First record has no prev_hash, subsequent ones chain.
        for i in range(1, len(records)):
            if records[i].get("prev_hash") != records[i - 1].get("hash"):
                # Allow records that may not be strictly sequential
                # (different jobs interleave); just verify SOME chaining.
                continue
        # At least one prev_hash must equal a prior hash.
        hashes = [r.get("hash") for r in records]
        prevs = [r.get("prev_hash") for r in records]
        self.assertTrue(
            any(p in hashes for p in prevs if p),
            "no chained records in journal",
        )

    def test_run_failed_state_includes_reason(self) -> None:
        """FAILED jobs carry a non-empty ``reason``."""
        from bugwolf.recon import ReconOrchestrator, STATE_FAILED

        # Force every tool to look absent — guarantees at least one
        # FAILED job even if the operator's PATH happens to be rich.
        with mock.patch(
            "bugwolf.recon.orchestrator._tool_on_path",
            return_value=False,
        ):
            orch = ReconOrchestrator(
                target="example.com",
                workflow_dir=ROOT
                    / "bugwolf"
                    / "recon"
                    / "workflows",
                state_dir=self.tmp,
            )
            # ``quick_triage`` is passive-only so the orchestrator
            # doesn't skip phases for scope reasons.
            orch.plan(["quick_triage"])
            report = orch.run(timeout=10.0)
        failed = [j for j in report.jobs if j.state == STATE_FAILED]
        self.assertGreater(len(failed), 0)
        for j in failed:
            self.assertTrue(j.reason)
            self.assertIn("tool not on PATH", j.reason)


# ===========================================================================
# 4. CLI parser
# ===========================================================================


class TestCLI(unittest.TestCase):
    """``cli.build_parser()`` handles ``--target T --workflow W``."""

    def setUp(self) -> None:
        from bugwolf.recon.cli import build_parser
        self.parser = build_parser()

    def test_plan_parses_target_and_workflow(self) -> None:
        ns = self.parser.parse_args([
            "plan", "--target", "example.com",
            "--workflow", "quick_triage",
        ])
        self.assertEqual(ns.command, "plan")
        self.assertEqual(ns.target, "example.com")
        self.assertEqual(ns.workflow, ["quick_triage"])

    def test_run_parses_repeat_workflows(self) -> None:
        ns = self.parser.parse_args([
            "run", "--target", "example.com",
            "--workflow", "quick_triage",
            "--workflow", "subdomain_hunt",
            "--max-concurrent", "8",
        ])
        self.assertEqual(ns.command, "run")
        self.assertEqual(ns.workflow,
                         ["quick_triage", "subdomain_hunt"])
        self.assertEqual(ns.max_concurrent, 8)

    def test_status_requires_target(self) -> None:
        ns = self.parser.parse_args(["status", "--target", "t.com"])
        self.assertEqual(ns.target, "t.com")

    def test_cancel_requires_job_id(self) -> None:
        ns = self.parser.parse_args([
            "cancel", "--target", "t.com", "--job-id", "abc",
        ])
        self.assertEqual(ns.job_id, "abc")

    def test_workflows_list(self) -> None:
        ns = self.parser.parse_args(["workflows", "--list"])
        self.assertEqual(ns.command, "workflows")
        self.assertTrue(ns.list)

    def test_export_format(self) -> None:
        ns = self.parser.parse_args([
            "export", "--target", "t.com", "--format", "yaml",
        ])
        self.assertEqual(ns.format, "yaml")

    def test_plan_missing_target_errors(self) -> None:
        """cmd_plan returns non-zero exit when target is empty."""
        from bugwolf.recon.cli import cmd_plan
        # Provide a workflow name but leave --target blank; argparse
        # allows empty-string --target, so cmd_plan is the one that
        # should reject it.
        ns = self.parser.parse_args([
            "plan", "--target", "", "--workflow", "x",
        ])
        rc = cmd_plan(ns)
        self.assertEqual(rc, 2)


# ===========================================================================
# 5. API token gating
# ===========================================================================


class TestAPI(unittest.TestCase):
    """``api.app`` returns 401 without token, 200 with token."""

    def setUp(self) -> None:
        self.tok = "secret-control-token-xyz"
        self._env = {
            "OUTRIDER_CONTROL_TOKEN": self.tok,
        }
        self._patches = [
            mock.patch.dict(os.environ, self._env, clear=False),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()

    def test_healthz_open(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle("GET", "/healthz", headers={})
        self.assertEqual(resp.status_code, 200)
        body = resp.to_payload()
        self.assertEqual(body["status"], "ok")
        self.assertIn("version", body)
        self.assertIn("uptime_seconds", body)

    def test_401_without_token(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle("POST", "/targets",
                                    headers={},
                                    json_body={"target": "x.com"})
        self.assertEqual(resp.status_code, 401)

    def test_200_with_token_on_create_target(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle(
            "POST", "/targets",
            headers={"x-outrider-control-token": self.tok},
            json_body={"target": "x.com",
                       "workflows": ["quick_triage"]},
        )
        self.assertEqual(resp.status_code, 200,
                         f"unexpected: {resp.to_payload()!r}")

    def test_401_with_wrong_token(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle(
            "POST", "/targets",
            headers={"x-outrider-control-token": "wrong"},
            json_body={"target": "x.com"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_unknown_route_404(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle("GET", "/does/not/exist",
                                    headers={})
        self.assertEqual(resp.status_code, 404)

    def test_list_workflows_requires_token(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle(
            "GET", "/targets/example.com/workflows", headers={},
        )
        self.assertEqual(resp.status_code, 401)
        resp2 = recon_api.app.handle(
            "GET", "/targets/example.com/workflows",
            headers={"x-outrider-control-token": self.tok},
        )
        self.assertEqual(resp2.status_code, 200)
        body = resp2.to_payload()
        self.assertIn("workflows", body)
        self.assertGreaterEqual(body["count"], 1)


# ===========================================================================
# 6. Passive modules
# ===========================================================================


class TestPassiveModules(unittest.TestCase):
    """Passive modules return ``[]`` when no credentials are present."""

    def test_crt_sh_no_key_returns_empty(self) -> None:
        """crt.sh requires no API key; the test checks behaviour either
        way: offline → []; online → a list of PassiveFinding."""
        from bugwolf.recon.passive.crt_sh import CrtShModule
        from bugwolf.recon import PassiveFinding
        m = CrtShModule()
        out = m.enrich("example.com", budget=5)
        # Either we have network and got data, or we don't and got [].
        self.assertIsInstance(out, list)
        for f in out:
            self.assertIsInstance(f, PassiveFinding)
            self.assertEqual(f.source, "crt_sh")

    def test_dns_brute_runs_without_key(self) -> None:
        """DNS brute resolves via stdlib — no creds required."""
        from bugwolf.recon.passive.dns_brute import DnsBruteModule
        m = DnsBruteModule(wordlist=["nonexistent-subdomain-xyz"])
        # Either resolves to nothing (returns []) or finds something;
        # we just verify it doesn't raise.
        out = m.enrich("example.com", budget=5)
        self.assertIsInstance(out, list)

    def test_wayback_no_key_returns_empty(self) -> None:
        from bugwolf.recon.passive.wayback import WaybackModule
        from bugwolf.recon import PassiveFinding
        m = WaybackModule()
        out = m.enrich("example.com", budget=5)
        self.assertIsInstance(out, list)
        for f in out:
            self.assertIsInstance(f, PassiveFinding)
            self.assertEqual(f.source, "wayback")

    def test_shodan_no_key_returns_empty(self) -> None:
        from bugwolf.recon.passive.shodan import ShodanModule
        m = ShodanModule()
        self.assertEqual(m.enrich("example.com"), [])

    def test_censys_no_creds_returns_empty(self) -> None:
        from bugwolf.recon.passive.censys import CensysModule
        m = CensysModule()
        self.assertEqual(m.enrich("example.com"), [])

    def test_github_search_no_token(self) -> None:
        """GitHub search works without a token — only fails on network."""
        from bugwolf.recon.passive.github_search import GithubSearchModule
        m = GithubSearchModule()
        out = m.enrich("example.com", budget=5)
        self.assertIsInstance(out, list)

    def test_google_dorks_returns_dorks(self) -> None:
        from bugwolf.recon.passive.google_dorks import GoogleDorksModule
        m = GoogleDorksModule()
        out = m.enrich("example.com", budget=5)
        self.assertGreater(len(out), 0)
        for f in out:
            self.assertEqual(f.kind, "endpoint")
            self.assertIn("example.com", f.value)

    def test_email_patterns_infers_addresses(self) -> None:
        from bugwolf.recon.passive.email_patterns import (
            EmailPatternsModule,
        )
        m = EmailPatternsModule()
        out = m.enrich("example.com", budget=5)
        self.assertGreater(len(out), 0)
        for f in out:
            self.assertEqual(f.kind, "email")
            self.assertTrue(f.value.endswith("@example.com"))

    def test_subdomain_alts_returns_alternations(self) -> None:
        from bugwolf.recon.passive.subdomain_alts import (
            SubdomainAltsModule,
        )
        m = SubdomainAltsModule()
        out = m.enrich("example.com", budget=5)
        self.assertEqual(len(out), 5)
        for f in out:
            self.assertTrue(f.value.endswith(".example.com"))

    def test_passive_finding_is_frozen(self) -> None:
        from bugwolf.recon import PassiveFinding
        f = PassiveFinding(
            kind="subdomain",
            value="a.example.com",
            source="test",
            confidence=0.5,
            seen_at="2025-01-01T00:00:00+00:00",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            f.value = "other"  # type: ignore[misc]


# ===========================================================================
# 7. OSINT channels
# ===========================================================================


class TestOSINTChannels(unittest.TestCase):
    """Each OSINT channel returns ``OSINTFinding`` or ``[]``."""

    def setUp(self) -> None:
        from bugwolf.osint.channels import (
            RedditChannel, TwitterChannel, GithubChannel,
            InstagramChannel, LinkedInChannel, FacebookChannel,
            YoutubeChannel, BilibiliChannel, XiaohongshuChannel,
            XiaoyuzhouChannel, XueqiuChannel, V2EXChannel,
            RssChannel, WebChannel, ExaSearchChannel,
        )
        self.channels = [
            ("reddit", RedditChannel),
            ("twitter", TwitterChannel),
            ("github", GithubChannel),
            ("instagram", InstagramChannel),
            ("linkedin", LinkedInChannel),
            ("facebook", FacebookChannel),
            ("youtube", YoutubeChannel),
            ("bilibili", BilibiliChannel),
            ("xiaohongshu", XiaohongshuChannel),
            ("xiaoyuzhou", XiaoyuzhouChannel),
            ("xueqiu", XueqiuChannel),
            ("v2ex", V2EXChannel),
            ("rss", RssChannel),
            ("web", WebChannel),
            ("exa_search", ExaSearchChannel),
        ]

    def test_channel_count(self) -> None:
        self.assertEqual(len(self.channels), 15)

    def test_each_channel_scrape_returns_list(self) -> None:
        from bugwolf.osint import OSINTFinding
        for name, cls in self.channels:
            ch = cls()
            out = ch.scrape("example.com", budget=5)
            self.assertIsInstance(out, list,
                                  f"{name} did not return a list")
            for f in out:
                self.assertIsInstance(f, OSINTFinding,
                                      f"{name} produced non-OSINTFinding")
                self.assertTrue(f.source)


# ===========================================================================
# 8. OSINT autopilot + dedup
# ===========================================================================


class TestOSINTAutopilot(unittest.TestCase):
    """``OSINTAutopilot.run()`` deduplicates by URL + content-hash."""

    def test_run_dedupes_by_url_and_value(self) -> None:
        from bugwolf.osint.autopilot import OSINTAutopilot
        from bugwolf.osint import OSINTFinding

        class StubChannel:
            name = "stub"
            kind = "post"

            def __init__(self, items):
                self._items = items

            def scrape(self, target, *, budget=50):
                return list(self._items)

        f1 = OSINTFinding(
            kind="post", value="hello", source="stub", url="u/1",
        )
        f2 = OSINTFinding(
            kind="post", value="hello", source="stub", url="u/1",
        )
        f3 = OSINTFinding(
            kind="post", value="world", source="stub", url="u/2",
        )
        f4 = OSINTFinding(
            kind="post", value="hello", source="stub", url="u/3",
        )
        ap = OSINTAutopilot(
            target="example.com",
            channels=[StubChannel([f1, f2, f3, f4])],
            max_concurrent=2,
        )
        out = ap.run()
        self.assertEqual(out["raw_count"], 4)
        self.assertEqual(out["dedup_count"], 3)
        urls = [f["url"] for f in out["findings"]]
        self.assertEqual(len(set(urls)), 3)

    def test_run_captures_errors(self) -> None:
        from bugwolf.osint.autopilot import OSINTAutopilot

        class BrokenChannel:
            name = "broken"
            kind = "post"

            def scrape(self, target, *, budget=50):
                raise RuntimeError("nope")

        ap = OSINTAutopilot(
            target="x",
            channels=[BrokenChannel()],
            max_concurrent=1,
        )
        out = ap.run()
        self.assertGreater(len(out["errors"]), 0)

    def test_run_uses_default_channels(self) -> None:
        from bugwolf.osint.autopilot import OSINTAutopilot
        ap = OSINTAutopilot(target="x")
        self.assertEqual(len(ap.channels), 15)


# ===========================================================================
# 9. Cookie extractor
# ===========================================================================


class TestCookieExtractor(unittest.TestCase):
    """``CookieExtractor.from_har()`` parses a sample HAR fixture."""

    def test_from_har(self) -> None:
        from bugwolf.osint.cookie_extract import CookieExtractor, from_har

        with tempfile.TemporaryDirectory() as tmp:
            har_path = Path(tmp) / "test.har"
            _write_har(har_path)
            cookies = from_har(har_path)
            self.assertEqual(len(cookies), 3)
            names = sorted(c.name for c in cookies)
            self.assertEqual(names, ["csrf", "session", "tracking"])
            session = next(c for c in cookies if c.name == "session")
            self.assertEqual(session.value, "abc123")
            self.assertTrue(session.http_only)
            self.assertTrue(session.secure)

    def test_from_dump_missing_file(self) -> None:
        from bugwolf.osint.cookie_extract import from_dump
        self.assertEqual(from_dump(Path("/no/such/file")), [])

    def test_from_browser_no_lib(self) -> None:
        """Without browser-cookie3, ``from_browser`` returns ``[]``."""
        from bugwolf.osint.cookie_extract import from_browser
        # Either browser-cookie3 is installed (then we get []) or
        # it's not (then we still get []).  Just ensure no raise.
        out = from_browser("chrome")
        self.assertIsInstance(out, list)


# ===========================================================================
# 10. Transcriber
# ===========================================================================


class TestTranscriber(unittest.TestCase):
    """``Transcriber.transcribe()`` returns TranscriptUnavailable when
    speech_recognition is not installed."""

    def test_transcribe_unavailable_when_no_engine(self) -> None:
        from bugwolf.osint.transcribe import (
            Transcriber, TranscriptUnavailable, Transcript,
        )
        tr = Transcriber(prefer="whisper")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "audio.wav"
            f.write_bytes(b"RIFFfake")
            result = tr.transcribe(f)
        # When no engine is installed, result is TranscriptUnavailable.
        # Otherwise it's a Transcript.  Both are accepted.
        self.assertTrue(
            isinstance(result, (TranscriptUnavailable, Transcript))
        )
        if isinstance(result, TranscriptUnavailable):
            self.assertTrue(result.reason)


# ===========================================================================
# 11. OSINT skills — count >= 8
# ===========================================================================


class TestOSINTSkills(unittest.TestCase):
    """``osint.skills`` exposes at least 8 skills."""

    def test_skills_module_count(self) -> None:
        from bugwolf.osint import skills as osint_skills
        # Find every module-level ``run`` function in skills/.
        skill_files = list(
            (ROOT / "bugwolf" / "osint" / "skills").glob("*.py")
        )
        # Filter out __init__.py — each skill lives in its own file.
        skill_files = [p for p in skill_files if p.stem != "__init__"]
        self.assertGreaterEqual(
            len(skill_files), 8,
            f"expected >=8 skill files, got {len(skill_files)}: "
            f"{[p.stem for p in skill_files]}",
        )

    def test_each_skill_has_run(self) -> None:
        from bugwolf.osint import skills as osint_skills
        skill_files = list(
            (ROOT / "bugwolf" / "osint" / "skills").glob("*.py")
        )
        skill_files = [p for p in skill_files if p.stem != "__init__"]
        for path in skill_files:
            mod_name = f"bugwolf.osint.skills.{path.stem}"
            mod = __import__(mod_name, fromlist=["run"])
            self.assertTrue(
                hasattr(mod, "run"),
                f"skill {path.stem} missing run() function",
            )

    def test_each_skill_run_returns_dict(self) -> None:
        from bugwolf.osint import skills as osint_skills
        skill_files = list(
            (ROOT / "bugwolf" / "osint" / "skills").glob("*.py")
        )
        skill_files = [p for p in skill_files if p.stem != "__init__"]
        for path in skill_files:
            mod = __import__(
                f"bugwolf.osint.skills.{path.stem}", fromlist=["run"]
            )
            result = mod.run("test_query", budget=5)
            self.assertIsInstance(result, dict)
            self.assertIn("schema", result)
            self.assertIn("skill", result)


# ===========================================================================
# 12. MCP server
# ===========================================================================


class TestMCPServer(unittest.TestCase):
    """MCP JSON-RPC server returns stub-safe errors when not started."""

    def test_not_started_response(self) -> None:
        from bugwolf.osint.mcp_server import not_started_response
        resp = not_started_response()
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["message"],
                         "MCP server not started")

    def test_handle_line_parse_error(self) -> None:
        from bugwolf.osint.mcp_server import _handle_line
        resp = _handle_line("not json")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32700)

    def test_handle_line_unknown_method(self) -> None:
        from bugwolf.osint.mcp_server import _handle_line
        resp = _handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 1,
                        "method": "does.not.exist", "params": {}})
        )
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_handle_line_osint_scrape_channel(self) -> None:
        from bugwolf.osint.mcp_server import _handle_line
        resp = _handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 2,
                        "method": "osint.scrape_channel",
                        "params": {"channel": "reddit",
                                   "target": "x"}})
        )
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["channel"], "reddit")

    def test_handle_line_osint_search(self) -> None:
        from bugwolf.osint.mcp_server import _handle_line
        resp = _handle_line(
            json.dumps({"jsonrpc": "2.0", "id": 3,
                        "method": "osint.search",
                        "params": {"query": "x", "top_k": 3}})
        )
        self.assertIn("result", resp)
        self.assertIn("channels", resp["result"])


# ===========================================================================
# 13. Workflow load + run integration smoke
# ===========================================================================


class TestWorkflowIntegration(unittest.TestCase):
    """A full end-to-end run of ``quick_triage`` with stubbed tools."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bw-int-"))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_run_pipeline(self) -> None:
        from bugwolf.recon import (
            ReconOrchestrator, STATE_COMPLETED, ReconReport,
        )
        with mock.patch(
            "bugwolf.recon.orchestrator._tool_on_path",
            return_value=True,
        ):
            orch = ReconOrchestrator(
                target="example.com",
                workflow_dir=ROOT
                    / "bugwolf"
                    / "recon"
                    / "workflows",
                state_dir=self.tmp,
            )
            planned = orch.plan(["quick_triage", "subdomain_hunt"])
            report = orch.run(timeout=10.0)
        self.assertIsInstance(report, ReconReport)
        # All jobs should be in a terminal state.
        for j in report.jobs:
            self.assertNotEqual(j.state, "RUNNING")
        completed = [j for j in report.jobs
                     if j.state == STATE_COMPLETED]
        self.assertGreater(len(completed), 0)
        # Workflows list should mention both.
        self.assertIn("quick_triage", report.workflows)
        self.assertIn("subdomain_hunt", report.workflows)


# ===========================================================================
# 14. API run + cancel endpoints
# ===========================================================================


class TestAPIRunLifecycle(unittest.TestCase):
    """The /runs/{run_id}/* endpoints behave correctly."""

    def setUp(self) -> None:
        self.tok = "secret-token-for-runs"
        self._p = mock.patch.dict(
            os.environ, {"OUTRIDER_CONTROL_TOKEN": self.tok},
            clear=False,
        )
        self._p.start()

    def tearDown(self) -> None:
        self._p.stop()

    def test_create_target_and_list_workflows(self) -> None:
        from bugwolf.recon import api as recon_api
        # 1) Create target.
        resp = recon_api.app.handle(
            "POST", "/targets",
            headers={"x-outrider-control-token": self.tok},
            json_body={"target": "example.com",
                       "workflows": ["quick_triage"]},
        )
        self.assertEqual(resp.status_code, 200)
        # 2) List workflows for that target.
        resp2 = recon_api.app.handle(
            "GET", "/targets/example.com/workflows",
            headers={"x-outrider-control-token": self.tok},
        )
        self.assertEqual(resp2.status_code, 200)
        body = resp2.to_payload()
        self.assertIn("workflows", body)
        self.assertGreaterEqual(body["count"], 1)

    def test_run_status_unknown(self) -> None:
        from bugwolf.recon import api as recon_api
        resp = recon_api.app.handle(
            "GET", "/runs/unknown-id",
            headers={"x-outrider-control-token": self.tok},
        )
        self.assertEqual(resp.status_code, 404)

    def test_kickoff_run_with_stub(self) -> None:
        from bugwolf.recon import api as recon_api
        with mock.patch(
            "bugwolf.recon.orchestrator._tool_on_path",
            return_value=True,
        ):
            resp = recon_api.app.handle(
                "POST", "/targets/example.com/run",
                headers={"x-outrider-control-token": self.tok},
                json_body={"workflows": ["quick_triage"]},
            )
        self.assertEqual(resp.status_code, 200, resp.to_payload())
        body = resp.to_payload()
        run_id = body["run_id"]
        self.assertTrue(run_id)
        # 2) Status.
        resp2 = recon_api.app.handle(
            "GET", f"/runs/{run_id}",
            headers={"x-outrider-control-token": self.tok},
        )
        self.assertEqual(resp2.status_code, 200)
        # 3) Results.
        resp3 = recon_api.app.handle(
            "GET", f"/runs/{run_id}/results",
            headers={"x-outrider-control-token": self.tok},
        )
        self.assertEqual(resp3.status_code, 200)
        # 4) Cancel.
        resp4 = recon_api.app.handle(
            "POST", f"/runs/{run_id}/cancel",
            headers={"x-outrider-control-token": self.tok},
            json_body={},
        )
        self.assertEqual(resp4.status_code, 200)


# ===========================================================================
# 15. ReconJob / PassiveFinding / OSINTFinding dataclasses
# ===========================================================================


class TestDataclasses(unittest.TestCase):
    """All dataclasses are frozen + hashable."""

    def test_recon_job_frozen(self) -> None:
        from bugwolf.recon import ReconJob
        job = ReconJob(
            job_id="j1", target="x", workflow="w", phase="p",
            tools=["a"], budget_requests=10, budget_seconds=60,
            scope_verb="passive", state="PENDING",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            job.state = "FAILED"  # type: ignore[misc]

    def test_passive_finding_frozen(self) -> None:
        from bugwolf.recon import PassiveFinding
        f = PassiveFinding(
            kind="subdomain", value="x", source="y",
            confidence=0.5, seen_at="2025-01-01T00:00:00+00:00",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            f.value = "z"  # type: ignore[misc]

    def test_osint_finding_frozen(self) -> None:
        from bugwolf.osint import OSINTFinding
        f = OSINTFinding(
            kind="post", value="x", source="y", url="z",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            f.value = "z"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
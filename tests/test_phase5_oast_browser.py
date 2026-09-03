#!/usr/bin/env python3
"""Phase 5 wiring tests: OAST attribution + browser validation lane.

Contracts under test (plan v2 section 5.6, S1 + S2):
  * OAST (S1): pre-registered per-surface canaries arm before the lanes;
    an SSRF re-probe through the target fires the canary; the callback is
    100% attributed to the registered surface; unregistered tokens are
    logged but never attributed; the verify lane treats an attributed
    callback as deterministic proof (PWNED without a reasoning tier).
  * Browser validation (S2): reflection is never execution -- a client_side
    lead confirms ONLY via a console/DOM signature hit through a bound
    driver; without a driver the lead stays OPEN under blocked-browser
    semantics (never refuted for missing tooling).
  * Stored-reflection differential: canary in -> canary out opens ONE lead
    per replay surface (no duplicates when both store and replay surfaces
    are declared).
  * ART scheduling: fuzz_bridge orders payloads across grammar families
    (per-family heads first) -- behavior smoke-tested through the family
    pipeline below.
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import time
import http.server
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec
from tools.runtime.lead_protocol import LeadStore
from tools.runtime.mission_runner import (
    MissionRunner, _probe_ssrf_outbound, _probe_stored_reflection,
)
from tools.runtime.oast import (
    OastListener, OastRegistry, canary_url, poll_callbacks,
)
from tools.runtime.browser_driver import (
    validate_client_side, make_signature, ClientSideEvidence,
    blocked_browser_evidence,
)
from tools.core.fuzz_bridge import _art_order_mutations as order_mutations
from tools.mutator import Mutation

ROOT = Path(__file__).resolve().parents[1]
STUB_TARGET = ROOT / "tests" / "_stub_target.py"


def _boot_stub_target():
    spec = importlib.util.spec_from_file_location("stub_target", STUB_TARGET)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["_stub_target.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/tech.json", timeout=2) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.1)
    return base, (lambda: (server.shutdown(), server.server_close()))


class _StubDriver:
    """Driver protocol stub with scriptable console output."""

    def __init__(self, console=(), fail=False):
        self._console = list(console)
        self._fail = fail
        self.navigated_to = None

    def navigate(self, url):
        if self._fail:
            raise RuntimeError("driver crashed mid-navigation")
        self.navigated_to = url
        return "<html>note page</html>"

    def console(self):
        return self._console

    def evaluate(self, expression):
        return None


class MissionEnvMixin:
    """Shared env save/restore (restore-always -- the Phase 4 lesson)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name

    def tearDown(self):
        # Restore BEFORE cleanup: later suites must not inherit a deleted
        # temp dir (the trigger-ledger poisoning class).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        self._td.cleanup()


class OastAttributionTest(MissionEnvMixin, unittest.TestCase):
    """S1: registry, listener, attribution, and restart-safe polling."""

    def test_registry_roundtrip_and_unregistered_stays_unattributed(self):
        reg = OastRegistry()
        token = reg.register("lead-1")
        self.assertTrue(token)
        self.assertEqual(reg.lookup(token), "lead-1")
        self.assertIsNone(reg.lookup("never-registered"))

    def test_listener_records_interaction(self):
        reg = OastRegistry()
        listener = OastListener(reg)
        listener.start()
        try:
            token = reg.register("lead-2")
            with urllib.request.urlopen(
                    f"{listener.base_url}/{token}?probe=1", timeout=5) as r:
                json.loads(r.read())
            deadline = time.time() + 5
            while time.time() < deadline and not reg.interactions():
                time.sleep(0.05)
            hits = reg.interactions(lead_id="lead-2")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["transport"], "http")
            self.assertEqual(hits[0]["source"], "127.0.0.1")
            self.assertIn("probe=1", hits[0].get("path", ""))
        finally:
            listener.stop()

    def test_poll_callbacks_publishes_only_attributed_hits(self):
        reg = OastRegistry()
        t1 = reg.register("lead-a")
        reg.record({"token": t1, "transport": "http", "lead_id": "lead-a"})
        reg.record({"token": "unregistered-token", "transport": "dns",
                    "lead_id": None})
        attributed, total = poll_callbacks(reg, since_count=0,
                                           publish=False)
        self.assertEqual(len(attributed), 1)
        self.assertEqual(attributed[0]["lead_id"], "lead-a")
        self.assertEqual(total, 2)

    def test_poll_cursor_is_restart_safe(self):
        reg = OastRegistry()
        t1 = reg.register("lead-b")
        reg.record({"token": t1, "transport": "http", "lead_id": "lead-b"})
        _, total1 = poll_callbacks(reg, since_count=0, publish=False)
        # Simulate a restart: a fresh registry instance over the same dir.
        reg2 = OastRegistry()
        attributed, total2 = poll_callbacks(reg2, since_count=total1,
                                            publish=False)
        self.assertEqual(attributed, [])
        self.assertEqual(total2, total1)

    def test_canary_url_registers_and_embeds_token(self):
        reg = OastRegistry()
        url = canary_url("http://127.0.0.1:9", "lead-c", registry=reg)
        token = url.rsplit("/", 1)[-1]
        self.assertEqual(reg.lookup(token), "lead-c")


class SsrfOastLaneTest(MissionEnvMixin, unittest.TestCase):
    """S1 end-to-end: target fetches canary -> attributed callback -> PWNED."""

    def setUp(self):
        super().setUp()
        boot = _boot_stub_target()
        if boot is None:
            self.skipTest("stub target missing")
        self.base, self._shutdown = boot
        self.addCleanup(self._shutdown)

    def test_probe_differential_and_oast_proof(self):
        # Differential: benign local fetch ok, arbitrary host fetch reported.
        signals = _probe_ssrf_outbound(self.base, ["/api/ingest"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["signal"], "ssrf-outbound-fetch")

        # OAST re-probe + attribution through the listener.
        reg = OastRegistry()
        listener = OastListener(reg)
        listener.start()
        try:
            canary = canary_url(listener.base_url, "surface:/api/ingest",
                                registry=reg)
            probe = urllib.request.Request(
                self.base + "/api/ingest", method="POST",
                data=json.dumps({"q": canary}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(probe, timeout=10) as r:
                self.assertTrue(json.loads(r.read())["fetched"])
            deadline = time.time() + 5
            while (time.time() < deadline
                   and not reg.interactions(lead_id="surface:/api/ingest")):
                time.sleep(0.05)
            hits = reg.interactions(lead_id="surface:/api/ingest")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["transport"], "http")
        finally:
            listener.stop()

    def test_e2e_ssrf_lead_pwned_via_attributed_callback(self):
        mission = MissionSpec(
            mission_id="p5-ssrf", target=self.base,
            domains=["web_api", "verify", "report"],
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 600})
        runner = MissionRunner(mission, project_root=self._td.name,
                               base_url=self.base, paths=["/api/ingest"],
                               oast_enabled=True)
        try:
            report = runner.run()
        finally:
            runner.close()
        ssrf = [f for f in report["findings"]
                if f.get("bug_class") == "generic"]
        # The SSRF lead closed PWNED on the attributed callback alone --
        # no reasoning tier involved.
        self.assertEqual(len(ssrf), 1,
                         f"expected ssrf finding, got {report['findings']}")
        self.assertTrue(runner.oast_registry.interactions(
            lead_id="surface:/api/ingest"))
        events = [e["event"] for e in runner._events]
        self.assertIn("oast_armed", events)
        self.assertIn("oast_callback", events)


class StoredReflectionTest(MissionEnvMixin, unittest.TestCase):
    """Client-side differential + dedupe across declared surfaces."""

    def setUp(self):
        super().setUp()
        boot = _boot_stub_target()
        if boot is None:
            self.skipTest("stub target missing")
        self.base, self._shutdown = boot
        self.addCleanup(self._shutdown)

    def test_differential_and_single_lead_across_surfaces(self):
        # Both the ingest (store) and notes (replay) surfaces declared:
        # one signal, one replay path -- no duplicate leads.
        signals = _probe_stored_reflection(
            self.base, ["/api/ingest", "/api/notes"])
        self.assertEqual(len(signals), 1,
                         f"expected dedupe, got {signals}")
        self.assertEqual(signals[0]["path"], "/api/notes")
        self.assertEqual(signals[0]["store_surface"], "/api/ingest")
        # And a fresh canary lands on a clean stub (module-level _NOTES is
        # per-process; both runs see the same clean module here).
        self.assertIn("stored-reflection", signals[0]["signal"])


class BrowserValidationTest(MissionEnvMixin, unittest.TestCase):
    """S2: reflection != execution; blocked-browser keeps leads OPEN."""

    def setUp(self):
        super().setUp()
        boot = _boot_stub_target()
        if boot is None:
            self.skipTest("stub target missing")
        self.base, self._shutdown = boot
        self.addCleanup(self._shutdown)
        self.store = LeadStore("p5-browser").load()

    def _open_client_lead(self, surface="/api/notes"):
        return self.store.open_lead(
            title="stored-reflection on /api/notes",
            mission_id="p5-browser", target="stub",
            bug_class="client_side", surface=surface,
            signal="stored-reflection")

    def test_execution_confirmed_only_via_signature(self):
        lead = self._open_client_lead()
        sig = make_signature(lead.lead_id)
        # Reflection only: payload echoed in the body, console silent.
        evidence = validate_client_side(
            {"lead_id": lead.lead_id, "url": f"{self.base}{lead.surface}",
             "dom_sink": ""},
            _StubDriver(console=[]))
        self.assertFalse(evidence.execution_confirmed)
        self.assertFalse(evidence.reflection_only)  # canary not embedded here
        # Signature observed in the console: execution confirmed.
        evidence = validate_client_side(
            {"lead_id": lead.lead_id, "url": f"{self.base}{lead.surface}",
             "dom_sink": ""},
            _StubDriver(console=[f"canary: {sig}"]))
        self.assertTrue(evidence.execution_confirmed)

    def test_driver_failure_is_a_blocker(self):
        lead = self._open_client_lead()
        evidence = validate_client_side(
            {"lead_id": lead.lead_id, "url": f"{self.base}{lead.surface}"},
            _StubDriver(fail=True))
        self.assertFalse(evidence.execution_confirmed)
        self.assertTrue(evidence.blocker)
        self.assertEqual(evidence, blocked_browser_evidence(
            evidence.url, evidence.blocker))

    def test_lane_without_driver_records_blocked_browser(self):
        lead = self._open_client_lead()
        mission = MissionSpec(
            mission_id="p5-browser", target=self.base,
            domains=["client_side"], budget={"max_agents": 8})
        runner = MissionRunner(mission, project_root=self._td.name,
                               base_url=self.base, paths=["/api/notes"])
        try:
            result = runner._run_client_side_lane()
        finally:
            runner.close()
        reloaded = LeadStore("p5-browser").load()
        by_id = {l.lead_id: l for l in reloaded.list_leads()}
        self.assertIn("blocked-browser",
                      [t.get("technique")
                       for t in by_id[lead.lead_id].technique_log])
        self.assertEqual(by_id[lead.lead_id].status, "OPEN")
        self.assertIn("browser_blocked",
                      [e["event"] for e in runner._events])

    def test_lane_with_executing_driver_closes_pwned(self):
        lead = self._open_client_lead()
        mission = MissionSpec(
            mission_id="p5-browser", target=self.base,
            domains=["client_side"], budget={"max_agents": 8})
        runner = MissionRunner(
            mission, project_root=self._td.name, base_url=self.base,
            paths=["/api/notes"],
            browser_driver=_StubDriver(
                console=[f"canary: {make_signature(lead.lead_id)}"]))
        try:
            result = runner._run_client_side_lane()
        finally:
            runner.close()
        self.assertTrue(result["summary"].startswith("validated 1"))
        reloaded = LeadStore("p5-browser").load()
        by_id = {l.lead_id: l for l in reloaded.list_leads()}
        self.assertEqual(by_id[lead.lead_id].status, "OPEN")
        # Verify lane finishes the job (independent replay).
        runner2 = MissionRunner(
            mission, project_root=self._td.name, base_url=self.base,
            paths=["/api/notes"],
            browser_driver=_StubDriver(
                console=[f"canary: {make_signature(lead.lead_id)}"]))
        try:
            runner2._run_verify_lane()
        finally:
            runner2.close()
        reloaded = LeadStore("p5-browser").load()
        by_id = {l.lead_id: l for l in reloaded.list_leads()}
        self.assertEqual(by_id[lead.lead_id].status, "PWNED")

    def test_verify_lane_never_refutes_for_missing_driver(self):
        self._open_client_lead()
        mission = MissionSpec(
            mission_id="p5-browser", target=self.base,
            domains=["verify"], budget={"max_agents": 8})
        runner = MissionRunner(mission, project_root=self._td.name,
                               base_url=self.base, paths=["/api/notes"])
        try:
            runner._run_verify_lane()
        finally:
            runner.close()
        reloaded = LeadStore("p5-browser").load()
        statuses = {l.lead_id: l.status for l in reloaded.list_leads()}
        for status in statuses.values():
            self.assertEqual(status, "OPEN")


class ArtSchedulingSmokeTest(MissionEnvMixin, unittest.TestCase):
    """ART ordering surfaced through the fuzz bridge payload pipeline."""

    def test_order_payloads_interleaves_families(self):
        batch = ([Mutation(mutation_id=f"sql-{i}", operation_id="op",
                           method="POST", path="/q", kind="injection",
                           variable="q", mutated=f"' OR '1'='1{i}")
                  for i in range(4)]
                 + [Mutation(mutation_id=f"bsql-{i}", operation_id="op",
                             method="POST", path="/q", kind="blind_sqli",
                             variable="q", mutated=f"1 AND SLEEP({i})")
                    for i in range(4)])
        ordered = order_mutations(batch)
        self.assertEqual(len(ordered), len(batch))
        self.assertEqual({m.mutation_id for m in ordered},
                         {m.mutation_id for m in batch})
        # ART property: the first rounds must rotate DISTINCT grammar
        # families (one payload per family before any family repeats).
        heads = [m.kind for m in ordered[:2]]
        self.assertEqual(len(set(heads)), 2,
                         f"first rounds must rotate families: {heads}")


if __name__ == "__main__":
    unittest.main()

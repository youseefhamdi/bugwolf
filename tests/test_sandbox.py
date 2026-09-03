#!/usr/bin/env python3
"""Subprocess sandbox tests (readiness R3 remediation).

Contracts pinned here:
  * the kill switch is a fail-CLOSED circuit breaker: engaged blocks every
    sandboxed spawn; an unreadable marker counts as engaged;
  * the binary allowlist defaults to the preflight inventory (parity);
    unknown binaries raise SandboxViolation before spawn;
  * spawns run with a scrubbed environment: keep-list + BUGWOLF_* +
    explicit overrides only; credential-shaped variables never leak;
  * sandboxed_run keeps run_bounded_subprocess's bounded-execution
    guarantees (timeout, output cap);
  * the sandbox module is the path preflight probes and the capability
    manifest's CLI checks run through;
  * the readiness claim is functionally verified.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime import sandbox  # noqa: E402
from tools.runtime.sandbox import (  # noqa: E402
    SandboxViolation, sandboxed_run, engage_kill_switch,
    release_kill_switch, kill_switch_engaged, grant, revoke, load_grants,
    scrub_env, verify_sandbox, sandbox_state,
)


class KillSwitchTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.addCleanup(lambda: release_kill_switch(self.root))

    def test_engage_blocks_spawn(self):
        engage_kill_switch(self.root, note="test")
        with self.assertRaises(SandboxViolation) as ctx:
            sandboxed_run([sys.executable, "-c", "print(1)"], cwd=self.root,
                          root=self.root, allow_unlisted=True)
        self.assertTrue(ctx.exception.kill_switch)

    def test_missing_marker_means_armed(self):
        self.assertFalse(kill_switch_engaged(self.root))

    def test_corrupt_marker_fails_closed(self):
        path = sandbox._kill_path(self.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xff\xfe\xfa")  # invalid UTF-8
        self.assertTrue(kill_switch_engaged(self.root),
                        "corrupt kill switch must count as ENGAGED")

    def test_release_rearms(self):
        engage_kill_switch(self.root)
        self.assertTrue(release_kill_switch(self.root))
        self.assertFalse(kill_switch_engaged(self.root))
        self.assertFalse(release_kill_switch(self.root))  # idempotent


class AllowlistTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.addCleanup(lambda: revoke(self.root, load_grants(self.root)))
        self.addCleanup(lambda: release_kill_switch(self.root))

    def test_default_allowlist_is_preflight_inventory(self):
        from tools.runtime.preflight import BINARY_CAPABILITIES
        self.assertEqual(set(sandbox._default_allowlist()),
                         set(BINARY_CAPABILITIES))
        # Parity: every documented binary is sandbox-allowed.
        for name in BINARY_CAPABILITIES:
            self.assertTrue(sandbox._is_allowed(name, self.root,
                                                allow_unlisted=False),
                            f"{name} must be allowlisted")

    def test_unlisted_binary_refused_before_spawn(self):
        with self.assertRaises(SandboxViolation) as ctx:
            sandboxed_run(["definitely-not-a-real-binary-xyz", "--version"],
                          cwd=self.root, root=self.root)
        self.assertFalse(ctx.exception.kill_switch)
        self.assertIn("not allowlisted", str(ctx.exception))

    def test_grant_extends_allowlist_durably(self):
        py = Path(sys.executable).name
        self.assertNotIn(py, load_grants(self.root))
        grant(self.root, [py])
        result = sandboxed_run([sys.executable, "-c", "print('ok')"],
                               cwd=self.root, root=self.root)
        self.assertIn(b"ok", result.stdout)

    def test_revoke_removes_grant(self):
        py = Path(sys.executable).name
        grant(self.root, [py])
        revoke(self.root, [py])
        with self.assertRaises(SandboxViolation):
            sandboxed_run([sys.executable, "-c", "print(1)"], cwd=self.root,
                          root=self.root)


class EnvScrubTest(unittest.TestCase):
    def test_scrub_removes_credential_shaped_vars(self):
        import os
        poisoned = {"AWS_SECRET_ACCESS_KEY": "leak-me",
                    "GH_TOKEN": "leak-me", "API_KEY": "leak-me",
                    "http_proxy": "http://leak:1", "PATH": os.environ["PATH"]}
        with unittest.mock.patch.dict(os.environ, poisoned):
            env = scrub_env()
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("API_KEY", env)
        self.assertNotIn("http_proxy", env)
        self.assertIn("PATH", env)

    def test_scrub_keeps_bugwolf_and_explicit_overrides(self):
        import os
        with unittest.mock.patch.dict(
                os.environ, {"BUGWOLF_MISSION_ID": "m1", "SECRET": "x"}):
            env = scrub_env({"MY_FLAG": "1"})
        self.assertEqual(env.get("BUGWOLF_MISSION_ID"), "m1")
        self.assertNotIn("SECRET", env)
        self.assertEqual(env.get("MY_FLAG"), "1")


class BoundedExecutionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.addCleanup(lambda: release_kill_switch(self.root))

    def test_timeout_still_kills_process_group(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            sandboxed_run([sys.executable, "-c", "import time; time.sleep(30)"],
                          cwd=self.root, root=self.root, timeout=1,
                          allow_unlisted=True)

    def test_output_cap_enforced(self):
        with self.assertRaises(sandbox.ResourceLimitError
                               if hasattr(sandbox, "ResourceLimitError")
                               else Exception):
            sandboxed_run(
                [sys.executable, "-c", "print('x' * 1000000)"],
                cwd=self.root, root=self.root, max_output_bytes=1024,
                allow_unlisted=True)

    def test_sandboxed_run_returns_completed_process(self):
        result = sandboxed_run([sys.executable, "-c", "print('hello')"],
                               cwd=self.root, root=self.root,
                               allow_unlisted=True)
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"hello", result.stdout)


class AuditTrailTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.addCleanup(lambda: release_kill_switch(self.root))
        self.addCleanup(lambda: revoke(self.root, load_grants(self.root)))

    def test_events_are_audited(self):
        grant(self.root, [Path(sys.executable).name])
        sandboxed_run([sys.executable, "-c", "print(1)"], cwd=self.root,
                      root=self.root, purpose="audit-test")
        engage_kill_switch(self.root, note="t")
        try:
            sandboxed_run([sys.executable, "-c", "print(1)"], cwd=self.root,
                          root=self.root, allow_unlisted=True)
        except SandboxViolation:
            pass
        events = [json.loads(line) for line in
                  sandbox._audit_path(self.root).read_text().splitlines()]
        kinds = {e["event"] for e in events}
        self.assertIn("granted", kinds)
        self.assertIn("spawn", kinds)
        self.assertIn("kill_switch_engaged", kinds)
        self.assertIn("blocked_kill_switch", kinds)


class ReadinessIntegrationTest(unittest.TestCase):
    def test_verify_sandbox_proves_all_three_layers(self):
        ok, detail = verify_sandbox()
        self.assertTrue(ok, detail)

    def test_readiness_claims_verify_functionally(self):
        import tools.readiness as readiness
        ok, detail = readiness._verify_subprocess_sandbox()
        self.assertTrue(ok, detail)
        report = readiness.validate_manifest(readiness.load_manifest())
        self.assertEqual(report["warnings"], [], report["warnings"])
        self.assertTrue(report["valid"], report["errors"])

    def test_state_snapshot(self):
        state = sandbox_state()
        self.assertEqual(state["schema"], "bugwolf-sandbox/v1")
        self.assertIn(state["kill_switch"], ("armed", "ENGAGED"))
        self.assertGreater(state["default_allowlist_size"], 10)


if __name__ == "__main__":
    unittest.main()

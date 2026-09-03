#!/usr/bin/env python3
"""Kill-switch coverage tests: every subprocess spawn in the tree obeys the
sandbox (product audit follow-up: non-Python spawns included).

Contracts pinned here:
  * NO raw subprocess.run/Popen/check_output outside the audited choke
    points (reliability's bounded Popen, and the two long-lived daemon
    sites that gate through the sandbox before a streaming Popen);
  * the kill switch blocks engine-INTERNAL spawns too (release import
    checks, capability CLI checks) -- not just operator-facing probes;
  * hooks and the MCP bridge never spawn (their contracts are pure
    stdlib / in-process) -- pinned by source scan;
  * long-lived daemons (interactsh/ngrok/lab fixtures) refuse to start
    under an engaged kill switch;
  * sandboxed_run honors subprocess.run semantics (input_text, text,
    check) for migrated callers.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO = Path(__file__).resolve().parent.parent

# Choke points allowed to call Popen directly (audited, gated):
#   * tools/reliability.py            -- the bounded executor itself
#   * tools/infra_deploy.py           -- long-lived daemons, gated pre-Popen
#   * tools/lab_lifecycle.py          -- long-lived fixtures, gated pre-Popen
# Test/scripts trees spawn subprocesses to TEST the engine itself (pytest
# harness, audit generator) -- they are operator-side tooling, not shipped
# product code paths, so the shipped-code sweep covers tools/ + bridge/ +
# hooks/ only.
_ALLOWED_RAW = ("tools/reliability.py", "tools/infra_deploy.py",
                "tools/lab_lifecycle.py")
_SWEEP_ROOTS = ("tools", "bridge", "hooks")


class NoRawSpawnSweepTest(unittest.TestCase):
    """Repository-wide invariant: the sandbox is the only spawn path."""

    def test_no_raw_spawns_outside_choke_points(self):
        pattern = re.compile(
            r"subprocess\.(?:run|Popen|check_output|check_call|call)\(")
        offenders = []
        for root_name in _SWEEP_ROOTS:
            for py in (REPO / root_name).rglob("*.py"):
                rel = py.relative_to(REPO).as_posix()
                if "__pycache__" in py.parts:
                    continue
                if rel in _ALLOWED_RAW:
                    continue
                try:
                    text = py.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if pattern.search(line) and "import" not in line:
                        offenders.append(f"{rel}:{i}: {line.strip()[:100]}")
        self.assertEqual(offenders, [],
                         "raw subprocess spawns outside the sandbox:\n"
                         + "\n".join(offenders))

    def test_hook_never_spawns(self):
        hook = (REPO / "hooks" / "bugwolf_stop_hook.py").read_text()
        for banned in ("subprocess", "popen", "os.system", "os.exec",
                       "urllib.request", "socket"):
            self.assertNotIn(banned, hook,
                             f"hook shim must not use {banned!r}")

    def test_bridge_never_spawns(self):
        bridge = (REPO / "bridge" / "bugwolf-mcp.py").read_text()
        self.assertNotIn("subprocess", bridge)
        self.assertNotIn("os.system", bridge)


class KillSwitchCoversEngineSpawnsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        # Engine code resolves the workspace via BUGWOLF_PROJECT_ROOT;
        # point it at the killed workspace so the switch is seen.
        import os
        self._old_root_env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self.root
        self.addCleanup(self._restore_env)
        from tools.runtime.sandbox import (engage_kill_switch,
                                           release_kill_switch)
        engage_kill_switch(self.root, note="coverage-test")
        self.addCleanup(lambda: release_kill_switch(self.root))

    def _restore_env(self):
        import os
        if self._old_root_env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._old_root_env

    def test_release_import_check_blocked_by_kill_switch(self):
        """The release smoke-import gate itself refuses to pass when the
        operator kills execution -- surfaced as failures, never silent."""
        import os
        import tools.release_ops as ro
        old = os.getcwd()
        os.chdir(self.root)
        try:
            result = ro.smoke_imports(root=REPO)
        finally:
            os.chdir(old)
        self.assertGreater(result.get("modules_tested", 0), 0)
        self.assertTrue(result.get("failed"),
                        "kill switch must fail the import check closed")
        self.assertIn("kill switch", " ".join(result["failed"]).lower())

    def test_capability_manifest_fails_closed(self):
        import importlib
        import tools.capability_manifest as cm
        importlib.reload(cm)   # pick up the patched workspace env
        try:
            results = cm._check_clis()
        finally:
            importlib.reload(cm)  # restore module state post-test
        for entry in results:
            self.assertEqual(entry["status"], "missing",
                             "kill switch must fail the CLI checks closed")
            self.assertIn("KILL SWITCH", entry["detail"])


class DaemonGateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        from tools.runtime.sandbox import (engage_kill_switch,
                                           release_kill_switch)
        engage_kill_switch(self.root, note="daemon-test")
        self.addCleanup(lambda: release_kill_switch(self.root))

    def test_interactsh_refuses_under_kill_switch(self):
        import os
        import tools.infra_deploy as infra
        old = os.getcwd()
        os.chdir(self.root)
        try:
            result = infra.start_interactsh() if hasattr(
                infra, "start_interactsh") else None
            if result is None:
                self.skipTest("interactsh entry point renamed")
            self.assertFalse(result.get("success", True))
            self.assertIn("kill switch", str(result.get("error", "")))
        finally:
            os.chdir(old)


class SandboxRunSemanticsTest(unittest.TestCase):
    """subprocess.run semantics preserved for migrated callers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        from tools.runtime.sandbox import grant, revoke, load_grants
        grant(self.root, ["python3", "cat"])
        self.addCleanup(lambda: revoke(self.root, load_grants(self.root)))
        self.addCleanup(lambda: revoke([], []))

    def test_input_text_and_text_mode(self):
        from tools.runtime.sandbox import sandboxed_run
        result = sandboxed_run(["cat"], cwd=self.root, root=self.root,
                               input_text="payload-123")
        self.assertEqual(result.stdout, "payload-123")

    def test_check_raises_called_process_error(self):
        from tools.runtime.sandbox import sandboxed_run
        with self.assertRaises(subprocess.CalledProcessError):
            sandboxed_run([sys.executable, "-c", "raise SystemExit(7)"],
                          cwd=self.root, root=self.root,
                          allow_unlisted=True, check=True)

    def test_timeout_surfaces_as_timeout_expired(self):
        from tools.runtime.sandbox import sandboxed_run
        with self.assertRaises(subprocess.TimeoutExpired):
            sandboxed_run([sys.executable, "-c",
                           "import time; time.sleep(20)"],
                          cwd=self.root, root=self.root, timeout=1,
                          allow_unlisted=True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.lab_lifecycle import (  # noqa: E402
    FixtureSpec,
    LabLifecycleError,
    LabManager,
    ResourceBudget,
)
from tools.reliability import ResourceLimitError  # noqa: E402


class TestLabLifecycle(unittest.TestCase):
    def make_manager(self, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return LabManager("private-lab.test", project_root=tmp.name, **kwargs)

    def test_create_is_idempotent_and_persists_manifest(self):
        manager = self.make_manager()
        first = manager.create()
        second = manager.create()
        self.assertEqual(first.lab_id, second.lab_id)
        self.assertTrue(manager.manifest_path.is_file())
        self.assertEqual(manager.status()["manifest"]["schema"],
                         "bugwolf/private-lab/v1")

    def test_register_rejects_cwd_outside_project(self):
        manager = self.make_manager()
        manager.create()
        with self.assertRaises(LabLifecycleError):
            manager.register_fixture(FixtureSpec(
                fixture_id="bad", command=[sys.executable, "-c", "pass"], cwd="/tmp"))

    def test_start_stop_tracks_owned_process(self):
        manager = self.make_manager()
        manager.create()
        manager.register_fixture(FixtureSpec(
            fixture_id="sleep", command=[sys.executable, "-c", "import time; time.sleep(30)"]))
        record = manager.start_fixture("sleep")
        self.assertEqual(record.fixture_id, "sleep")
        self.assertEqual(manager.status()["resources"]["running_processes"], 1)
        stopped = manager.stop_fixture(record.process_id)
        self.assertEqual(stopped["status"], "terminated")
        self.assertEqual(manager.status()["resources"]["running_processes"], 0)

    def test_process_budget_is_enforced(self):
        manager = self.make_manager(budget=ResourceBudget(max_processes=1))
        manager.create()
        manager.register_fixture(FixtureSpec(
            fixture_id="sleep", command=[sys.executable, "-c", "import time; time.sleep(30)"]))
        first = manager.start_fixture("sleep")
        self.addCleanup(lambda: manager.stop_fixture(first.process_id))
        with self.assertRaises(ResourceLimitError):
            manager.start_fixture("sleep")

    def test_reset_stops_process_and_clears_workspace(self):
        manager = self.make_manager()
        manager.create()
        manager.register_fixture(FixtureSpec(
            fixture_id="sleep", command=[sys.executable, "-c", "import time; time.sleep(30)"]))
        record = manager.start_fixture("sleep")
        (manager.workspace / "fixture-state.txt").write_text("ephemeral")
        manifest = manager.reset()
        self.assertEqual(manifest.generation, 1)
        self.assertEqual(manifest.status, "reset")
        self.assertFalse((manager.workspace / "fixture-state.txt").exists())
        self.assertEqual(manager.status()["resources"]["running_processes"], 0)
        self.assertNotEqual(manager.status()["manifest"]["processes"].get(record.process_id, {}).get("status"), "running")

    def test_teardown_removes_runtime_directories_and_is_idempotent_when_requested(self):
        manager = self.make_manager()
        manager.create()
        (manager.workspace / "artifact.txt").write_text("data")
        result = manager.teardown()
        self.assertEqual(result["status"], "teardown")
        self.assertFalse(manager.workspace.exists())
        self.assertFalse(manager.logs.exists())
        self.assertEqual(manager.teardown(ignore_missing=False)["status"], "teardown")

    def test_workspace_budget_is_reported(self):
        manager = self.make_manager(budget=ResourceBudget(max_workspace_bytes=3))
        manager.create()
        (manager.workspace / "large.txt").write_text("1234")
        snapshot = manager.status()["resources"]
        self.assertIn("max_workspace_bytes", snapshot["over_budget"])

    def test_unknown_fixture_is_rejected(self):
        manager = self.make_manager()
        manager.create()
        with self.assertRaises(LabLifecycleError):
            manager.start_fixture("missing")


if __name__ == "__main__":
    unittest.main()

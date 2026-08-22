#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.environment_profile import (
    EnvironmentProfileError, collect_environment, save_profile,
)


class TestEnvironmentProfile(unittest.TestCase):
    def test_declaration_does_not_scan_os(self):
        profile = collect_environment("vps")
        self.assertEqual(profile.location, "vps")
        self.assertFalse(profile.os_scan_performed)
        self.assertIsNone(profile.cpu_count)
        self.assertEqual(profile.base, "vps-process")

    def test_os_scan_requires_explicit_confirmation(self):
        with self.assertRaises(EnvironmentProfileError):
            collect_environment("local", scan_os=True)
        profile = collect_environment("local", scan_os=True, confirm_os_scan=True)
        self.assertTrue(profile.os_scan_performed)
        self.assertTrue(profile.os_name)
        self.assertTrue(profile.architecture)
        self.assertTrue(profile.safety_notes)

    def test_profile_persists_without_raw_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "environment.json"
            profile = collect_environment("container_vm", scan_os=True,
                                          confirm_os_scan=True)
            save_profile(profile, path)
            raw = path.read_text()
            self.assertNotIn("/home/", raw)
            loaded = json.loads(raw)
            self.assertEqual(loaded["location"], "container_vm")
            self.assertIn("profile_id", loaded)

    def test_cli_denies_unconfirmed_scan(self):
        result = subprocess.run(
            [sys.executable, "tools/environment_profile.py",
             "--location", "local", "--scan-os", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("confirm-os-scan", result.stdout)


if __name__ == "__main__":
    unittest.main()

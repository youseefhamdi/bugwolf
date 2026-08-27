#!/usr/bin/env python3
import unittest
from unittest.mock import patch

from tools.lab_doctor import doctor


class TestLabDoctor(unittest.TestCase):
    @patch("tools.lab_doctor.shutil.which", return_value=None)
    @patch("tools.lab_doctor._port_open", return_value=False)
    def test_reports_all_runtime_fixes(self, _port, _which):
        result = doctor()
        self.assertFalse(result["ready"])
        self.assertEqual(len(result["doctor"]), 6)
        for row in result["doctor"]:
            self.assertFalse(row["available"])
            self.assertIn("fix:", row["diagnostic"])


if __name__ == "__main__":
    unittest.main()

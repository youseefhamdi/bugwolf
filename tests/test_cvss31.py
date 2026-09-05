#!/usr/bin/env python3
"""Tests for :mod:`bugwolf.governance.cvss`.

Covers the canonical FIRST.org CVSS 3.1 thresholds (0.0, 4.0, 7.0, 9.0)
plus a handful of well-known vector strings.  Reference values were taken
from https://www.first.org/cvss/calculator/3.1 — the official CVSS
calculator rounds consistently with our ``_round_up_one``.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class CVSSScoreTests(unittest.TestCase):
    """Hand-computed scores for canonical vectors."""

    def setUp(self) -> None:
        from bugwolf.governance.cvss import CVSS31
        self.cvss = CVSS31()

    def test_critical_default(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 critical
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)
        self.assertEqual(self.cvss.severity(score), "critical")

    def test_high_default(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 high
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertEqual(score, 7.5)
        self.assertEqual(self.cvss.severity(score), "high")

    def test_medium_default(self) -> None:
        # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N -> 6.4 medium
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
        self.assertEqual(score, 6.4)
        self.assertEqual(self.cvss.severity(score), "medium")

    def test_low_default(self) -> None:
        # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> ~1.7 low
        score = self.cvss.score(
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        self.assertAlmostEqual(score, 1.7, delta=0.05)
        self.assertEqual(self.cvss.severity(score), "low")

    def test_none_zero(self) -> None:
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(score, 0.0)
        self.assertEqual(self.cvss.severity(score), "none")

    def test_scope_changed(self) -> None:
        # Scope changed bumps the base score by 1.08
        # AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N -> 4.7 medium
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N")
        self.assertAlmostEqual(score, 4.7, delta=0.05)
        self.assertEqual(self.cvss.severity(score), "medium")


class CVSSSeverityThresholdTests(unittest.TestCase):
    """The four canonical threshold cutoffs (0, 4, 7, 9)."""

    def setUp(self) -> None:
        from bugwolf.governance.cvss import CVSS31
        self.cvss = CVSS31()

    def test_threshold_0_is_none(self) -> None:
        self.assertEqual(self.cvss.severity(0.0), "none")

    def test_threshold_just_above_none_is_low(self) -> None:
        self.assertEqual(self.cvss.severity(0.1), "low")

    def test_threshold_just_below_medium_is_low(self) -> None:
        self.assertEqual(self.cvss.severity(3.9), "low")

    def test_threshold_4_is_medium(self) -> None:
        self.assertEqual(self.cvss.severity(4.0), "medium")
        self.assertEqual(self.cvss.severity(6.9), "medium")

    def test_threshold_7_is_high(self) -> None:
        self.assertEqual(self.cvss.severity(7.0), "high")
        self.assertEqual(self.cvss.severity(8.9), "high")

    def test_threshold_9_is_critical(self) -> None:
        self.assertEqual(self.cvss.severity(9.0), "critical")
        self.assertEqual(self.cvss.severity(10.0), "critical")


class CVSSParseErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        from bugwolf.governance.cvss import CVSS31
        self.cvss = CVSS31()

    def test_invalid_prefix(self) -> None:
        with self.assertRaises(ValueError):
            self.cvss.score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_missing_metric(self) -> None:
        with self.assertRaises(ValueError):
            self.cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_invalid_value(self) -> None:
        with self.assertRaises(ValueError):
            self.cvss.score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_unknown_metric(self) -> None:
        with self.assertRaises(ValueError):
            self.cvss.score(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/X:F")

    def test_severity_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            self.cvss.severity(-0.1)
        with self.assertRaises(ValueError):
            self.cvss.severity(10.5)

    def test_cvss30_prefix_accepted(self) -> None:
        # CVSS 3.0 and 3.1 share the same formula; the parser must
        # accept either prefix.
        score = self.cvss.score(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)


if __name__ == "__main__":
    unittest.main()
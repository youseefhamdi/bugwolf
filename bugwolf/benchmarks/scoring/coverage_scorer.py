# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-scoring-coverage-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Coverage scorer — line + branch coverage ratios."""

SCHEMA = "bugwolf-benchmarks-scoring-coverage-v1"


def line_coverage(covered, total):
    """Return |covered ∩ total| / |total|, or 0.0 if total is empty."""
    if not total:
        return 0.0
    intersection = len(set(covered) & set(total))
    return intersection / len(set(total))


def branch_coverage(branches_covered, branches_total):
    """Return ``branches_covered / branches_total`` or 0.0 if no branches."""
    if not branches_total:
        return 0.0
    return branches_covered / branches_total


def _run_self_tests():
    import unittest

    class CoverageTests(unittest.TestCase):
        def test_line_full(self):
            self.assertEqual(line_coverage({1, 2, 3}, {1, 2, 3}), 1.0)

        def test_line_partial(self):
            self.assertAlmostEqual(line_coverage({1}, {1, 2, 4}), 1 / 3)

        def test_line_empty_total(self):
            self.assertEqual(line_coverage({1, 2}, set()), 0.0)

        def test_line_no_overlap(self):
            self.assertEqual(line_coverage({9, 10}, {1, 2}), 0.0)

        def test_branch_full(self):
            self.assertEqual(branch_coverage(8, 8), 1.0)

        def test_branch_partial(self):
            self.assertAlmostEqual(branch_coverage(3, 4), 0.75)

        def test_branch_zero_total(self):
            self.assertEqual(branch_coverage(0, 0), 0.0)

    return unittest.TestLoader().loadTestsFromTestCase(CoverageTests)


if __name__ == "__main__":
    import unittest
    unittest.TextTestRunner(verbosity=2).run(_run_self_tests())
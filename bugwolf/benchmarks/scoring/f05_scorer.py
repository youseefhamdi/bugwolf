# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-scoring-f05-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""F0.5 scorer — BugWolf prefers precision over recall.

F0.5 weights precision 4x more than recall. This matches BugWolf's
mission: false positives damage credibility with bug-bounty triage, so
we happily trade some recall for high confidence.
"""

SCHEMA = "bugwolf-benchmarks-scoring-f05-v1"


def precision(tp, fp):
    """Return TP / (TP + FP) or 0.0 when denominator is zero."""
    denom = (tp or 0) + (fp or 0)
    if denom <= 0:
        return 0.0
    return (tp or 0) / denom


def recall(tp, fn):
    """Return TP / (TP + FN) or 0.0 when denominator is zero."""
    denom = (tp or 0) + (fn or 0)
    if denom <= 0:
        return 0.0
    return (tp or 0) / denom


def f05(p, r):
    """Return F0.5 score. Pure-precision runs return p; zero P/R returns 0.0."""
    beta2 = 0.5 * 0.5  # 0.25
    denom = beta2 * p + r
    if denom <= 0:
        return 0.0
    return (1 + beta2) * p * r / denom


def score_run(predicted, ground_truth):
    """Compute TP/FP/FN and the F0.5 family for two flat string lists."""
    pred = set(predicted or [])
    gt = set(ground_truth or [])
    tp = len(pred & gt)
    fp = len(pred - gt)
    fn = len(gt - pred)
    p = precision(tp, fp)
    r = recall(tp, fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": p,
        "recall": r,
        "f05": f05(p, r),
    }


def _run_self_tests():
    import unittest

    class F05Tests(unittest.TestCase):
        def test_precision_basic(self):
            self.assertEqual(precision(8, 2), 0.8)

        def test_precision_zero_fp(self):
            self.assertEqual(precision(10, 0), 1.0)

        def test_precision_zero_total(self):
            self.assertEqual(precision(0, 0), 0.0)

        def test_recall_basic(self):
            self.assertEqual(recall(8, 2), 0.8)

        def test_recall_zero_fn(self):
            self.assertEqual(recall(10, 0), 1.0)

        def test_recall_zero_total(self):
            self.assertEqual(recall(0, 0), 0.0)

        def test_f05_prefers_precision(self):
            # High precision + low recall still scores well under F0.5
            score_high_p = f05(1.0, 0.1)
            score_balanced = f05(0.7, 0.7)
            self.assertGreater(score_high_p, score_balanced)

        def test_f05_zero(self):
            self.assertEqual(f05(0.0, 0.0), 0.0)
            self.assertEqual(f05(0.0, 1.0), 0.0)

        def test_score_run_full(self):
            res = score_run(["a", "b", "c"], ["a", "b", "d"])
            self.assertEqual(res["tp"], 2)
            self.assertEqual(res["fp"], 1)
            self.assertEqual(res["fn"], 1)
            self.assertAlmostEqual(res["precision"], 2 / 3)
            self.assertAlmostEqual(res["recall"], 2 / 3)

    return unittest.TestLoader().loadTestsFromTestCase(F05Tests)


if __name__ == "__main__":
    import unittest
    unittest.TextTestRunner(verbosity=2).run(_run_self_tests())
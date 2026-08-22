"""Tests for the ART4SQLi payload-aware selection layer (tools/art_selector.py)."""

import hashlib
import json
import math
import random
import unittest

from tools.mutator import Mutation, RiskClass
from tools.art_selector import (
    DEFAULT_FIXED_SIZE, PayloadSpace, adaptive_select, art_allocate,
    build_payload_space, distance, f_measure, feature_vector,
    nearest_neighbor_score, payload_aware_distance, payload_tokens,
    select_and_report, select_next,
)


def _mutation(kind, mutated, *, variable="q", method="GET", path="/x",
              operation_id="op1", bug_class="sql_injection", risk="read"):
    raw = "|".join([operation_id, kind, variable, repr(mutated)])
    return Mutation(
        mutation_id=hashlib.sha256(raw.encode()).hexdigest()[:16],
        operation_id=operation_id, method=method, path=path, kind=kind,
        variable=variable, original=None, mutated=mutated,
        bug_class=bug_class, risk=RiskClass(risk),
    )


# The paper's worked example (Fig. 6): a single-quote payload that decomposes
# into quote-encoding / comment / keyword / equality / comment tokens.
PAPER_EXAMPLE = "%27/**/or/**/%27a%27 = %27a%27#"


class TestPayloadTokens(unittest.TestCase):
    def test_paper_example_decomposition(self):
        tokens = payload_tokens(PAPER_EXAMPLE)
        # %27 x5, /**/ x2, or, a x2, =, #
        self.assertEqual(tokens.count("%27"), 5)
        self.assertEqual(tokens.count("/**/"), 2)
        self.assertEqual(tokens.count("OR"), 1)
        self.assertEqual(tokens.count("id"), 2)  # the two literal 'a' terminals
        self.assertEqual(tokens.count("="), 1)
        self.assertEqual(tokens.count("#"), 1)

    def test_keywords_case_insensitive_and_literals_normalized(self):
        tokens = payload_tokens("1 AND sleep(5)--")
        self.assertIn("AND", tokens)
        self.assertIn("SLEEP", tokens)
        # '1' and '5' both collapse to the ``num`` token
        self.assertEqual(tokens.count("num"), 2)
        self.assertIn("--", tokens)

    def test_whitespace_produces_no_token(self):
        self.assertEqual(payload_tokens("a   b"),
                         ["id", "id"])
        # whitespace tactic is represented by the comment/encoding token
        self.assertIn("/**/", payload_tokens("a/**/b"))

    def test_deterministic(self):
        self.assertEqual(payload_tokens(PAPER_EXAMPLE),
                         payload_tokens(PAPER_EXAMPLE))

    def test_mysql_version_comment_and_hex(self):
        tokens = payload_tokens("/*!50000select*/0x41")
        self.assertEqual(tokens.count("comment"), 1)
        self.assertIn("hex", tokens)

    def test_ws_comment_is_its_own_token(self):
        tokens = payload_tokens("a/**/b")
        self.assertEqual(tokens, ["id", "/**/", "id"])


class TestPayloadSpace(unittest.TestCase):
    def test_identical_payloads_distance_one(self):
        space = PayloadSpace.fit(["1' AND SLEEP(5)--", "1' AND SLEEP(5)--",
                                  "1 AND SLEEP(5)--"])
        self.assertEqual(space.distance("1' AND SLEEP(5)--",
                                        "1' AND SLEEP(5)--"), 1.0)

    def test_orthogonal_payloads_infinite(self):
        # No shared tokens -> cosine 0 -> +inf (paper eq. 3).
        space = PayloadSpace.fit(["1' OR '1'='1--", "WAITFOR DELAY"])
        self.assertTrue(math.isinf(
            space.distance("1' OR '1'='1--", "WAITFOR DELAY")))

    def test_intermediate_distance_between_one_and_inf(self):
        space = PayloadSpace.fit(["1' OR '1'='1--", "1' OR 'a'='b#",
                                  "1 AND 1=1--"])
        d = space.distance("1' OR '1'='1--", "1' OR 'a'='b#")
        self.assertGreater(d, 1.0)
        self.assertLess(d, math.inf)

    def test_vectors_are_l2_normalized(self):
        payloads = ["1' OR '1'='1--", "1 AND SLEEP(5)--", "1;DROP TABLE x--"]
        space = PayloadSpace.fit(payloads)
        for p in payloads:
            v = space.vector(p)
            self.assertAlmostEqual(math.sqrt(sum(x * x for x in v)), 1.0,
                                   places=6)

    def test_effective_payloads_cluster(self):
        """Paper Q1: effective payloads cluster in the token space.

        Intra-class (effective-to-effective) average distance must be well
        below inter-class (effective-to-ineffective), mirroring Table IV.
        """
        effective = ["1' OR '1'='1", "' OR 1=1--", "1' OR '1'='1'--",
                     "1' OR 1=1#", "1' OR 'a'='a", "1' OR '1'='1'#"]
        ineffective = ["1 AND SLEEP(2)--", "1 AND SLEEP(9)--",
                       "1 UNION SELECT NULL--", "1 WAITFOR DELAY '0:0:5'--",
                       "1;DROP TABLE x--", "1 AND PG_SLEEP(5)--",
                       "1 UNION ALL SELECT 1,2,3--", "1 AND 1=2--",
                       "1' AND (SELECT SLEEP(5))--", "'"]
        space = PayloadSpace.fit(effective + ineffective)

        intra = [space.distance(a, b)
                 for i, a in enumerate(effective) for b in effective[i + 1:]]
        inter = [space.distance(a, b) for a in effective for b in ineffective]
        intra_mean = sum(intra) / len(intra)
        inter_mean = sum(inter) / len(inter)
        self.assertLess(intra_mean, inter_mean)
        # The paper reports intra ~15 vs inter ~66 (roughly 4x gap); keep a
        # tolerant bound so the test stays robust to tokenizer details.
        self.assertLess(intra_mean, inter_mean / 2)


class TestSelection(unittest.TestCase):
    def _pool(self, n=40):
        """40 distinct payload-bearing mutations (unique mutated values)."""
        bases = [
            lambda i: "1' OR '1'='{}'".format(i),
            lambda i: "1 AND SLEEP({})--".format(i),
            lambda i: "1 UNION SELECT {}--".format(i),
            lambda i: "1 WAITFOR DELAY '0:0:{}'".format(i),
            lambda i: "1 AND PG_SLEEP({})--".format(i),
            lambda i: "1;SELECT IF(({0}>{0}-1),SLEEP(5),0)#".format(i),
        ]
        out = []
        i = 0
        while len(out) < n:
            out.append(_mutation("blind_sqli", bases[i % len(bases)](i)))
            i += 1
        return out

    def test_adaptive_select_deterministic_and_bounded(self):
        pool = self._pool(40)
        a = adaptive_select(pool, 12, fixed_size=10)
        b = adaptive_select(pool, 12, fixed_size=10)
        self.assertEqual([m.mutation_id for m in a],
                         [m.mutation_id for m in b])
        self.assertEqual(len(a), 12)
        self.assertEqual(len({m.mutation_id for m in a}), 12)  # no repeats
        self.assertEqual(adaptive_select(pool, 0), [])
        self.assertEqual(adaptive_select(pool, 100), list(pool))  # clamped

    def test_adaptive_select_seed_changes_selection(self):
        pool = self._pool(40)
        a = adaptive_select(pool, 10, fixed_size=10, seed=1)
        b = adaptive_select(pool, 10, fixed_size=10, seed=2)
        self.assertNotEqual([m.mutation_id for m in a],
                            [m.mutation_id for m in b])

    def test_fixed_size_none_matches_legacy_farthest_first(self):
        pool = self._pool(30)
        legacy = adaptive_select(pool, 8, fixed_size=None)
        self.assertEqual(len(legacy), 8)
        self.assertEqual(legacy[0].mutation_id, pool[0].mutation_id)  # seed

    def test_art_allocate_untried_first_then_refill(self):
        pool = self._pool(20)
        untried = pool[:5]
        tried = pool[5:15]
        alloc = art_allocate(untried, tried, 10, fixed_size=5)
        self.assertEqual(len(alloc), 10)
        first_five = {m.mutation_id for m in alloc[:5]}
        self.assertEqual(first_five, {m.mutation_id for m in untried})
        refilled = {m.mutation_id for m in alloc[5:]}
        self.assertTrue(refilled <= {m.mutation_id for m in tried})

    def test_art_allocate_all_refill_when_no_untried(self):
        pool = self._pool(10)
        alloc = art_allocate([], pool, 4, fixed_size=5)
        self.assertEqual(len(alloc), 4)
        self.assertEqual(len({m.mutation_id for m in alloc}), 4)

    def test_payload_aware_distance_falls_back_to_structural(self):
        space = build_payload_space(self._pool(6))
        payload_a = _mutation("injection", "1' OR '1'='1")
        payload_b = _mutation("injection", "1 AND SLEEP(5)--")
        self.assertEqual(payload_aware_distance(payload_a, payload_b, space),
                         space.distance("1' OR '1'='1", "1 AND SLEEP(5)--"))
        boundary = _mutation("boundary", 0, bug_class="input_validation")
        structural = payload_aware_distance(payload_a, boundary, space)
        self.assertEqual(structural,
                         distance(feature_vector(payload_a),
                                  feature_vector(boundary)))

    def test_f_measure(self):
        pool = self._pool(10)
        self.assertEqual(f_measure(pool, lambda m: True), 1)
        self.assertEqual(f_measure(pool, lambda m: False), None)
        self.assertEqual(f_measure(pool, lambda m: m is pool[4]), 5)

    def _art_sequence(self, pool, fixed_size=10, seed=0):
        """Faithful ART4SQLi process: evaluate one payload at a time, keep the
        evaluated set growing while the pool shrinks by the chosen payload only
        (paper Fig. 4 Step 4a/4b/4c), until the pool is exhausted.
        """
        remaining = list(pool)
        evaluated = []
        order = []
        round_no = 0
        while remaining:
            nxt = select_next(remaining, evaluated, fixed_size=fixed_size,
                              seed=seed, round_no=round_no)
            remaining.remove(nxt)
            evaluated.append(nxt)
            order.append(nxt)
            round_no += 1
        return order

    def test_art_finds_effective_cluster_faster_than_random(self):
        """Paper Q2, in miniature: with a tight effective cluster, FSCS-ART
        reaches an effective payload in fewer draws than random selection on
        the same payload ordering. Effective payloads are the quote+OR family.
        """
        effective = ["1' OR '1'='1", "' OR 1=1--", "1' OR '1'='1'--",
                     "1' OR 1=1#", "1' OR 'a'='a", "1' OR '1'='1'#"]
        ineffective = []
        for i in range(40):
            ineffective.append(
                ["1 AND SLEEP({})--".format(i % 10),
                 "1 UNION SELECT {}--".format(i),
                 "1 WAITFOR DELAY '0:0:{}'".format(i % 10),
                 "1 AND PG_SLEEP({})--".format(i % 10),
                 "1;SELECT IF(({0}>{0}-1),SLEEP(5),0)#".format(i % 10)][i % 5])
        pool = [_mutation("blind_sqli", p) for p in ineffective]
        pool += [_mutation("blind_sqli", p) for p in effective]
        effective_ids = {m.mutation_id for m in pool[len(ineffective):]}

        art_fmeasures, random_fmeasures = [], []
        for seed in range(10):
            rng = random.Random(seed)
            ordered = pool[:]
            rng.shuffle(ordered)
            art = self._art_sequence(ordered, fixed_size=10, seed=seed)
            art_fmeasures.append(f_measure(art, lambda m, ids=effective_ids:
                                           m.mutation_id in ids))
            # Same ordering, pure random draw (paper's Random baseline).
            rnd = ordered[:]
            rng.shuffle(rnd)
            random_fmeasures.append(f_measure(rnd, lambda m, ids=effective_ids:
                                              m.mutation_id in ids))
        self.assertLess(sum(art_fmeasures) / len(art_fmeasures),
                        sum(random_fmeasures) / len(random_fmeasures))

    def test_nearest_neighbor_score_payload_vs_structural(self):
        pool = self._pool(10)
        space = build_payload_space(pool)
        payload_score = nearest_neighbor_score(pool, space=space)
        # Payload distances are >= 1 (identical) so the payload-aware score
        # exceeds the [0, 1] structural score for this payload-only pool.
        self.assertGreater(payload_score, nearest_neighbor_score(pool))


class TestArtSelectionReport(unittest.TestCase):
    def test_select_and_report_shape(self):
        pool = [
            _mutation("blind_sqli", "1 AND SLEEP({})--".format(i))
            for i in range(20)
        ]
        report = select_and_report(pool, 8, fixed_size=10, seed=0)
        data = report.to_dict()
        self.assertEqual(data["schema"], "bugwolf-art-selector-v2")
        self.assertEqual(data["fixed_size"], 10)
        self.assertEqual(len(data["selection"]), 8)
        self.assertGreater(data["payload_vocab_size"], 0)
        self.assertEqual(data["payload_bearing"], 8)
        # JSON-serializable end to end
        json.dumps(data, default=str)


if __name__ == "__main__":
    unittest.main()

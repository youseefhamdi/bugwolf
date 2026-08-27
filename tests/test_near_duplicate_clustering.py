#!/usr/bin/env python3
import unittest

from tools.candidate_lifecycle import ResearchCandidate
from tools.novelty_pipeline import cluster_near_duplicates


def _candidate(domain="web_api", *, title="x", bug_class="c", endpoint="/x", behavior=None):
    return ResearchCandidate(domain=domain, bug_class=bug_class, title=title,
                             endpoint=endpoint, behavior=behavior or {})


class TestNearDuplicateClustering(unittest.TestCase):
    def test_clusters_similar_candidates(self):
        a = _candidate(title="SQL injection in user search endpoint", bug_class="sqli", endpoint="/search")
        b = _candidate(title="SQL injection in search endpoint (user)", bug_class="sqli", endpoint="/search")
        c = _candidate(title="GraphQL batch denial of service", bug_class="graphql_dos", endpoint="/graphql")
        clusters = cluster_near_duplicates([a, b, c], threshold=0.6)
        self.assertEqual(len(clusters), 2)
        big = max(clusters, key=len)
        self.assertEqual(len(big), 2)
        self.assertIn(a.candidate_id, big)
        self.assertIn(b.candidate_id, big)

    def test_distinct_candidates_stay_separate(self):
        a = _candidate(title="Reentrancy in vault", bug_class="reentrancy", endpoint="/vault")
        b = _candidate(title="GraphQL batching abuse", bug_class="graphql", endpoint="/graphql")
        clusters = cluster_near_duplicates([a, b], threshold=0.6)
        self.assertEqual(len(clusters), 2)


if __name__ == "__main__":
    unittest.main()
#!/usr/bin/env python3
import tempfile
import unittest

from tools.mutation_lineage import MutationLineage, mutation_id


class TestMutationLineage(unittest.TestCase):
    def test_identifier_is_stable(self):
        self.assertEqual(
            mutation_id(surface="api", operation="GET /users/1", variant="id-swap", input_value="2"),
            mutation_id(surface="api", operation="GET /users/1", variant="id-swap", input_value="2"),
        )

    def test_records_are_deduplicated_and_outcome_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            lineage = MutationLineage("lab", tmp)
            first = lineage.add(surface="api", operation="GET /users/1",
                                variant="id-swap", input_value="2")
            same = lineage.add(surface="api", operation="GET /users/1",
                               variant="id-swap", input_value="2")
            self.assertEqual(first.mutation_id, same.mutation_id)
            lineage.update_outcome(first.mutation_id, "reproduced")
            restored = MutationLineage("lab", tmp)
            self.assertEqual(restored.records[first.mutation_id].outcome, "reproduced")
            self.assertEqual(restored.report()["total"], 1)

    def test_parent_lineage_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            lineage = MutationLineage("lab", tmp)
            parent = lineage.add(surface="api", operation="GET", variant="base")
            child = lineage.add(surface="api", operation="GET", variant="header",
                                parent_id=parent.mutation_id)
            self.assertEqual(child.parent_id, parent.mutation_id)
            self.assertEqual(lineage.report()["roots"], 1)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.lineage_graph import LineageGraph, LineageNode


class TestLineageGraph(unittest.TestCase):
    def test_records_document_to_transaction_lineage(self):
        graph = LineageGraph("lab")
        doc = graph.add("document", {"file": "poisoned.md"})
        tool = graph.add("tool_call", {"tool": "fetch", "arguments": {"url": "https://lab/api/transfer"}}, parent=doc.id)
        request = graph.add("request", {"method": "POST", "url": "/api/transfer"}, parent=tool.id)
        transaction = graph.add("transaction", {"contract": "Vault", "function": "withdraw"}, parent=request.id)
        path = graph.path(doc.id, transaction.id)
        self.assertEqual(len(path), 4)
        self.assertEqual(path[0].kind, "document")
        self.assertEqual(path[-1].kind, "transaction")

    def test_cycle_detection(self):
        graph = LineageGraph("test")
        a = graph.add("input", {"v": 1})
        b = graph.add("mutation", {"v": 2}, parent=a.id)
        with self.assertRaises(ValueError):
            graph.add("output", {"v": 3}, parent=b.id, children=[a.id])

    def test_export_jsonl_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            graph = LineageGraph("test")
            a = graph.add("input", {"v": 1})
            b = graph.add("request", {"url": "/x"}, parent=a.id)
            path = graph.export(Path(tmp) / "lineage.jsonl")
            self.assertTrue(path.is_file())
            self.assertIn('"kind": "request"', path.read_text())


if __name__ == "__main__":
    unittest.main()
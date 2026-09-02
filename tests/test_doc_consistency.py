#!/usr/bin/env python3
"""Doc-consistency regression tests: AUDIT_MAP.md vs tools/recon/.

History: ``historical_asset_delta.py`` was documented in AUDIT_MAP.md
(424 lines, ``compute_delta``@274, ``ingest_historical``@232) and required
by the CI bundle checker, but never committed -- three test failures on a
clean tree. These tests pin the doc<->code contract so a documented-but-
missing module, a stale anchor, or a lost API fails immediately instead
of surfacing as a phantom CI failure.

The semantic half pins the churn-category algebra of ``compute_delta``
that the committed spec test (``TestHistoricalAssetDelta``) exposed:

  * ``added``      = latest - first   (a mid-history sighting does NOT
                     disqualify an asset from being "added": it was not
                     part of the baseline surface)
  * ``removed``    = first - latest   (baseline asset gone now; absence
                     from intermediate snapshots does not matter)
  * ``reattached`` = seen before, missing from the immediately-previous
                     snapshot, back in the latest
  * ``forgotten``  = ever - latest    (nothing silently dropped)
  * ``total_tracked`` = size of the union across all snapshots
"""

import inspect
import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.recon import historical_asset_delta as had

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = REPO_ROOT / "AUDIT_MAP.md"
MODULE_REL = "tools/recon/historical_asset_delta.py"


class TestAuditMapDocSync(unittest.TestCase):
    """AUDIT_MAP.md rows about historical_asset_delta must stay true."""

    def setUp(self):
        self.doc = DOC_PATH.read_text(encoding="utf-8")

    def test_doc_file_exists(self):
        self.assertTrue(DOC_PATH.is_file(), "AUDIT_MAP.md is missing")

    def test_module_exists_at_documented_path(self):
        self.assertTrue(
            (REPO_ROOT / MODULE_REL).is_file(),
            f"{MODULE_REL} is documented in AUDIT_MAP.md but missing from the tree",
        )

    def test_doc_rows_present(self):
        # Both the 7.2 module table and the 9 (recon/intelligence) table
        # reference the module; both must use the canonical path.
        self.assertGreaterEqual(
            self.doc.count(MODULE_REL), 2,
            "AUDIT_MAP.md must reference the module by its canonical path "
            f"{MODULE_REL} in both the section-7.2 and section-9 tables",
        )
        self.assertIn("Passive-DNS/CRT churn tracker", self.doc)

    def test_doc_anchors_match_code(self):
        # The doc pins `fn@line` anchors; they must equal the real def line.
        for fn_name in ("compute_delta", "ingest_historical"):
            match = re.search(rf"`{fn_name}`@(\d+)", self.doc)
            self.assertIsNotNone(
                match, f"AUDIT_MAP.md lost its `{fn_name}`@line anchor"
            )
            claimed = int(match.group(1))
            fn = getattr(had, fn_name)
            actual = inspect.getsourcelines(fn)[1]
            self.assertEqual(
                claimed, actual,
                f"AUDIT_MAP.md says {fn_name}@{claimed} but the function "
                f"starts at line {actual} -- update the AUDIT_MAP row",
            )

    def test_public_api_matches_doc(self):
        # The doc's purpose line names the key definitions; they must exist.
        for name in ("compute_delta", "ingest_historical", "history_path"):
            self.assertTrue(
                callable(getattr(had, name, None)),
                f"documented API surface lost: {name}",
            )


class TestHistoricalAssetDeltaSemantics(unittest.TestCase):
    """Pin the churn-category algebra against the documented semantics."""

    SNAPSHOTS = [
        {"as_of": "2026-01",
         "assets": ["api.example.com", "old.example.com", "blog.example.com",
                    "dev.example.com"]},
        {"as_of": "2026-04",
         "assets": ["api.example.com", "blog.example.com", "staging.example.com"]},
        {"as_of": "2026-07",
         "assets": ["api.example.com", "blog.example.com", "old.example.com",
                    "staging.example.com", "new.example.com"]},
    ]

    def test_added_is_latest_minus_first(self):
        # staging was seen mid-history (2026-04) yet is still "added":
        # it was absent from the baseline snapshot.
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.added.assets,
                         ["new.example.com", "staging.example.com"])

    def test_removed_is_first_minus_latest(self):
        # dev disappeared after 2026-01. It is absent from the
        # immediately-previous snapshot too -- it must still be counted as
        # removed (baseline surface lost), never as reattached.
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.removed.assets, ["dev.example.com"])
        self.assertNotIn("dev.example.com", delta.reattached.assets)

    def test_reattached_requires_gap_from_previous(self):
        # old: present 2026-01, gone 2026-04, back 2026-07 -> reattached.
        # api/blog: never dropped -> not reattached.
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.reattached.assets, ["old.example.com"])

    def test_forgotten_is_ever_minus_latest(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.forgotten.assets, ["dev.example.com"])

    def test_total_tracked_is_union_size(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS)
        self.assertEqual(delta.total_tracked, 6)

    def test_two_snapshot_window(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS[:2])
        self.assertEqual(delta.added.assets, ["staging.example.com"])
        self.assertEqual(delta.removed.assets,
                         ["dev.example.com", "old.example.com"])
        self.assertEqual(delta.reattached.count, 0)

    def test_single_snapshot_is_all_stable(self):
        delta = had.compute_delta("acme", self.SNAPSHOTS[:1])
        self.assertEqual(delta.added.count, 0)
        self.assertEqual(delta.removed.count, 0)
        self.assertEqual(delta.reattached.count, 0)
        self.assertEqual(delta.forgotten.count, 0)
        self.assertEqual(delta.total_tracked, 4)

    def test_canonicalization_folds_case_and_trailing_dot(self):
        delta = had.compute_delta("acme", [
            {"as_of": "a", "assets": ["API.Example.COM"]},
            {"as_of": "b", "assets": ["api.example.com."]},
        ])
        self.assertEqual(delta.total_tracked, 1)
        self.assertEqual(delta.reattached.count, 0)

    def test_deterministic_output(self):
        d1 = had.compute_delta("acme", self.SNAPSHOTS).to_dict()
        d2 = had.compute_delta("acme", self.SNAPSHOTS).to_dict()
        self.assertEqual(d1, d2)

    def test_ingest_merges_first_and_last_seen(self):
        records = [
            {"name": "api.example.com", "first_seen": "2026-01", "last_seen": "2026-03"},
            {"name": "api.example.com", "first_seen": "2026-05", "last_seen": "2026-07"},
        ]
        with tempfile.TemporaryDirectory() as td:
            obs = had.ingest_historical("acme", records, base_dir=td)
            self.assertEqual(obs["api.example.com"].first_seen, "2026-01")
            self.assertEqual(obs["api.example.com"].last_seen, "2026-07")
            hist = had.history_path(Path(td), "acme")
            self.assertTrue(hist.is_file())
            lines = [l for l in hist.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 2)  # append-only, one per record


if __name__ == "__main__":
    unittest.main()

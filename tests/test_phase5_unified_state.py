"""Tests for bugwolf.unified_state."""

# bugwolf/tests — Phase 5.C unified_state integration tests
# SCHEMA: bugwolf-unifiedstate-tests-v1

from __future__ import annotations

import json
import os
import tempfile
import unittest

from bugwolf.unified_state.chain import (
    GENESIS_HASH,
    compute_hash,
    entry_hash,
    seal_entry,
    verify_chain,
)
from bugwolf.unified_state.facade import get_state, quick_record, reset_singleton
from bugwolf.unified_state.machine import (
    Phase,
    StateMachine,
    VALID_TRANSITIONS,
    InvalidTransition,
)
from bugwolf.unified_state.merge import merge_files, merge_journals
from bugwolf.unified_state.migrate import (
    detect_legacy_format,
    migrate_legacy,
    migrate_legacy_dict,
)
from bugwolf.unified_state.state import State
from bugwolf.unified_state.types import Entry, EntryKind, canonical_json, from_dict, to_dict


def _tmp_path(name: str) -> str:
    fd, path = tempfile.mkstemp(prefix=f"test_state_{name}_", suffix=".jsonl")
    os.close(fd)
    os.unlink(path)
    return path


def _make_entry(seq: int, kind: EntryKind = EntryKind.INIT, payload=None,
                prev_hash: str = GENESIS_HASH, mission_id: str = "m1",
                actor: str = "tester"):
    e = Entry(
        id=f"id-{seq}",
        seq=seq,
        timestamp=float(seq),
        kind=kind,
        mission_id=mission_id,
        actor=actor,
        payload=payload or {},
        prev_hash=prev_hash,
        hash="",
    )
    e.hash = entry_hash(e)
    return e


class TestHashChain(unittest.TestCase):
    def test_empty_chain_ok(self):
        result = verify_chain([])
        self.assertTrue(result["ok"])
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["broken_at"], None)
        self.assertEqual(result["errors"], [])

    def test_valid_chain_ok(self):
        e1 = _make_entry(1)
        e2 = _make_entry(2, prev_hash=e1.hash)
        e3 = _make_entry(3, prev_hash=e2.hash)
        result = verify_chain([e1, e2, e3])
        self.assertTrue(result["ok"])
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["broken_at"], None)

    def test_tampered_entry_detected(self):
        e1 = _make_entry(1)
        e2 = _make_entry(2, prev_hash=e1.hash, payload={"x": 1})
        # Tamper with e2's payload but keep stale hash.
        e2.payload = {"x": 999}
        result = verify_chain([e1, e2])
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], 1)
        self.assertGreater(len(result["errors"]), 0)

    def test_missing_prev_hash_field_detected(self):
        # Genesis must have GENESIS_HASH as prev_hash; verify mismatch is caught.
        e1 = _make_entry(1, prev_hash="f" * 64)  # wrong prev_hash
        result = verify_chain([e1])
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], 0)
        self.assertTrue(any("genesis" in e["reason"] for e in result["errors"]))

    def test_compute_hash_deterministic(self):
        h1 = compute_hash("a", "b")
        h2 = compute_hash("a", "b")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)


class TestState(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_path("state")

    def tearDown(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def test_create_new(self):
        s = State(self.path)
        self.assertEqual(s.read_all(), [])
        stats = s.stats()
        self.assertEqual(stats["total"], 0)

    def test_append_and_read_back(self):
        s = State(self.path, mission_id="alpha", actor="alice")
        e1 = s.append(EntryKind.INIT, {"hello": "world"})
        e2 = s.append(EntryKind.SCOPE, {"target": "x"})
        entries = s.read_all()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].seq, 1)
        self.assertEqual(entries[1].seq, 2)
        self.assertEqual(entries[1].prev_hash, e1.hash)

    def test_verify_chain(self):
        s = State(self.path)
        for i in range(3):
            s.append(EntryKind.SCAN, {"i": i})
        result = s.verify()
        self.assertTrue(result["ok"])

    def test_tampered_file_detected(self):
        s = State(self.path)
        s.append(EntryKind.INIT, {"a": 1})
        s.append(EntryKind.SCAN, {"a": 2})
        # Tamper with the second line's payload but leave hash.
        with open(self.path, "r") as fh:
            lines = fh.readlines()
        d = json.loads(lines[1])
        d["payload"] = {"a": "tampered"}
        lines[1] = json.dumps(d) + "\n"
        with open(self.path, "w") as fh:
            fh.writelines(lines)
        result = s.verify()
        self.assertFalse(result["ok"])

    def test_multi_mission(self):
        s = State(self.path)
        s.append(EntryKind.INIT, {}, mission_id="A")
        s.append(EntryKind.SCOPE, {}, mission_id="B")
        s.append(EntryKind.SCAN, {}, mission_id="A")
        a_entries = s.entries_by_mission("A")
        b_entries = s.entries_by_mission("B")
        self.assertEqual(len(a_entries), 2)
        self.assertEqual(len(b_entries), 1)

    def test_kind_filter(self):
        s = State(self.path)
        s.append(EntryKind.INIT, {})
        s.append(EntryKind.SCOPE, {})
        s.append(EntryKind.SCOPE, {})
        scans = s.entries_by_kind(EntryKind.SCOPE)
        self.assertEqual(len(scans), 2)
        self.assertTrue(all(e.kind == EntryKind.SCOPE for e in scans))

    def test_latest(self):
        s = State(self.path)
        s.append(EntryKind.INIT, {"v": 1})
        s.append(EntryKind.SCOPE, {"v": 2})
        s.append(EntryKind.SCAN, {"v": 3})
        latest = s.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.kind, EntryKind.SCAN)
        latest_scope = s.latest(EntryKind.SCOPE)
        self.assertEqual(latest_scope.kind, EntryKind.SCOPE)

    def test_stats(self):
        s = State(self.path)
        s.append(EntryKind.INIT, {}, mission_id="A")
        s.append(EntryKind.SCOPE, {}, mission_id="B")
        stats = s.stats()
        self.assertEqual(stats["total"], 2)
        self.assertIn("init", stats["by_kind"])
        self.assertIn("A", stats["missions"])
        self.assertIn("B", stats["missions"])
        self.assertIsNotNone(stats["last_hash"])
        self.assertNotEqual(stats["last_hash"], GENESIS_HASH)

    def test_open_classmethod(self):
        s = State.open(self.path, mission_id="m1")
        s.append(EntryKind.INIT, {})
        s2 = State.open(self.path)
        self.assertEqual(len(s2.read_all()), 1)


class TestStateMachine(unittest.TestCase):
    def setUp(self):
        self.path = _tmp_path("machine")
        self.state = State(self.path, mission_id="mission-x")
        self.sm = StateMachine(self.state, mission_id="mission-x")

    def tearDown(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def test_initial_state(self):
        self.assertEqual(self.sm.current(), Phase.INITIALIZED)

    def test_valid_transition(self):
        entry = self.sm.transition(Phase.SCOPED, reason="ready")
        self.assertIsInstance(entry, Entry)
        self.assertEqual(self.sm.current(), Phase.SCOPED)
        # The transition is recorded.
        audits = self.state.entries_by_kind(EntryKind.AUDIT)
        self.assertGreaterEqual(len(audits), 1)

    def test_invalid_transition_raises(self):
        self.sm.transition(Phase.SCOPED)
        with self.assertRaises(InvalidTransition):
            # SCOPED -> ANALYZING is not allowed.
            self.sm.transition(Phase.ANALYZING)

    def test_terminal_states_cannot_transition(self):
        self.sm.transition(Phase.FAILED, reason="boom")
        self.assertEqual(self.sm.current(), Phase.FAILED)
        with self.assertRaises(InvalidTransition):
            self.sm.transition(Phase.SCOPED)

    def test_can_transition(self):
        self.assertTrue(self.sm.can_transition(Phase.SCOPED))
        self.assertFalse(self.sm.can_transition(Phase.COMPLETED))


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.journal = _tmp_path("migrate_journal")
        self.legacy = _tmp_path("migrate_legacy")
        self.state = State(self.journal, mission_id="mig")

    def tearDown(self):
        for p in (self.journal, self.legacy):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_detect_tools_state(self):
        with open(self.legacy, "w") as fh:
            json.dump({
                "engagement_id": "E1",
                "targets": ["t1"],
                "phases": [{"from": "init", "to": "scope"}],
            }, fh)
        self.assertEqual(detect_legacy_format(self.legacy), "tools_state")

    def test_migrate_tools_state(self):
        with open(self.legacy, "w") as fh:
            json.dump({
                "engagement_id": "E1",
                "targets": ["t1", "t2"],
                "phases": [{"from": "init", "to": "scope"}],
                "actor": "legacy-actor",
            }, fh)
        count = migrate_legacy(self.legacy, self.state)
        self.assertGreater(count, 0)
        entries = self.state.read_all()
        self.assertGreater(len(entries), 0)

    def test_migrate_chain_state(self):
        with open(self.legacy, "w") as fh:
            json.dump({
                "mission_id": "E2",
                "chains": [{"chain_id": "c1", "links": [{"b": 1}]}],
            }, fh)
        # Detect
        fmt = detect_legacy_format(self.legacy)
        self.assertIn(fmt, ("chain_state", "tools_state"))
        count = migrate_legacy(self.legacy, self.state)
        self.assertGreater(count, 0)

    def test_corrupt_input_returns_zero(self):
        with open(self.legacy, "w") as fh:
            fh.write("not valid json at all <<<")
        count = migrate_legacy(self.legacy, self.state)
        self.assertEqual(count, 0)

    def test_migrate_legacy_dict(self):
        d = {
            "engagement_id": "D1",
            "targets": ["x"],
            "phases": [],
            "actor": "dict-actor",
        }
        count = migrate_legacy_dict(d, self.state)
        self.assertGreater(count, 0)
        entries = self.state.read_all()
        self.assertGreater(len(entries), 0)


class TestMerge(unittest.TestCase):
    def test_disjoint_journals_merge(self):
        # Two truly disjoint journals: ours has seq 1..2, theirs has seq 3..4
        # on top of our chain. They share the genesis so the seqs differ.
        e1 = _make_entry(1, EntryKind.INIT)
        e2 = _make_entry(2, EntryKind.SCOPE, prev_hash=e1.hash)
        e3 = _make_entry(3, EntryKind.SCAN, prev_hash=e2.hash)
        e4 = _make_entry(4, EntryKind.FUZZ, prev_hash=e3.hash)
        # Disjoint: ours = [e1], theirs = [e3]
        result = merge_journals([e1], [e3])
        merged = result["merged"]
        # Both seq 1 and seq 3 are kept; no conflict because seqs differ.
        self.assertEqual(len(merged), 2)
        self.assertEqual(result["conflicts"], [])
        seqs = sorted(e.seq for e in merged)
        self.assertEqual(seqs, [1, 3])

    def test_overlapping_seq_same_hash_merge(self):
        e1 = _make_entry(1, EntryKind.INIT)
        # Same entry on both sides.
        result = merge_journals([e1], [e1])
        self.assertEqual(len(result["merged"]), 1)
        self.assertEqual(result["conflicts"], [])

    def test_conflicting_hash_recorded(self):
        e1 = _make_entry(1, EntryKind.INIT, {"v": 1})
        e1_conflict = _make_entry(1, EntryKind.INIT, {"v": 2})
        result = merge_journals([e1], [e1_conflict])
        # Same seq, different hash → conflict recorded.
        self.assertGreater(len(result["conflicts"]), 0)
        self.assertEqual(len(result["merged"]), 1)

    def test_missing_file_handled(self):
        with tempfile.TemporaryDirectory() as td:
            ours = os.path.join(td, "ours.jsonl")
            theirs = os.path.join(td, "theirs.jsonl")
            out = os.path.join(td, "out.jsonl")
            # Both missing
            result = merge_files(ours, theirs, out)
            self.assertEqual(result["merged_count"], 0)
            self.assertEqual(result["ours_count"], 0)
            self.assertEqual(result["theirs_count"], 0)


class TestFacade(unittest.TestCase):
    def setUp(self):
        reset_singleton()

    def tearDown(self):
        reset_singleton()

    def test_quick_record_returns_entry(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "j.jsonl")
            entry = quick_record(EntryKind.INIT, {"facade": True}, path=p)
            self.assertIsNotNone(entry)
            self.assertEqual(entry.kind, EntryKind.INIT)

    def test_permission_denied_falls_back(self):
        # Try a path under a non-writable directory; expect fallback to /tmp.
        reset_singleton()
        # Use a path that will trigger permission denied via a directory
        # that doesn't exist and can't be created (a file in /proc).
        bad_path = "/proc/1/cmdline-fake/state.jsonl"
        result = quick_record(EntryKind.INIT, {"x": 1}, path=bad_path)
        self.assertIsNotNone(result)
        reset_singleton()


class TestAppendOnly(unittest.TestCase):
    """Verify State has no destructive public methods."""

    def test_no_delete_method(self):
        self.assertFalse(hasattr(State, "delete"))

    def test_no_update_method(self):
        self.assertFalse(hasattr(State, "update"))

    def test_no_clear_method(self):
        self.assertFalse(hasattr(State, "clear"))

    def test_no_pop_method(self):
        self.assertFalse(hasattr(State, "pop"))


if __name__ == "__main__":
    unittest.main()
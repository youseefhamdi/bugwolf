#!/usr/bin/env python3
"""Unit tests for tools/runtime/contracts.py - Phase 1 of the orchestrator plan.

Covers: artifact/tool-receipt/task/result/mission validation, the structural
mandates from the plan (R1 lead enforcement, R6 open-lead rule, pre-flight MCP
attribution, anti-stalling), mission intake composition over
tools/harness_command, and durable JSONL recording.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parent.parent
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from tools.runtime.contracts import (  # noqa: E402
    ArtifactRef,
    ContractViolation,
    MissionSpec,
    TaskResult,
    TaskSpec,
    ToolReceipt,
    append_jsonl,
    parse_mission,
    record_task_result,
    result_log_path,
    validate_artifact_ref,
    validate_mission_spec,
    validate_task_result,
    validate_task_spec,
    validate_tool_receipt,
    LEAD_PWNED,
    LEAD_REFUTED,
    LEAD_BUDGET_EXHAUSTED,
    RESULT_COMPLETED,
    RESULT_PARTIAL,
)


def _valid_receipt() -> dict:
    return ToolReceipt(
        tool="live_executor",
        command="python3 tools/core/live_executor.py --target acme --unit '{}'",
        output_paths=["state/sessions/acme/probes.jsonl"],
        duration_ms=42,
        evidence_refs=["evid-0001"],
    ).to_dict()


def _valid_result(**over) -> dict:
    base = {
        "task_id": "task-0001",
        "agent_role": "web-api",
        "status": RESULT_COMPLETED,
        "summary": "probe executed against endpoint",
        "lead_refs": ["LEAD-0001"],
        "evidence_refs": ["evid-0001"],
        "tool_receipts": [_valid_receipt()],
    }
    base.update(over)
    return base


class TestArtifactRef(unittest.TestCase):
    def test_valid(self):
        ref = ArtifactRef(path="state/x.json", sha256="a" * 64).to_dict()
        self.assertEqual(validate_artifact_ref(ref), [])

    def test_missing_path(self):
        self.assertTrue(validate_artifact_ref({"sha256": "a" * 64}))

    def test_bad_digest(self):
        issues = validate_artifact_ref({"path": "x", "sha256": "nope"})
        self.assertTrue(any("sha256" in i for i in issues))

    def test_bad_kind(self):
        issues = validate_artifact_ref({"path": "x", "kind": "alien"})
        self.assertTrue(any("kind" in i for i in issues))


class TestToolReceipt(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_tool_receipt(_valid_receipt()), [])

    def test_missing_tool(self):
        issues = validate_tool_receipt({"command": "ls"})
        self.assertTrue(any("missing tool" in i for i in issues))


class TestTaskSpec(unittest.TestCase):
    def test_valid(self):
        spec = TaskSpec(task_id="t1", task_type="probe", domain="web_api").to_dict()
        self.assertEqual(validate_task_spec(spec), [])

    def test_bad_type(self):
        spec = TaskSpec(task_id="t1", task_type="cow", domain="web_api").to_dict()
        self.assertTrue(any("task type" in i for i in validate_task_spec(spec)))

    def test_bad_profile(self):
        spec = TaskSpec(task_id="t1", task_type="probe", domain="web_api",
                        model_profile="turbo").to_dict()
        self.assertTrue(any("model profile" in i for i in validate_task_spec(spec)))


class TestTaskResult(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_task_result(_valid_result()), [])

    def test_missing_identity(self):
        issues = validate_task_result({"status": "completed"})
        self.assertTrue(any("missing task_id" in i for i in issues))

    def test_bad_status(self):
        issues = validate_task_result(_valid_result(status="vibes"))
        self.assertTrue(any("status" in i for i in issues))

    def test_r1_insight_without_lead_rejected(self):
        result = _valid_result(lead_refs=[], summary="anomaly observed in response timing")
        issues = validate_task_result(result)
        self.assertTrue(any("R1 violation" in i for i in issues))

    def test_r1_satisfied_with_lead(self):
        result = _valid_result(summary="anomaly observed in response timing")
        self.assertEqual(validate_task_result(result), [])

    def test_r1_negated_summary_is_not_a_claim(self):
        """Absence is not an insight: honest negative results validate clean.

        Live-engagement regression (plumsail-r5): machine summaries like
        "0 leads open; 0 signals hunted deterministically" and
        "findings=0 refuted=0 open=0" tripped the substring scan and
        flagged R1 on finding-free runs.
        """
        for summary in (
                "0 leads open; 0 signals hunted deterministically",
                "findings=0 refuted=0 open=0",
                "no signals found",
                "no potential SSRF on /fetch",
                "verified 0, refuted 0",
                "no Phase 4 executor for this domain yet"):
            result = _valid_result(lead_refs=[], summary=summary)
            self.assertEqual(validate_task_result(result), [],
                             f"false R1 on negative summary: {summary!r}")

    def test_r1_negation_mixed_summary_still_a_claim(self):
        """A negated mention followed by a positive claim still needs a lead."""
        for summary in (
                "no signals found, but a suspicious pattern on /import",
                "signals found on /ingest",
                "findings=1 refuted=0 open=0"):
            result = _valid_result(lead_refs=[], summary=summary)
            issues = validate_task_result(result)
            self.assertTrue(any("R1 violation" in i for i in issues),
                            f"expected R1 on claim summary: {summary!r}")

    def test_r6_completed_with_open_leads_rejected(self):
        result = _valid_result(open_leads=["LEAD-0009"])
        issues = validate_task_result(result)
        self.assertTrue(any("R6 violation" in i for i in issues))

    def test_partial_with_open_leads_ok(self):
        result = _valid_result(status=RESULT_PARTIAL, open_leads=["LEAD-0009"])
        self.assertEqual(validate_task_result(result), [])

    def test_preflight_mcp_attribution_required(self):
        receipt = _valid_receipt()
        receipt["tool"] = "browser_driver"
        receipt["command"] = "browserMCP navigate"
        result = _valid_result(tool_receipts=[receipt], mcp_bindings_used=[])
        issues = validate_task_result(result)
        self.assertTrue(any("pre-flight violation" in i for i in issues))

    def test_preflight_mcp_attribution_ok(self):
        receipt = _valid_receipt()
        receipt["command"] = "browserMCP navigate"
        result = _valid_result(tool_receipts=[receipt], mcp_bindings_used=["browserMCP"])
        self.assertEqual(validate_task_result(result), [])

    def test_anti_stalling_prose_only_rejected(self):
        result = _valid_result(tool_receipts=[], evidence_refs=[])
        issues = validate_task_result(result)
        self.assertTrue(any("anti-stalling" in i for i in issues))

    def test_bad_hash_format(self):
        issues = validate_task_result(_valid_result(prompt_hash="zzz"))
        self.assertTrue(any("prompt_hash" in i for i in issues))


class TestMissionSpec(unittest.TestCase):
    def test_valid(self):
        m = MissionSpec(mission_id="bw-1", target="example.com",
                        domains=["web_api"]).to_dict()
        self.assertEqual(validate_mission_spec(m), [])

    def test_bad_domain(self):
        m = MissionSpec(mission_id="bw-1", target="example.com",
                        domains=["farming"]).to_dict()
        self.assertTrue(any("domain" in i for i in validate_mission_spec(m)))

    def test_bad_budget(self):
        m = MissionSpec(mission_id="bw-1", target="example.com",
                        budget={"max_agents": -3}).to_dict()
        self.assertTrue(any("budget" in i for i in validate_mission_spec(m)))


class TestMissionIntake(unittest.TestCase):
    """Phase 1 exit criterion: MissionSpec builds on the EXISTING parser."""

    def test_parse_mission_composes_harness_command(self):
        spec = parse_mission("bugwolf --web attack this target https://example.test")
        self.assertTrue(spec.mission_id.startswith("bw-"))
        self.assertEqual(spec.target, "https://example.test")
        self.assertIn("web", spec.domains)
        self.assertEqual(spec.model_profile, "balanced")
        # Default budget present (plan layer B example).
        self.assertEqual(spec.budget["max_parallel_tasks"], 8)

    def test_mission_digest_stable(self):
        a = parse_mission("bugwolf --web attack this target https://example.test")
        b = parse_mission("bugwolf --web attack this target https://example.test")
        self.assertEqual(a.mission_id, b.mission_id)
        self.assertEqual(a.digest(), b.digest())

    def test_intake_record_attached_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            intake_dir = Path(tmp) / "state" / "intake"
            intake_dir.mkdir(parents=True)
            (intake_dir / "latest.json").write_text(json.dumps({"attested": True}))
            spec = parse_mission("bugwolf attack this target https://example.test",
                                 project_root=tmp)
            self.assertEqual(spec.intake_record.get("attested"), True)


class TestDurableState(unittest.TestCase):
    def test_record_task_result_appends_valid_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = TaskResult(**{k: v for k, v in _valid_result().items()
                                   if k in TaskResult.__dataclass_fields__})
            issues = record_task_result(result, project_root=tmp)
            self.assertEqual(issues, [])
            log = result_log_path("task-0001", project_root=tmp)
            lines = log.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["task_id"], "task-0001")

    def test_record_rejects_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = TaskResult(task_id="t", agent_role="web", status="nope")
            issues = record_task_result(result, project_root=tmp)
            self.assertTrue(any("status" in i for i in issues))

    def test_append_jsonl_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "events.jsonl"
            append_jsonl(p, {"a": 1})
            append_jsonl(p, {"a": 2})
            lines = p.read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["a"], 2)


class TestTerminalStates(unittest.TestCase):
    def test_lead_terminal_states_are_exactly_three(self):
        self.assertEqual((LEAD_PWNED, LEAD_REFUTED, LEAD_BUDGET_EXHAUSTED),
                         ("PWNED", "REFUTED", "BUDGET-EXHAUSTED"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

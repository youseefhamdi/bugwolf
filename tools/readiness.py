#!/usr/bin/env python3
"""Validate and report BugWolf's machine-readable readiness contract.

This module is intentionally offline. It reads the repository VERSION file and
configs/readiness.json, validates capability declarations, and reports whether
the documented claims match the implementation maturity. It does not authorize,
probe, or execute against any target.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

SCHEMA = "bugwolf-readiness/v1"
VALID_STATUSES = {"supported", "partial", "planned", "unsupported"}
VALID_LEVELS = {
    "L0-experimental-planner",
    "L1-controlled-active-researcher",
    "L2-reproducible-research-harness",
    "L3-continuously-evaluated-platform",
    "L4-production-ready-authorized-research",
}
REQUIRED_PROFILES = {"authorized_live", "disposable_lab"}
REQUIRED_PROFILE_FIELDS = {"research_depth", "execution_scope", "safety_controls", "reporting"}
REQUIRED_CLAIMS = {
    "zero_day_guarantee",
    "autonomous_production_exploitation",
    "reportable_findings_without_human_review",
    "supported_for_explicitly_authorized_research",
    "full_depth_apt_research",
    "depth_never_reduced_by_gates_or_scope",
}
REQUIRED_CONTROLS = {
    "authorization_enforced_at_execution_boundary",
    "ssrf_protection_complete",
    "subprocess_sandbox_required",
    "evidence_redaction",
    "replay_requires_recorded_status_and_block_state",
    "canonical_finding_ledger",
    "human_review_required_for_reportable_findings",
    "research_depth_never_reduced_by_gates",
    "authorization_recorded_not_a_depth_limiter",
    "engagement_context_recording",
    "coverage_guided_substrate",
    "corpus_management",
    "crash_deduplication_minimization",
    "state_sequence_coverage",
    "benchmark_laboratory",
    "candidate_evidence_state_machine",
    "impact_validation_layers",
    "static_source_fingerprinting",    "patch_diff_reasoning", "dependency_provenance",
    "research_source_provenance",
    "reporting_gate", "coordinated_disclosure", "retest_workflow",
    "sbom_generation", "bundle_integrity_check", "clean_install_smoke",
    "kill_switch",
    "request_budgets",
    "release_provenance",
    "benchmark_corpus",
}


def _root(explicit: Optional[str] = None) -> Path:
    return workspace_root(explicit) if explicit else CODE_ROOT


# ---------------------------------------------------------------------------
# Functional verification of the execution-boundary controls (honesty rule:
# a claimed control must prove itself, offline, before the flag counts)
# ---------------------------------------------------------------------------

_AUDIT_ALLOWED = "https://boundary-audit.invalid"
_AUDIT_BLOCKED = "http://boundary-audit-evil.invalid/x"


def _verify_scope_gate() -> tuple:
    """Functionally prove the scope gate blocks out-of-scope traffic at the
    shared HTTP choke point -- no network: the check fires before I/O."""
    try:
        from tools.runtime import scope
        from tools.runtime.mission_runner import http_probe
        scope.reset()
        scope.bind_target(_AUDIT_ALLOWED)
        result = http_probe(_AUDIT_BLOCKED)
        if result.status == 0 and "scope-blocked" in result.body:
            return True, "http_probe blocked out-of-scope URL (status 0)"
        return False, f"http_probe did not block: status={result.status}"
    except Exception as exc:  # noqa: BLE001 - verification failure is data
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            from tools.runtime import scope
            scope.reset()
        except Exception:  # noqa: BLE001
            pass


def _verify_ssrf_choke_points() -> tuple:
    """Prove every network capability obeys the gate: raw-socket race
    engine, live executor, and the injected browser driver."""
    details = []
    try:
        from tools.runtime import scope
        scope.reset()
        scope.bind_target(_AUDIT_ALLOWED)

        from tools.validation.race_engine import RaceRequest, run_race
        race = run_race(RaceRequest(url=_AUDIT_BLOCKED, count=2))
        if not (race.attempted == 2 and race.window_ms == 0
                and race.statuses == [0, 0]
                and "scope-blocked" in (race.error or "")):
            return False, ("race engine did not block: "
                           f"statuses={race.statuses} error={race.error!r}")
        details.append("race")

        from tools.core.live_executor import ProbeSpec, _send_once
        status, _headers, body, _ms = _send_once(
            ProbeSpec(probe_id="boundary-audit", method="GET",
                      url=_AUDIT_BLOCKED),
            timeout=5, urlopen=_NeverOpen)
        if not (status == 0 and "scope-blocked" in body):
            return False, f"live executor did not block: status={status}"
        details.append("live_executor")

        from tools.runtime.browser_driver import validate_client_side
        evidence = validate_client_side({"url": _AUDIT_BLOCKED,
                                         "lead_id": "boundary-audit"},
                                        driver=_NullDriver())
        if not str(evidence.blocker or "").startswith("scope-blocked"):
            return False, "browser driver path did not block"
        details.append("browser_driver")

        return True, "blocked at: " + ", ".join(details)
    except Exception as exc:  # noqa: BLE001 - verification failure is data
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            from tools.runtime import scope
            scope.reset()
        except Exception:  # noqa: BLE001
            pass


class _NullDriver:
    """Must never be reached when the scope gate fires first."""

    def navigate(self, url: str) -> str:  # pragma: no cover - guard
        raise AssertionError("driver reached despite scope block")

    def console(self):  # pragma: no cover - guard
        return []

    def evaluate(self, _sink):  # pragma: no cover - guard
        return None


def _NeverOpen(*_args, **_kwargs):  # pragma: no cover - guard
    """Must never be reached when the scope gate fires first."""
    raise AssertionError("urlopen reached despite scope block")


def load_manifest(root: Optional[str] = None) -> Dict[str, Any]:
    path = _root(root) / "configs" / "readiness.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("readiness manifest must be a JSON object")
    return value


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def validate_manifest(manifest: Dict[str, Any], *, root: Optional[str] = None) -> Dict[str, Any]:
    """Return a stable validation report; never performs network or target I/O."""
    errors: list[str] = []
    warnings: list[str] = []
    project = _root(root)

    if manifest.get("schema") != SCHEMA:
        errors.append(f"unsupported schema: {manifest.get('schema')!r}")
    if not isinstance(manifest.get("manifest_version"), int):
        errors.append("manifest_version must be an integer")
    if manifest.get("readiness_level") not in VALID_LEVELS:
        errors.append("readiness_level is invalid")

    version_file = str(manifest.get("release_version_file") or "VERSION")
    version_path = project / version_file
    if not version_path.is_file():
        errors.append(f"release version file is missing: {version_file}")
    else:
        release_version = version_path.read_text(encoding="utf-8").strip()
        if not release_version:
            errors.append("release version file is empty")
        manifest_version = str(manifest.get("release_version") or release_version)
        if manifest_version != release_version:
            errors.append(
                f"manifest release version {manifest_version!r} does not match VERSION {release_version!r}"
            )

    authority = manifest.get("operator_authority")
    if not isinstance(authority, dict):
        errors.append("operator_authority must be an object")
    else:
        # The operator organization is operator-supplied context and defaults
        # to unknown; it must never be hardcoded to a specific organization.
        organization = str(authority.get("organization") or "").strip()
        if not organization:
            errors.append("operator_authority.organization is empty")
        elif organization.lower() != "unknown":
            errors.append("operator_authority.organization must not be hardcoded "
                          "to a specific organization; keep 'unknown' "
                          "(operator-declared per engagement)")
        if authority.get("authorization") != "operator_declared":
            errors.append("operator_authority.authorization must be operator_declared")
        if authority.get("research_depth") != "full_apt_team":
            errors.append("operator_authority.research_depth must be full_apt_team")
        if authority.get("depth_never_reduced_by_gates") is not True:
            errors.append("depth_never_reduced_by_gates must remain true")

    profiles = manifest.get("execution_profiles")
    if not isinstance(profiles, dict):
        errors.append("execution_profiles must be an object")
    else:
        for profile_name in REQUIRED_PROFILES:
            profile = profiles.get(profile_name)
            if not isinstance(profile, dict):
                errors.append(f"execution profile {profile_name!r} is missing")
                continue
            missing = REQUIRED_PROFILE_FIELDS - set(profile)
            errors.extend(
                f"execution profile {profile_name!r} missing field {field!r}"
                for field in sorted(missing)
            )
            if profile.get("research_depth") != "full_apt_team":
                errors.append(
                    f"execution profile {profile_name!r} must preserve full_apt_team research depth"
                )

    claims = manifest.get("claims")
    if not isinstance(claims, dict):
        errors.append("claims must be an object")
    else:
        for key in REQUIRED_CLAIMS:
            if key not in claims or not _is_bool(claims[key]):
                errors.append(f"claim {key!r} must be boolean")
        if claims.get("zero_day_guarantee") is True:
            errors.append("zero_day_guarantee must remain false")
        if claims.get("autonomous_production_exploitation") is True:
            errors.append("autonomous_production_exploitation must remain false")
        if claims.get("reportable_findings_without_human_review") is True:
            errors.append("human review cannot be bypassed for reportable findings")
        if claims.get("full_depth_apt_research") is not True:
            errors.append("full_depth_apt_research claim must remain true")
        if claims.get("depth_never_reduced_by_gates_or_scope") is not True:
            errors.append("depth_never_reduced_by_gates_or_scope claim must remain true")

    targets = manifest.get("target_classes")
    if not isinstance(targets, dict) or not targets:
        errors.append("target_classes must be a non-empty object")
    else:
        for name, capability in targets.items():
            if not isinstance(capability, dict):
                errors.append(f"target class {name!r} must be an object")
                continue
            status = capability.get("status")
            if status not in VALID_STATUSES:
                errors.append(f"target class {name!r} has invalid status {status!r}")
            for field in ("modes", "entrypoints", "evidence", "limitations"):
                if not isinstance(capability.get(field), list):
                    errors.append(f"target class {name!r} field {field!r} must be a list")
            if status == "supported" and not capability.get("entrypoints"):
                errors.append(f"supported target class {name!r} has no entrypoints")
            if status == "planned" and capability.get("entrypoints"):
                warnings.append(f"planned target class {name!r} declares entrypoints")

    controls = manifest.get("global_controls")
    if not isinstance(controls, dict):
        errors.append("global_controls must be an object")
    else:
        for key in REQUIRED_CONTROLS:
            if key not in controls:
                errors.append(f"global control {key!r} is missing")
        if controls.get("human_review_required_for_reportable_findings") is not True:
            errors.append("human review must be required for reportable findings")
        if controls.get("canonical_finding_ledger") is not True:
            errors.append("canonical finding ledger must be enabled")
        if controls.get("research_depth_never_reduced_by_gates") is not True:
            errors.append("research depth must never be reduced by gates")
        if controls.get("authorization_recorded_not_a_depth_limiter") is not True:
            errors.append("authorization must be recorded, not a depth limiter")
        if not controls.get("engagement_context_recording"):
            errors.append("engagement_context_recording must be configured")
        for phase_control in ("coverage_guided_substrate", "corpus_management",
                              "crash_deduplication_minimization",
                              "state_sequence_coverage", "benchmark_laboratory",
                              "candidate_evidence_state_machine",
                              "impact_validation_layers",
                              "static_source_fingerprinting",
                              "patch_diff_reasoning", "dependency_provenance",
                              "research_source_provenance",
                              "reporting_gate", "coordinated_disclosure",
                              "retest_workflow", "sbom_generation",
                              "bundle_integrity_check", "clean_install_smoke"):
            if not controls.get(phase_control):
                errors.append(f"global control {phase_control!r} must be configured")
        if controls.get("authorization_enforced_at_execution_boundary") is not True:
            warnings.append("authorization is not yet enforced at the execution boundary")
        else:
            ok, detail = _verify_scope_gate()
            if not ok:
                errors.append(
                    "authorization_enforced_at_execution_boundary claim is "
                    f"not verifiable: {detail}")
        if controls.get("ssrf_protection_complete") is not True:
            warnings.append("complete SSRF protection is not yet available")
        else:
            ok, detail = _verify_ssrf_choke_points()
            if not ok:
                errors.append(
                    f"ssrf_protection_complete claim is not verifiable: {detail}")
        if controls.get("subprocess_sandbox_required") is not True:
            warnings.append("subprocess sandbox is not yet required")

    required = manifest.get("required_before_l4")
    if not isinstance(required, list) or not required:
        errors.append("required_before_l4 must be a non-empty list")

    phases = manifest.get("phase_completion")
    if not isinstance(phases, dict):
        errors.append("phase_completion must be an object")

    return {
        "schema": SCHEMA,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "readiness_level": manifest.get("readiness_level"),
        "release_status": manifest.get("release_status"),
        "operator_authority": {
            "organization": authority.get("organization") if isinstance(authority, dict) else None,
            "research_depth": authority.get("research_depth") if isinstance(authority, dict) else None,
        },
        "execution_profiles": {
            name: profile.get("research_depth")
            for name, profile in (profiles.items() if isinstance(profiles, dict) else [])
            if isinstance(profile, dict)
        },
        "target_classes": {
            name: capability.get("status")
            for name, capability in (targets.items() if isinstance(targets, dict) else [])
            if isinstance(capability, dict)
        },
        "network": "not performed",
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate BugWolf readiness manifest")
    parser.add_argument("--project-root", help="repository root (default: bundled source root)")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        report = validate_manifest(load_manifest(args.project_root), root=args.project_root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {
            "schema": SCHEMA,
            "valid": False,
            "errors": [str(exc)],
            "warnings": [],
            "network": "not performed",
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        state = "VALID" if report["valid"] else "INVALID"
        print(f"BugWolf readiness manifest: {state}")
        print(f"  level: {report.get('readiness_level', 'unknown')}")
        for error in report.get("errors", []):
            print(f"  ERROR: {error}")
        for warning in report.get("warnings", []):
            print(f"  WARNING: {warning}")
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

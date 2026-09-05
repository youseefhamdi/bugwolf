"""BugWolf Phase 1.4 — Governance Core.

Additive package — does NOT modify the logic of any pre-existing module.
The governance core sits ON TOP of the closed Phase 0 ``# UNCENSORED:``
bypass surface and provides:

  * strict, evidence-hash-chained scope binding (scope.py)
  * full SHA-256 + canonical-JSON evidence verification (verifier.py)
  * 7-Question Gate semantic judgment (question_gate.py)
  * approval window with destructive-action gating (approval.py)
  * skill_request / skill_result dataclasses (contract.py)
  * mission lifecycle state machine (state.py)
  * FastAPI control plane with token auth + CSP (web.py)
  * refutation lifecycle: ACCEPTED / STALLED / EXHAUSTED (rebuttal.py)
  * budget / step / wall-clock guard (budget.py)
  * action-id loop detector (loop_detector.py)
  * append-only JSONL plan-hash tracer (tracer.py)
  * fail-closed audit-log scanner for client/UA/scanner leakage (audit_log.py)
  * GPG signer with deterministic fallback (gpg_signer.py)

All modules declare ``SCHEMA = "bugwolf-governance-v1"``.  No third-party
deps are required.
"""

from __future__ import annotations

SCHEMA = "bugwolf-governance-v1"

__all__ = ["SCHEMA"]
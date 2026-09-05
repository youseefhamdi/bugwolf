# BugWolf — Repository Audit & File Map (generated)

> Generated on 2026-09-05T07:46:11+00:00 from `main@039dc2c` by `scripts/generate_audit.py`. All counts are computed from the live tree; do not edit them by hand.

## 1. Scale

- Python modules under `tools/`: **220** (89989 lines) + **16** `__init__.py` package markers.
- CLI-capable modules (argparse/`__main__`): **139**
- Group sizes: core **11**, domains **14**, intelligence **3**, recon **2**, validation **4**

## 2. Test suite

- Test files: **163**
- Discovered tests: **1921**

## 3. References

- Reference docs: **66** (11 attack-vector catalogs, 32 hacking-agent guides)

## 4. Scripts & configs

- Shell scripts under `scripts/`: **5**
- readiness level: `L2-reproducible-research-harness`
- release status: `experimental-human-supervised`

## 5. Tool map (largest modules)

| Module | Lines | Purpose |
|---|---|---|
| `tools/runtime/mission_runner.py` | 3293 | BugWolf mission runner (orchestrator plan v2, Phase 4 exit criterion). |
| `tools/core/campaign_orchestrator.py` | 2177 | BugWolf Campaign Orchestrator — APT Commander (Stage 2 rebuild). |
| `tools/paper_intel.py` | 2096 | Offline adapters derived from the supplied 2026 security papers. |
| `tools/hunt.py` | 1498 | BugWolf Hunt Engine — Auth-aware vulnerability scanner. |
| `tools/core/research_loop.py` | 1445 | BugWolf Mandatory Deep-Research Loop v1.0.0 |
| `tools/zero_day.py` | 1398 | BugWolf potentially-novel vulnerability research orchestrator. |
| `tools/runtime/team.py` | 1221 | BugWolf Multi-Agent Team Engine v1.0.0. |
| `tools/kill_chain.py` | 1014 | BugWolf Autonomous Kill Chain Builder v1.0.0 |
| `tools/research_thread.py` | 1012 | BugWolf Research Thread System — self-driven research units. |
| `tools/campaign.py` | 964 | BugWolf Campaign State Engine — self-driven APT-level research persistence. |
| `tools/core/stage_controller.py` | 953 | Persistent no-skip workflow controller for BugWolf (APT Commander, Stage 2). |
| `tools/ledger.py` | 904 | BugWolf Ledger Verifier v1.0.0 |
| `tools/surface_model.py` | 869 | Structured Web/API attack-surface model for BugWolf's discovery core. |
| `tools/observation.py` | 861 | BugWolf Observation / Oracle Validation Layer v1.0.0 |
| `tools/runtime/scheduler.py` | 841 | BugWolf orchestrator scheduler (plan v2, sections 3-4: task graph + lanes). |
| `tools/core/live_executor.py` | 829 | BugWolf Live Execution Harness — real probes, real evidence. |
| `tools/core/agent_registry.py` | 820 | BugWolf Specialized Agent Registry v1.0.0. |
| `tools/patch_gap.py` | 806 | BugWolf Patch-Gap Exploitation Engine v1.0.0 |
| `tools/runtime/understanding/stages.py` | 803 | The nine Understanding-Layer stage engines (master plan §8.1). |
| `tools/leads.py` | 796 | BugWolf Lead Ledger — persistent state-transition research objects for OPEN LEADs. |
| `tools/infra_deploy.py` | 786 | BugWolf Infrastructure Auto-Deploy v1.0.0 |
| `tools/carlini_loop.py` | 752 | BugWolf Carlini Loop Track — per-file brute-force vulnerability analysis. |
| `tools/perf.py` | 734 | BugWolf performance harness (orchestrator plan v2, sections 5.3 + 7). |
| `tools/capability_registry.py` | 733 | BugWolf Capability Registry v1.0.0 |
| `tools/trust_map.py` | 720 | BugWolf Trust Map Engine v1.0.0 |
| `tools/agent_isolation.py` | 711 | Agent Isolation Checker — verifies each BugWolf agent operates within |
| `tools/adversary_emulation.py` | 699 | BugWolf Adversary Emulation Framework v1.0.0 |
| `tools/runtime/contracts.py` | 693 | BugWolf Runtime Contracts - Phase 1 of the orchestrator plan. |
| `tools/header_trust.py` | 679 | Header-trust / proxy-trust analysis for BugWolf's discovery core. |
| `tools/validation/self_eval_harness.py` | 667 | BugWolf Self-Evaluation Harness — AutoPenBench-style milestone scoring. |
| `tools/threat_intel.py` | 659 | BugWolf Threat Intelligence Module v1.0.0 |
| `tools/instincts.py` | 642 | Post-mission instinct distillation (INTEGRATION_PLAN Phase A, v1.24). |
| `tools/art_selector.py` | 630 | Adaptive Random Testing (ART) selection for BugWolf's discovery core. |
| `tools/lab_lifecycle.py` | 617 | BugWolf private-lab lifecycle manager. |
| `tools/program_fit.py` | 604 | BugWolf Program-Fit Gate v1.0.0 |
| `tools/idor_research.py` | 603 | Offline IDOR/access-control research planning. |
| `tools/chain_of_custody.py` | 591 | BugWolf Chain of Custody — Tamper-proof audit trail for every finding. |
| `tools/contract_discovery.py` | 588 | Smart-contract state-space exploration for BugWolf's discovery core. |
| `tools/asset_discovery.py` | 584 | BugWolf Asset Discovery Engine — recursive multi-source enumeration. |
| `tools/intel/research_engine.py` | 581 | BugWolf Deep-Research Engine v1.0.0. |

## 6. Verification notes

Run the reproducible verification locally:

```bash
python3 scripts/generate_audit.py
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m compileall -q tools tests lab
bash -n tools/recon_engine.sh
bash scripts/ci_bundle_check.sh
```

This document makes no claim about zero-day discovery probability; it is an engineering inventory.